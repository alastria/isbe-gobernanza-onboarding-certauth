package certauth

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/evidenceledger/certauth/internal/errl"
	"github.com/evidenceledger/certauth/internal/jpath"
	"github.com/evidenceledger/certauth/internal/models"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/utils"
	"github.com/golang-jwt/jwt/v5"
	jwtV5 "github.com/golang-jwt/jwt/v5"
	"github.com/skip2/go-qrcode"
)

const (
	oidc_configuration     = "/.well-known/openid-configuration"
	authorization_endpoint = "/oauth2/auth"
	token_endpoint         = "/oauth2/token"
	// userinfo_endpoint      = "/oauth2/userinfo"
	jwks_uri = "/.well-known/jwks.json"
)

// handleDiscovery handles OIDC discovery endpoint
func (s *Server) handleDiscovery(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{
		"issuer":                 s.cfg.CertAuthURL,
		"authorization_endpoint": s.cfg.CertAuthURL + authorization_endpoint,
		"token_endpoint":         s.cfg.CertAuthURL + token_endpoint,
		// "userinfo_endpoint":                     s.cfg.CertAuthURL + userinfo_endpoint,
		"jwks_uri":                              s.cfg.CertAuthURL + jwks_uri,
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"ES256"},
		"scopes_supported":                      []string{"openid", "eidas", "learcredential", "learcred"},
		"claims_supported":                      []string{"sub", "iss", "aud", "exp", "iat", "name", "given_name", "family_name", "email", "organization", "organization_identifier", "country"},
	})
}

// Authorization handles OAuth2 authorization endpoint.
// This is the first step of the authorization process.
// We support two types of authorization: with an eIDAS certificate and with a Verifiable Credential
func (s *Server) Authorization(c *fiber.Ctx) error {

	// Parse authorization request
	authReq := &models.AuthorizationRequest{
		ResponseType: utils.CopyString(c.Query("response_type")),
		ClientID:     utils.CopyString(c.Query("client_id")),
		RedirectURI:  utils.CopyString(c.Query("redirect_uri")),
		// Scope:        utils.CopyString(c.Query("scope")),
		Scopes:    strings.Fields(c.Query("scope")),
		State:     utils.CopyString(c.Query("state")),
		Nonce:     utils.CopyString(c.Query("nonce")),
		CreatedAt: time.Now(),
	}

	slog.Info("Authorization request received",
		"response_type", authReq.ResponseType,
		"client_id", authReq.ClientID,
		"redirect_uri", authReq.RedirectURI,
		"scope", c.Query("scope"),
		"state", authReq.State,
		"nonce", authReq.Nonce,
	)

	// Validate request
	if errorCode, errorDesc := s.validateAuthorizationRequest(authReq); errorCode != "" {
		return s.handleAuthorizationError(c, authReq.RedirectURI, authReq.State, errorCode, errorDesc)
	}

	// The relying party must have been registered previously
	rp, err := s.db.GetRelyingParty(authReq.ClientID)
	if err != nil {
		errorCode := "server_error"
		errorDesc := errl.Errorf("database error: %w", err).Error()
		return s.handleAuthorizationError(c, authReq.RedirectURI, authReq.State, errorCode, errorDesc)
	}
	if rp == nil {
		errorCode := "unauthorized_client"
		errorDesc := "invalid client_id"
		return s.handleAuthorizationError(c, authReq.RedirectURI, authReq.State, errorCode, errorDesc)
	}

	// Validate redirect_uri matches registered RP redirect URL
	// For security reasons, the redirect_uri must be the same as the one that was registered
	if authReq.RedirectURI != rp.RedirectURL {
		errorCode := "invalid_request"
		errorDesc := "invalid redirect_uri"
		return s.handleAuthorizationError(c, authReq.RedirectURI, authReq.State, errorCode, errorDesc)
	}

	// Check if certificate authentication is requested with scope 'eidas', 'onlyeidas' or 'learcred'
	if !slices.Contains(authReq.Scopes, "eidas") && !slices.Contains(authReq.Scopes, "onlyeidas") && !slices.Contains(authReq.Scopes, "learcred") {
		errorCode := "invalid_scope"
		errorDesc := "the server requires scope eidas, onlyeidas or learcred"
		return s.handleAuthorizationError(c, authReq.RedirectURI, authReq.State, errorCode, errorDesc)
	}

	// Check if we received the SSO cookie that we generated in a possible recent authentication
	ssoCookie := c.Cookies("__Http-sso_certauth")
	ssoClaims, err := s.jwtService.ParseSSOCookieToken(ssoCookie)
	if err != nil {
		slog.Warn("Invalid SSO cookie received, proceeding with normal flow", "error", errl.Error(err))
	}

	var ssoSession *models.SSOSession
	if ssoClaims != nil {

		// Valid SSO cookie, we may bypass certificate selection
		slog.Info("Valid SSO cookie received", "subject", ssoClaims["sub"])

		// Retrieve the SSO session ID from the claims
		ssoSessionID, _ := ssoClaims["session_id"].(string)

		// Retrieve the SSO session data from the cache corresponding to that session id
		ssoSessionIntf, found := s.cache.Get(ssoSessionID)
		if !found {
			slog.Warn("SSO session not found in cache, proceeding with normal flow", "sso_session_id", ssoSessionID)
		} else {
			ss, ok := ssoSessionIntf.(*models.SSOSession)
			if !ok {
				slog.Warn("Invalid SSO session type in cache, proceeding with normal flow", "sso_session_id", ssoSessionID)
			} else {
				ssoSession = ss
			}
		}
	}

	// Generate an authorization code for this RP authentication process.
	// The code is associated to an authorization process object which will be used to track
	// the whole set of interactions with the user.
	authProcess := s.generateAuthCode(authReq, rp)

	// Store the authorization process struct in a cache with a reasonable expiration time (currently hardcoded to 15 min)
	// It will hold the certificate data once it is received by the certsec handler
	// The key is the unique authorization code used in the OAUth authorithation code flow, which will be
	// passed around the endpoints to associate with the in-memory authorization proces object.
	// TODO: maybe create a unique id specific for this purpose, and only send the auth code when it is required.
	s.cache.Set(authProcess.Code, authProcess, 15*time.Minute)

	if ssoSession != nil {

		// Bypass certificate selection and return directly to caller
		slog.Debug("bypassing certificate selection", "code", authProcess.Code, "redirect_uri", authProcess.RedirectURI)

		// Store certificate data and email of the user in the authProcess struct
		authProcess.CertificateData = ssoSession.CertificateData
		authProcess.Email = ssoSession.Email

		// And redirect to the caller
		redirectURL := fmt.Sprintf("%s?code=%s", authProcess.RedirectURI, authProcess.Code)
		if authProcess.State != "" {
			redirectURL += fmt.Sprintf("&state=%s", authProcess.State)
		}

		return c.Redirect(redirectURL, fiber.StatusFound)

	} else {

		// No valid SSO cookie, proceed with normal flow

		// We pass the auth code so we will be able to retrieve the in-memory auth process object later
		if slices.Contains(authReq.Scopes, "onlyeidas") {
			slog.Info("Redirection to ONLY Certificate login")
			return c.Redirect("/cert/login?code="+authProcess.Code, fiber.StatusFound)
		}
		slog.Info("Redirection to BOTH Certificate and Wallet login")
		return c.Redirect("/login?code="+authProcess.Code, fiber.StatusFound)

	}

}

func (s *Server) LoginPage(c *fiber.Ctx) error {
	slog.Info("Login page", "from", c.Hostname(), "to", c.IP())

	// Retrieve the AuthorizationRequest from the application authentication session
	authProcess, err := s.getAuthProcess(c.Query("code"))
	if err != nil {
		err := errl.Errorf("getAuthProcess: %w", err)
		slog.Error(err.Error())
		return s.html.Render(c, "error", fiber.Map{"message": err})
	}

	data := map[string]any{
		"authCode": authProcess.Code,
	}
	slog.Debug("Login page", "data", data)

	return s.html.Render(c, "login", data)

}

func (s *Server) CertLoginPage(c *fiber.Ctx) error {
	slog.Info("CertLoginPage", "from", c.Hostname(), "to", c.IP())

	// Retrieve the AuthorizationRequest from the application authentication session
	authProcess, err := s.getAuthProcess(c.Query("code"))
	if err != nil {
		err := errl.Errorf("getAuthProcess: %w", err)
		slog.Error(err.Error())
		return s.html.Render(c, "error", fiber.Map{"message": err})
	}

	// Present the screen informing the user about the next step
	return s.html.Render(c, "1_certificate_select", fiber.Map{
		"authCode":   authProcess.Code,
		"certsecURL": s.cfg.CertSecURL,
	})

}

func (s *Server) WalletLoginPage(c *fiber.Ctx) error {
	slog.Info("Landing page", "from", c.Hostname(), "to", c.IP())

	// Retrieve the AuthorizationRequest from the application authentication session
	authCode := c.Query("code")
	authProcess, err := s.getAuthProcess(authCode)
	if err != nil {
		err := errl.Errorf("getAuthProcess: %w", err)
		slog.Error(err.Error())
		return s.html.Render(c, "error", fiber.Map{"message": err})
	}

	verifierURL := s.cfg.CertAuthURL
	// This is the response url for the wallet
	response_uri := verifierURL + "/wallet/authenticationresponse"

	// We now create an OID4VP Authorization Request to send to the Wallet.
	// Do not confuse this request with the one we received from the RP. they are associated but different.
	// With regards to the RP, we are an OpenID Provider and so we receive from the RP a "standard" OIDC auth request.
	// But for the Wallet we are a RP and the Wallet is the OpenID Provider, speaking the OID4VP protocol.
	// We request a Verifiable Credential from the Wallet, extract relevant info from it and send back to
	// the RP a standard OIDC response, so the RP/Application does not have to be involved with the OID4VP protocol.

	// According to OID4VP, the variable 'state' is used to track the interaction process with the Wallet.
	// We will use the 'authCode' we generated for the authorization process of the RP for this purpose.
	// That is: authCode will be used to track the whole authentication process, even if it is named differently
	// when talking to the Wallet.
	// In this way, when the Wallet sends the OID4VP AuthResponse, we will be able to match the Wallet response with the RP request.
	walletAuthRequest, err := s.createJWTSecuredAuthenticationRequest(response_uri, authCode)
	if err != nil {
		errorCode := "server_error"
		errorDesc := errl.Errorf("failed to create wallet authentication request: %w", err).Error()
		return s.handleAuthorizationError(c, authProcess.RedirectURI, authProcess.State, errorCode, errorDesc)
	}

	// Store in our authentication process object
	authProcess.WalletAuthRequest = walletAuthRequest

	slog.Info("Wallet authentication request created", "wallet_auth_request", walletAuthRequest)

	// Generate the data for the login page as a map
	data, err := dataForWalletLogin(verifierURL, authCode)
	if err != nil {
		errorCode := "server_error"
		errorDesc := errl.Errorf("failed to generate login page data: %w", err).Error()
		return s.handleAuthorizationError(c, authProcess.RedirectURI, authProcess.State, errorCode, errorDesc)
	}

	// Present a screen with the QR code to be scanned by the Wallet
	return s.html.Render(c, "wallet_login", data)

}

func dataForWalletLogin(verifierURL string, authRequestID string) (map[string]any, error) {

	// Get our URL defined in the config

	// Build the URL that the Wallet will have to call to retriwve the Authentication Request
	request_uri := verifierURL + "/wallet/authenticationrequest" + "?state=" + authRequestID
	request_uri = url.QueryEscape(request_uri)

	// Build the full URI (including the request_uri) for the same-device use
	sameDeviceWallet := "https://eudiwallet.mycredential.eu"
	samedevice_uri := sameDeviceWallet + "?request_uri=" + request_uri

	// Build the full URI (including the request_uri) for the cross-device use (mobile)
	openid4PVURL := "openid4vp://"
	crossdevice_uri := openid4PVURL + "?request_uri=" + request_uri

	// Create the QR code for cross-device Authentication Request
	png, err := qrcode.Encode(crossdevice_uri, qrcode.Medium, 256)
	if err != nil {
		return nil, errl.Errorf("cannot create QR code: %w", err)
	}

	// Convert the image data to a dataURL
	base64Img := base64.StdEncoding.EncodeToString(png)
	base64Img = "data:image/png;base64," + base64Img

	data := fiber.Map{
		"AuthRequestID": authRequestID,
		"QRcode":        base64Img,
		"Samedevice":    samedevice_uri,
	}

	return data, nil

}

// APIWalletLoginPagePoll is the endpoint called periodically by the Wallet Login page to check
// if the authentication request has been processed or is still pending.
func (s *Server) APIWalletLoginPagePoll(c *fiber.Ctx) error {

	// Get state from query parameter
	authReqId := c.Query("state")
	if authReqId == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Missing state value",
		})
	}

	// Retrieve the Authentication Process object from the cache
	authProcess, err := s.getAuthProcess(authReqId)
	if err != nil {
		slog.Error("Invalid state", "state", authReqId)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": errl.Errorf("Invalid authorization code").Error(),
		})
	}

	if authProcess.FinishedWalletAuth {
		// The authentication request has been processed, so we redirect to the caller
		// with the auth code and the state.
		redirectURL := fmt.Sprintf("%s?code=%s", authProcess.RedirectURI, authProcess.Code)
		if authProcess.State != "" {
			redirectURL += fmt.Sprintf("&state=%s", authProcess.State)
		}
		return c.Redirect(redirectURL, fiber.StatusFound)

	} else {
		// The authentication request is still pending, so we return "pending" to the Wallet Login page, which
		// will call this endpoint again after a short delay.
		return c.SendString("pending")

	}

}

// This is the route that the Wallet calls to retrieve the
// OID4VP Authentication Request object
func (s *Server) APIWalletAuthenticationRequest(c *fiber.Ctx) error {

	// Retrieve the AuthorizationRequest from the application authentication session
	authProcess, err := s.getAuthProcess(c.Query("state"))
	if err != nil {
		err := errl.Errorf("getAuthProcess for state: %w", err)
		slog.Error(err.Error())
		return s.html.Render(c, "error", fiber.Map{"message": err})
	}

	slog.Info("sending back the WalletAuthentication request")

	// Get the Wallet AuthRequest
	walletAuthRequest := authProcess.WalletAuthRequest

	c.Response().Header.Add("Content-Type", "application/oauth-authz-req+jwt")
	return c.Send([]byte(walletAuthRequest))

}

// The Wallet calls this route to send the Authentication Response with the LEARCredential
func (s *Server) APIWalletAuthenticationResponse(c *fiber.Ctx) error {

	// Get state from query parameter
	authReqId := c.FormValue("state")

	// Retrieve the Authentication Process object from the cache
	authProcess, err := s.getAuthProcess(authReqId)
	if err != nil {
		err := errl.Errorf("getAuthProcess for state: %w", err)
		slog.Error(err.Error())
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Missing vp_token",
		})
	}

	// The state parameter is used to identify the in-memory AutRequest that was sent to the wallet
	slog.Info("APIWalletAuthenticationResponse", "stateKey", authReqId)

	// Get the vp_token field
	vp_token := c.FormValue("vp_token")
	if len(vp_token) == 0 {
		slog.Error("Mising vp_token", "vp_token", vp_token)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Missing vp_token",
		})
	}

	// Decode VP token from B64Url to get a JWT
	vpJWT, err := base64.RawURLEncoding.DecodeString(vp_token)
	if err != nil {
		err = errl.Errorf("error decoding vp_token: %w", err)
		slog.Error("Error decoding VP", "vp_token", vp_token)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	// The VP object is a JWT, signed with the private key associated to the user did:key
	// We must verify the signature and decode the JWT payload to get the VerifiablePresentation
	// TODO: We do not check the signature.
	var pc = jwt.MapClaims{}
	tokenParser := jwt.NewParser()
	_, _, err = tokenParser.ParseUnverified(string(vpJWT), &pc)
	if err != nil {
		err = errl.Errorf("parsing vp_token: %w", err)
		slog.Error("Error parsing vp_token", "vp_token", vp_token)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	fmt.Print(pc["vp"])

	// Parse the VP object into a map
	vp := jpath.GetMap(pc, "vp")
	if vp == nil {
		err := errl.Errorf("error parsing the VP object")
		slog.Error("Error parsing vp_token", "vp_token", vp_token)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	// Get the list of credentials in the VP
	credentials := jpath.GetList(vp, "verifiableCredential")
	if len(credentials) == 0 {
		err := errl.Errorf("no credentials found in VP")
		slog.Error("Error parsing vp_token", "vp_token", vp_token)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	// TODO: for the moment, we accept only the first credential inside the VP
	firstCredentialJWT, _ := credentials[0].(string)
	if len(firstCredentialJWT) == 0 {
		err := errl.Errorf("invalid credential in VP")
		slog.Error("Error parsing vp_token", "vp_token", vp_token)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	// The credential is in 'jwt_vc_json' format (which is a JWT)
	var credMap = jwt.MapClaims{}
	_, _, err = tokenParser.ParseUnverified(firstCredentialJWT, &credMap)
	if err != nil {
		err := errl.Errorf("error parsing the JWT:%s", errl.Error(err))
		slog.Error("Error parsing vp_token", "vp_token", vp_token)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	// Serialize the credential into a JSON string
	serialCredential, err := json.Marshal(credMap)
	if err != nil {
		err := errl.Errorf("error serialising the credential:%s", errl.Error(err))
		slog.Error("Error parsing vp_token", "vp_token", vp_token)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": err.Error(),
		})
	}
	slog.Info("credential", "cred", string(serialCredential))

	// // Invoke the PDP (Policy Decision Point) to authenticate/authorize this request
	// accepted, err := pdp.TakeAuthnDecision(Authenticate, r, string(serialCredential), "")
	// if err != nil {
	// 	slog.Error("error evaluating authentication rules", "error", err)
	// 	http.Error(w, fmt.Sprintf("error evaluating authentication rules:%s", err), http.StatusInternalServerError)
	// 	return
	// }

	// if !accepted {
	// 	slog.Error("PDP rejected authentication")
	// 	http.Error(w, "authentication failed", http.StatusUnauthorized)
	// 	return
	// }

	// Update the internal AuthProcess with the LEARCredential received from the Wallet and signal we are finished.
	authProcess.CredentialData = credMap
	authProcess.FinishedWalletAuth = true

	// Redirect to the caller sending the auth code and the state
	redirectURL := fmt.Sprintf("%s?code=%s", authProcess.RedirectURI, authProcess.Code)
	if authProcess.State != "" {
		redirectURL += fmt.Sprintf("&state=%s", authProcess.State)
	}

	// Send reply to the Wallet, so it can show a success screen
	resp := map[string]string{
		"authenticatorRequired": "no",
		"type":                  "login",
		"email":                 "email",
		"redirectURL":           redirectURL,
	}

	return c.JSON(resp)

}

// **************************************************************
// **************************************************************
// **************************************************************

// handleCertificateReceive is invoked from CertSec when the user has selected a certificate in the browser popup
func (s *Server) handleCertificateReceive(c *fiber.Ctx) error {
	// Get auth code from query parameter
	authCode := c.Query("code")

	// Retrieve the Authentication Process object from the cache
	authProcess, err := s.getAuthProcess(authCode)
	if err != nil {
		err := errl.Errorf("getAuthProcess: %w", err)
		slog.Error(err.Error())
		return s.html.Render(c, "error", fiber.Map{"message": err})
	}
	slog.Info("Certificate received entry", "auth_code", authCode)

	// Check if CertSec returned some error
	certError := c.Query("error")
	if certError != "" || authProcess.ErrorInProcess != nil {
		err := authProcess.ErrorInProcess
		slog.Error("Error:", "error", err)
		return s.html.Render(c, "error", fiber.Map{
			"message": err,
		})
	}

	// Get the certificate data that was set by the certificate authentication process
	certData := authProcess.CertificateData

	// Check if the certificate is already registered
	email, err := s.db.GetRegistrationEmail(certData.OrganizationID)
	if err != nil {
		return errl.Errorf("failed to get registration email: %w", err)
	}

	if email != "" {

		// The certificate is already registered, bypass certificate and email validation

		// Bypass certificate selection and return directly to caller
		slog.Debug("bypass certificate selection", "code", authProcess.Code, "redirect_uri", authProcess.RedirectURI)

		// Store email of the user in the authProcess struct
		authProcess.Email = email

		redirectURL := fmt.Sprintf("%s?code=%s", authProcess.RedirectURI, authProcess.Code)
		if authProcess.State != "" {
			redirectURL += fmt.Sprintf("&state=%s", authProcess.State)
		}

		return c.Redirect(redirectURL, fiber.StatusFound)

	}

	// Otherwise, we present the certificate data to the user and must request and validate its email
	slog.Info("Certificate received exit", "auth_code", authCode, "cert_length", len(certData.Certificate.Raw))

	// Present the screen
	return s.html.Render(c, "2_certificate_received", fiber.Map{
		"authCode":    authCode,
		"authCodeObj": authProcess,
		"certType":    certData.CertificateType,
		"subject":     certData.Subject,
	})

}

// handleTokenExchange handles OAuth2 token endpoint.
// This is the last step for the RP in the authentication flow.
func (s *Server) handleTokenExchange(c *fiber.Ctx) error {

	// Parse token request
	var tokenReq models.TokenRequest
	if err := c.BodyParser(&tokenReq); err != nil {
		return errl.Errorf("invalid request body: %w", err)
	}

	slog.Info("Token request received", "client_id", tokenReq.ClientID, "grant_type", tokenReq.GrantType, "code", tokenReq.Code, "code_verifier", tokenReq.CodeVerifier, "redirect_uri", tokenReq.RedirectURI)

	if tokenReq.ClientID == "" {
		// We reject immediately RPs which are not authorized
		username, err := s.validateTokenAuthorization(c)
		if err != nil {
			return errl.Errorf("invalid authorization: %w", err)
		}

		slog.Info("Client ID retrieved from Authorization header", "client_id", username)
		// Set the user name in tokenReq
		tokenReq.ClientID = username
	}

	// Retrieve the Authorization process associated with the authCode
	authProcess, err := s.getAuthProcess(tokenReq.Code)
	if err != nil {
		err = errl.Errorf("failed to get auth process: %w", err)
		slog.Error(err.Error(), "auth_code", tokenReq.Code)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	// Validate received auth code against the stored one
	if authProcess.ClientID != tokenReq.ClientID {
		return errl.Errorf("auth code client mismatch")
	}

	// Get the registered relying party
	rp, err := s.db.GetRelyingParty(tokenReq.ClientID)
	if err != nil {
		return errl.Errorf("failed to get relying party: %w", err)
	}

	// Generate tokens with certificate data if available
	tokens, err := s.generateTokens(authProcess, rp)
	if err != nil {
		return errl.Errorf("failed to generate tokens: %w", err)
	}

	// Delete used auth code
	s.cache.Delete(tokenReq.Code)

	slog.Info("Tokens generated successfully", "client_id", tokenReq.ClientID)

	return c.JSON(tokens)
}

// UserInfo handles OpenID Connect userinfo endpoint
func (s *Server) UserInfo(c *fiber.Ctx) error {
	// TODO: Implement userinfo with token validation
	return c.SendStatus(fiber.StatusNotImplemented)
}

// Logout handles logout endpoint
func (s *Server) Logout(c *fiber.Ctx) error {
	// TODO: Implement logout (no-op for now)
	return c.JSON(fiber.Map{"status": "logged_out"})
}

// Helper methods

func (s *Server) validateAuthorizationRequest(req *models.AuthorizationRequest) (errorCode string, errorDescription string) {
	if req.ResponseType != "code" {
		return "invalid_request", "unsupported response_type"
	}
	if req.ClientID == "" {
		return "invalid_request", "missing client_id"
	}
	if req.RedirectURI == "" {
		return "invalid_request", "missing redirect_uri"
	}
	if !slices.Contains(req.Scopes, "openid") {
		return "invalid_request", "openid scope required"
	}
	return "", ""
}

func (s *Server) validateTokenAuthorization(c *fiber.Ctx) (clientid string, err error) {

	// Get authorization header
	authHeader := c.Get(fiber.HeaderAuthorization)

	// Check if the header contains content besides "basic"
	if len(authHeader) <= 6 || !utils.EqualFold(authHeader[:6], "basic ") {
		return "", errl.Errorf("invalid authorization header")
	}

	// Decode the header contents
	raw, err := base64.StdEncoding.DecodeString(authHeader[6:])
	if err != nil {
		return "", errl.Errorf("invalid authorization header: %w", err)
	}

	// Get the credentials
	creds := string(raw)

	// Check if the credentials are in the correct form
	// which is "username:password".
	index := strings.Index(creds, ":")
	if index == -1 {
		return "", errl.Errorf("invalid authorization header")
	}

	// Get the username and password
	username := creds[:index]
	password := creds[index+1:]

	// Validate client credentials
	valid, err := s.db.ValidateClientSecret(username, password)
	if err != nil {
		slog.Error("Failed to validate client secret", "error", err)
		return "", errl.Errorf("internal error")
	}
	if !valid {
		return "", errl.Errorf("invalid client credentials")
	}

	username = utils.CopyString(username)
	return username, nil
}

// handleAuthorizationError handles authorization errors by redirecting to the RP with error details
func (s *Server) handleAuthorizationError(c *fiber.Ctx, redirectURI, state, errorCode, errorDescription string) error {
	slog.Error("Authorization error", "error", errorCode, "redirect_uri", redirectURI)

	redirectURL, _ := url.Parse(redirectURI)
	q := redirectURL.Query()
	if state != "" {
		q.Set("state", state)
	}
	q.Set("error", errorCode)
	q.Set("error_description", errorDescription)
	redirectURL.RawQuery = q.Encode()

	return c.Status(fiber.StatusFound).Redirect(redirectURL.String())
}

func (s *Server) generateAuthCode(req *models.AuthorizationRequest, rp *models.RelyingParty) *models.AuthProcess {
	// Generate random code
	codeBytes := make([]byte, 32)
	rand.Read(codeBytes)
	code := base64.URLEncoding.EncodeToString(codeBytes)

	authCode := &models.AuthProcess{
		Code:        code,
		ClientID:    req.ClientID,
		RedirectURI: req.RedirectURI,
		State:       req.State,
		Nonce:       req.Nonce,
		Scopes:      req.Scopes,
		CreatedAt:   time.Now(),
		ExpiresAt:   time.Now().Add(10 * time.Minute),
	}

	slog.Debug("Generated auth code", "code", authCode.Code, "client_id", authCode.ClientID, "redirect_uri", authCode.RedirectURI)
	return authCode
}

func (s *Server) generateTokens(authProcess *models.AuthProcess, rp *models.RelyingParty) (map[string]any, error) {

	if authProcess.CertificateData == nil && authProcess.CredentialData == nil {
		err := errl.Errorf("no credential or certificate data found in auth process")
		slog.Error(err.Error(), "auth_code", authProcess.Code)
		return nil, err
	}

	if authProcess.CertificateData != nil {
		// Authentication performed with a certificate

		certData := authProcess.CertificateData

		// Generate ID token
		idToken, err := s.jwtService.GenerateIDTokenForCert(authProcess, certData, rp)
		if err != nil {
			return nil, errl.Errorf("failed to generate ID token: %w", err)
		}

		tokenString, err := s.jwtService.GenerateAccessTokenForCert(authProcess, certData, rp)
		if err != nil {
			return nil, errl.Errorf("failed to generate access token: %w", err)
		}
		slog.Debug("Access Token", "token", tokenString)

		slog.Info("JWT tokens generated with certificate data",
			"organization_id", certData.OrganizationID,
			"organization", certData.Subject.Organization,
		)

		return map[string]any{
			"access_token": tokenString,
			"token_type":   "Bearer",
			"expires_in":   rp.TokenExpiry,
			"scope":        strings.Join(authProcess.Scopes, " "),
			"id_token":     idToken,
		}, nil

	} else {
		// Authentication performed with a Verifiable Credential

		credData := authProcess.CredentialData

		idToken, err := s.jwtService.GenerateIDTokenForCredential(authProcess, credData, rp)
		if err != nil {
			return nil, errl.Errorf("failed to generate ID token: %w", err)
		}

		tokenString, err := s.jwtService.GenerateAccessTokenForCredential(authProcess, credData, rp)
		if err != nil {
			return nil, errl.Errorf("failed to generate access token: %w", err)
		}

		slog.Info("JWT tokens generated with credential data")

		return map[string]any{
			"access_token": tokenString,
			"token_type":   "Bearer",
			"expires_in":   rp.TokenExpiry,
			"scope":        strings.Join(authProcess.Scopes, " "),
			"id_token":     idToken,
		}, nil

	}

}

func generateRandomString() string {
	tokenBytes := make([]byte, 32)
	rand.Read(tokenBytes)

	return base64.URLEncoding.EncodeToString(tokenBytes)
}

// handleJWKS handles the JSON Web Key Set endpoint
func (s *Server) handleJWKS(c *fiber.Ctx) error {
	jwks := s.jwtService.GetJWKS()
	return c.JSON(jwks)
}

// handleRequestEmailVerification handles the email verification form submission
func (s *Server) handleRequestEmailVerification(c *fiber.Ctx) error {
	// Get form data
	email := utils.CopyString(c.FormValue("email"))
	authCode := c.FormValue("auth_code")

	// Retrieve the Authentication Process object from the cache
	authProcess, err := s.getAuthProcess(authCode)
	if err != nil {
		err := errl.Errorf("getAuthProcess: %w", err)
		slog.Error(err.Error())
		return s.html.Render(c, "error", fiber.Map{"message": err})
	}

	if email == "" || authCode == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Missing email or authorization code",
		})
	}

	// Basic email format validation
	if !isValidEmail(email) {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid email format",
		})
	}

	slog.Info("Email verification requested", "email", email, "auth_code", authCode)

	certData := authProcess.CertificateData
	if certData == nil {
		err := errl.Errorf("certificate data not found in authorization request")
		slog.Error(err.Error(), "auth_code", authCode)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	// Generate a random 6-digit verification code
	emailVerificationCode := generateRandomCode()

	// Waiting for verification of the email address
	authProcess.Email = email
	authProcess.EmailVerificationCode = emailVerificationCode

	slog.Info("Verification code generated", "code", emailVerificationCode, "auth_code", authCode)

	// Render the confirm_email template
	return s.html.Render(c, "3_confirm_email", fiber.Map{
		"email":            email,
		"authCode":         authCode,
		"verificationCode": emailVerificationCode, // For testing - remove in production
		"subject":          certData.Subject,
	})
}

// isValidEmail performs basic email format validation
func isValidEmail(email string) bool {
	// Simple regex for basic email validation
	emailRegex := `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
	matched, _ := regexp.MatchString(emailRegex, email)
	return matched
}

// generateRandomCode generates a random 6-digit verification code
func generateRandomCode() string {
	// Generate a random 6-digit number
	a, _ := rand.Int(rand.Reader, big.NewInt(999999))

	return fmt.Sprintf("%06d", a.Uint64())

}

// handleVerifyEmailCode handles the email verification code verification
func (s *Server) handleVerifyEmailCode(c *fiber.Ctx) error {
	// Get form data
	emailVerificationCode := utils.CopyString(c.FormValue("verification_code"))
	authCode := utils.CopyString(c.FormValue("auth_code"))
	email := utils.CopyString(c.FormValue("email"))

	if emailVerificationCode == "" || authCode == "" || email == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Missing verification code, authorization code, or email",
		})
	}

	slog.Info("Email verification code verification requested", "email", email, "auth_code", authCode)

	// Retrieve the Authentication Process object from the cache
	authProcess, err := s.getAuthProcess(authCode)
	if err != nil {
		err := errl.Errorf("getAuthProcess: %w", err)
		slog.Error(err.Error())
		return s.html.Render(c, "error", fiber.Map{"message": err})
	}

	storedEmailVerificationCode := authProcess.EmailVerificationCode
	if storedEmailVerificationCode == "" {
		err := errl.Errorf("email verification code not found in authorization request")
		slog.Error(err.Error(), "auth_code", authCode)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	// Verify the code
	if emailVerificationCode != storedEmailVerificationCode {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid verification code",
		})
	}

	slog.Info("Email verification code verified successfully", "email", email, "auth_code", authCode)

	storedEmail := authProcess.Email
	if storedEmail != email {
		err := errl.Errorf("email mismatch in authorization request")
		slog.Error(err.Error(), "auth_code", authCode)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	slog.Debug("Stored email", "email", storedEmail)

	certData := authProcess.CertificateData

	// Update the email field in the certificate data
	certData.Subject.EmailAddress = storedEmail

	// Get the current date
	currentDate := time.Now()
	year := currentDate.Year()
	month := currentDate.Month()
	day := currentDate.Day()
	currentDateMap := map[string]int{
		"year":  year,
		"month": int(month),
		"day":   day,
	}

	// Render the certificate consent template
	return s.html.Render(c, "4_contract", fiber.Map{
		"authCode":    authCode,
		"authCodeObj": authProcess,
		"certType":    certData.CertificateType,
		"subject":     certData.Subject,
		"email":       storedEmail,
		"date":        currentDateMap,
	})
}

// handleCertificateConsent is the last step, after the user has given consent to proceed.
// We then generate the SSO cookie and redirect to the RP with the auth code.
// The RP will eventually exchange the auth code for ID and access tokens, which will contain user and certificate data.
func (s *Server) handleCertificateConsent(c *fiber.Ctx) error {
	// Get form data
	authCode := utils.CopyString(c.FormValue("auth_code"))
	email := utils.CopyString(c.FormValue("email"))

	if authCode == "" || email == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Missing verification code or email",
		})
	}

	slog.Info("Consent received from user", "email", email, "auth_code", authCode)

	// Retrieve the Authentication Process object from the cache
	authProcess, err := s.getAuthProcess(authCode)
	if err != nil {
		err := errl.Errorf("getAuthProcess: %w", err)
		slog.Error(err.Error())
		return s.html.Render(c, "error", fiber.Map{"message": err})
	}

	storedEmail := authProcess.Email
	if storedEmail != email {
		err := errl.Errorf("email mismatch in authorization request")
		slog.Error(err.Error(), "auth_code", authCode)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	slog.Debug("Stored email", "email", storedEmail)

	// Store the company data in the registrations table
	if err := s.db.CreateRegistration(authProcess.CertificateData, storedEmail); err != nil {
		err = errl.Errorf("creating registration: %w", err)
		slog.Error(err.Error(), "auth_code", authCode)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})

	}

	// Generate a random unique identifier for the SSO session
	ssoSessionID := generateRandomString()

	// Create the SSO session data to be held in the server-side cache
	ssoSession := &models.SSOSession{
		SessionID:       ssoSessionID,
		Email:           storedEmail,
		CertificateData: authProcess.CertificateData,
	}

	// Store the SSO session in the cache (valid for 24 hours)
	s.cache.Set(ssoSessionID, ssoSession, 24*time.Hour)

	// Generate SSO cookie
	ssoCookie, err := s.generateSSOCookie(ssoSessionID, ssoSession.CertificateData)
	if err != nil {
		slog.Error("failed to generate sso cookie", "error", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Internal server error",
		})
	}

	// Set SSO cookie
	c.Cookie(ssoCookie)

	// Redirect (302) to RP with auth code
	slog.Info("User consent processed successfully", "email", email, "auth_code", authCode)
	// href="{{ .authCodeObj.RedirectURI }}?code={{ .authCode }}&state={{ .authCodeObj.State }}"
	redirectURL := fmt.Sprintf("%s?code=%s", authProcess.RedirectURI, authCode)
	if authProcess.State != "" {
		redirectURL += fmt.Sprintf("&state=%s", authProcess.State)
	}

	return c.Redirect(redirectURL, fiber.StatusFound)

}

// generateSSOCookie generates the SSO cookie
func (s *Server) generateSSOCookie(ssoSessionID string, certData *models.CertificateData) (*fiber.Cookie, error) {

	// Determine the sub identifier based on certificate type
	var sub string
	if certData.Subject.OrganizationIdentifier != "" {
		sub = certData.Subject.OrganizationIdentifier
	} else {
		// For personal certificates, use serial number or generate a unique identifier
		if certData.Subject.SerialNumber != "" {
			sub = certData.Subject.SerialNumber
		} else if certData.Subject.CommonName != "" {
			sub = certData.Subject.CommonName
		} else {
			return nil, errl.Errorf("cannot determine subject identifier for SSO cookie")
		}
	}

	// Standard OIDC claims
	claims := jwtV5.MapClaims{
		// Standard claims
		"iss":   s.jwtService.Issuer(),                 // Issuer
		"sub":   sub,                                   // Subject (org ID or personal identifier)
		"aud":   s.cfg.CertAuthURL,                     // Audience
		"exp":   time.Now().Add(24 * time.Hour).Unix(), // Expiration
		"iat":   time.Now().Unix(),                     // Issued at
		"email": certData.Subject.EmailAddress,         // Email
		// Custom claims
		"session_id": ssoSessionID, // SSO session ID
	}

	// Generate the token
	token, err := s.jwtService.GenerateSSOCookieToken(claims)
	if err != nil {
		return nil, fmt.Errorf("failed to generate sso token: %w", err)
	}

	// Generate SSO cookie
	cookie := new(fiber.Cookie)
	cookie.Name = "__Http-sso_certauth"
	cookie.Value = token
	// cookie.Expires = time.Now().Add(24 * time.Hour)
	cookie.Secure = true
	cookie.HTTPOnly = true
	cookie.SameSite = "Lax"
	cookie.SessionOnly = true

	// Set the domain to the main domain so it's accessible by subdomains
	u, err := url.Parse(s.cfg.CertAuthURL)
	if err != nil {
		slog.Error("failed to parse cert auth url", "error", err)
	} else {
		hostname := u.Hostname()
		// Heuristic to get the naked domain.
		// This works for domains like 'example.com' and 'sub.example.com',
		// but not for 'example.co.uk'.
		if hostname != "localhost" && net.ParseIP(hostname) == nil {
			parts := strings.Split(hostname, ".")
			if len(parts) > 2 {
				hostname = strings.Join(parts[len(parts)-2:], ".")
			}
		}
		cookie.Domain = hostname
	}

	return cookie, nil
}

func (s *Server) getAuthProcess(authCode string) (*models.AuthProcess, error) {
	if authCode == "" {
		return nil, errl.Errorf("Missing authorization code")
	}

	// Retrieve the AuthorizationRequest from the application authentication session
	entry, _ := s.cache.Get(authCode)
	if entry == nil {
		return nil, errl.Errorf("Authorization code not found in cache for auth_code: %s", authCode)
	}

	authProcess, ok := entry.(*models.AuthProcess)
	if !ok {
		return nil, errl.Errorf("Invalid authorization request type in cache for auth_code: %s", authCode)
	}

	return authProcess, nil

}
