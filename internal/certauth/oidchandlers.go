package certauth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/evidenceledger/certauth/internal/errl"
	"github.com/evidenceledger/certauth/internal/models"
	"github.com/evidenceledger/certauth/internal/util/x509util"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/utils"
	jwtV5 "github.com/golang-jwt/jwt/v5"
)

const (
	oidc_configuration     = "/.well-known/openid-configuration"
	authorization_endpoint = "/oauth2/auth"
	token_endpoint         = "/oauth2/token"
	userinfo_endpoint      = "/oauth2/userinfo"
	jwks_uri               = "/.well-known/jwks.json"
)

// handleDiscovery handles OIDC discovery endpoint
func (s *Server) handleDiscovery(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{
		"issuer":                                s.cfg.CertAuthURL,
		"authorization_endpoint":                s.cfg.CertAuthURL + authorization_endpoint,
		"token_endpoint":                        s.cfg.CertAuthURL + token_endpoint,
		"userinfo_endpoint":                     s.cfg.CertAuthURL + userinfo_endpoint,
		"jwks_uri":                              s.cfg.CertAuthURL + jwks_uri,
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "eidas"},
		"claims_supported":                      []string{"sub", "iss", "aud", "exp", "iat", "name", "given_name", "family_name", "email", "elsi_organization", "elsi_organization_identifier", "elsi_country"},
	})
}

// Authorization handles OAuth2 authorization endpoint
func (s *Server) Authorization(c *fiber.Ctx) error {
	slog.Info("Authorization request received",
		"client_id", c.Query("client_id"),
		"redirect_uri", c.Query("redirect_uri"))

	state := c.Query("state")

	// Parse authorization request
	authReq := &models.AuthorizationRequest{
		ResponseType: c.Query("response_type"),
		ClientID:     c.Query("client_id"),
		RedirectURI:  c.Query("redirect_uri"),
		Scope:        c.Query("scope"),
		State:        state,
		Nonce:        c.Query("nonce"),
		CreatedAt:    time.Now(),
	}

	// Validate request
	if err := s.validateAuthorizationRequest(authReq); err != nil {
		return s.handleAuthorizationError(c, authReq, errl.Errorf("invalid authorization request: %w", err))
	}

	// Retrieve information we have about the relying party
	rp, err := s.db.GetRelyingParty(authReq.ClientID)
	if err != nil {
		return s.handleAuthorizationError(c, authReq, errl.Errorf("database error: %w", err))
	}
	if rp == nil {
		return s.handleAuthorizationError(c, authReq, errl.Errorf("invalid client_id"))
	}

	// Validate redirect_uri matches registered RP redirect URL
	if authReq.RedirectURI != rp.RedirectURL {
		return s.handleAuthorizationError(c, authReq, errl.Errorf("redirect_uri mismatch"))
	}

	// Check if certificate authentication is requested with scope 'eidas'
	if !strings.Contains(authReq.Scope, "eidas") {
		return s.handleAuthorizationError(c, authReq, errl.Errorf("eidas scope required"))
	}

	// Check if we received the SSO cookie
	ssoCookie := c.Cookies("sso_certauth")
	ssoClaims, err := s.jwtService.ParseSSOCookieToken(ssoCookie)
	if err != nil {
		slog.Warn("Invalid SSO cookie received, proceeding with normal flow", "error", err)
	}

	var ssoSession *models.SSOSession
	if ssoClaims != nil {

		// Valid SSO cookie, bypass certificate selection
		slog.Info("Valid SSO cookie received", "subject", ssoClaims["sub"])

		// Retrieve the SSO session ID from the claims
		ssoSessionID, _ := ssoClaims["session_id"].(string)

		// Retrieve the SSO session data from the cache
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

	// Generate an authorization code for this RP authentication process
	// But we will bypass certificate selection and use the certificate data from the SSO session
	authProcess := s.generateAuthCode(authReq, rp)

	// Generate the application authorization session
	// We use the cache with an expiration reasonable for the user to select and use the certificate
	// The key is the auth code, the value is the certificate data once received
	s.cache.Set(authProcess.Code, authProcess, 15*time.Minute)

	if ssoSession != nil {

		// Bypass certificate selection and return directly to caller
		slog.Debug("bypass certificate selection", "code", authProcess.Code, "redirect_uri", c.Query("redirect_uri"))

		// Store certificate data and email of the user in the authProcess struct
		authProcess.CertificateData = ssoSession.CertificateData
		authProcess.Email = ssoSession.Email

		redirectURL := fmt.Sprintf("%s?code=%s", c.Query("redirect_uri"), authProcess.Code)
		if state != "" {
			redirectURL += fmt.Sprintf("&state=%s", state)
		}

		return c.Redirect(redirectURL, fiber.StatusFound)

	} else {

		// No valid SSO cookie, proceed with normal flow

		// Redirect to certificate authentication
		redirectURL := s.cfg.CertAuthURL + "/certificate-select?code=" + authProcess.Code
		return c.Status(fiber.StatusFound).Redirect(redirectURL)

	}

}

// handleTokenExchange handles OAuth2 token endpoint
func (s *Server) handleTokenExchange(c *fiber.Ctx) error {
	slog.Info("Token request received")

	// Parse token request
	var tokenReq models.TokenRequest
	if err := c.BodyParser(&tokenReq); err != nil {
		return errl.Errorf("invalid request body: %w", err)
	}

	// Get authorization header
	auth := c.Get(fiber.HeaderAuthorization)

	// Check if the header contains content besides "basic".
	if len(auth) <= 6 || !utils.EqualFold(auth[:6], "basic ") {
		return errl.Errorf("invalid authorization header")
	}

	// Decode the header contents
	raw, err := base64.StdEncoding.DecodeString(auth[6:])
	if err != nil {
		return errl.Errorf("invalid authorization header: %w", err)
	}

	// Get the credentials
	creds := utils.UnsafeString(raw)

	// Check if the credentials are in the correct form
	// which is "username:password".
	index := strings.Index(creds, ":")
	if index == -1 {
		return errl.Errorf("invalid authorization header")
	}

	// Get the username and password
	username := creds[:index]
	password := creds[index+1:]

	// Set the fields in tokenReq
	tokenReq.ClientID = username
	tokenReq.ClientSecret = password

	// Validate client credentials
	valid, err := s.db.ValidateClientSecret(username, password)
	if err != nil {
		slog.Error("Failed to validate client secret", "error", err)
		return errl.Errorf("internal error")
	}
	if !valid {
		return errl.Errorf("invalid client credentials")
	}

	// Retrieve the AuthorizationRequest associated with the authCode
	authCodeIntf, _ := s.cache.Get(tokenReq.Code)
	if authCodeIntf == nil {
		err := errl.Errorf("authorization code not found in cache")
		slog.Error(err.Error(), "auth_code", tokenReq.Code)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	authProcess, ok := authCodeIntf.(*models.AuthProcess)
	if !ok {
		err := errl.Errorf("invalid authorization request type in cache")
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

	certData := authProcess.CertificateData
	if certData == nil {
		slog.Error("No certificate data found in auth process, proceeding without it", "auth_code", tokenReq.Code)
		return errl.Errorf("no certificate data found in auth process: %s", tokenReq.Code)
	}

	// Generate tokens with certificate data if available
	tokens, err := s.generateTokens(authProcess, rp, certData)
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

// AdminDashboard handles admin dashboard
func (s *Server) AdminDashboard(c *fiber.Ctx) error {
	// TODO: Implement admin dashboard
	return c.SendStatus(fiber.StatusNotImplemented)
}

// ListRP lists all relying parties
func (s *Server) ListRP(c *fiber.Ctx) error {
	rps, err := s.db.ListRelyingParties()
	if err != nil {
		return errl.Errorf("failed to list relying parties: %w", err)
	}

	return c.JSON(rps)
}

// CreateRP creates a new relying party
func (s *Server) CreateRP(c *fiber.Ctx) error {
	// TODO: Implement RP creation
	return c.SendStatus(fiber.StatusNotImplemented)
}

// UpdateRP updates an existing relying party
func (s *Server) UpdateRP(c *fiber.Ctx) error {
	// TODO: Implement RP update
	return c.SendStatus(fiber.StatusNotImplemented)
}

// DeleteRP deletes a relying party
func (s *Server) DeleteRP(c *fiber.Ctx) error {
	// TODO: Implement RP deletion
	return c.SendStatus(fiber.StatusNotImplemented)
}

// Helper methods

func (s *Server) validateAuthorizationRequest(req *models.AuthorizationRequest) error {
	if req.ResponseType != "code" {
		return errl.Errorf("unsupported response_type")
	}
	if req.ClientID == "" {
		return errl.Errorf("missing client_id")
	}
	if req.RedirectURI == "" {
		return errl.Errorf("missing redirect_uri")
	}
	if !strings.Contains(req.Scope, "openid") {
		return errl.Errorf("openid scope required")
	}
	if !strings.Contains(req.Scope, "eidas") {
		return errl.Errorf("eidas scope required")
	}
	return nil
}

// handleAuthorizationError handles authorization errors by redirecting to the RP with error details
func (s *Server) handleAuthorizationError(c *fiber.Ctx, req *models.AuthorizationRequest, err error) error {
	slog.Error("Authorization error", "error", err, "client_id", req.ClientID, "redirect_uri", req.RedirectURI)

	errorCode := "invalid_request"
	if strings.Contains(err.Error(), "client_id") {
		errorCode = "unauthorized_client"
	}

	redirectURL, _ := url.Parse(req.RedirectURI)
	q := redirectURL.Query()
	q.Set("error", errorCode)
	q.Set("error_description", err.Error())
	if req.State != "" {
		q.Set("state", req.State)
	}
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
		Scope:       req.Scope,
		CreatedAt:   time.Now(),
		ExpiresAt:   time.Now().Add(10 * time.Minute),
	}

	slog.Debug("Generated auth code", "code", authCode.Code, "client_id", authCode.ClientID, "redirect_uri", authCode.RedirectURI)
	return authCode
}

func (s *Server) generateTokens(authCode *models.AuthProcess, rp *models.RelyingParty, certData *models.CertificateData) (map[string]any, error) {
	if s.jwtService == nil {
		// Fallback to basic tokens if JWT service is not available
		accessToken := generateRandomString()
		return map[string]any{
			"access_token": accessToken,
			"token_type":   "Bearer",
			"expires_in":   3600,
			"scope":        authCode.Scope,
			"id_token":     "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...", // Placeholder
		}, nil
	}

	// If we have certificate data, generate real JWT tokens
	if certData != nil {

		storedEmail, found := s.cache.Get(authCode.Code + "_verified_email")
		slog.Debug("generateTokens", "storedEmail", storedEmail, "found", found)
		// Generate ID token
		idToken, err := s.jwtService.GenerateIDToken(authCode, certData, rp)
		if err != nil {
			return nil, errl.Errorf("failed to generate ID token: %w", err)
		}

		// Generate access token
		accessToken, err := s.jwtService.GenerateAccessToken(authCode, certData, rp)
		if err != nil {
			return nil, errl.Errorf("failed to generate access token: %w", err)
		}

		slog.Info("Real JWT tokens generated with certificate data",
			"organization_id", certData.OrganizationID,
			"organization", certData.Subject.Organization,
		)

		return map[string]any{
			"access_token": accessToken.AccessToken,
			"token_type":   accessToken.TokenType,
			"expires_in":   accessToken.ExpiresIn,
			"scope":        accessToken.Scope,
			"id_token":     idToken,
		}, nil
	}

	// Fallback to basic tokens without certificate data
	accessToken := generateRandomString()
	return map[string]interface{}{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   rp.TokenExpiry,
		"scope":        authCode.Scope,
		"id_token":     "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...", // Placeholder for now
	}, nil
}

func generateRandomString() string {
	tokenBytes := make([]byte, 32)
	rand.Read(tokenBytes)

	return base64.URLEncoding.EncodeToString(tokenBytes)
}

// handleCertificateSelect handles the certificate selection screen
func (s *Server) handleCertificateSelect(c *fiber.Ctx) error {
	// Get auth code from query parameter
	authCode := c.Query("code")
	if authCode == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Missing authorization code",
		})
	}

	slog.Info("Certificate selection requested", "auth_code", authCode)

	// Send HTML response
	return s.html.Render(c, "1_certificate_select", fiber.Map{
		"authCode":   authCode,
		"certsecURL": s.cfg.CertSecURL,
	})

}

func (s *Server) handleCertificateReceive(c *fiber.Ctx) error {
	// Get auth code from query parameter
	authCode := c.Query("code")
	if authCode == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Missing authorization code",
		})
	}

	slog.Info("Certificate received entry", "auth_code", authCode)

	// Retrieve the AuthorizationRequest from the application authentication session
	entry, _ := s.cache.Get(authCode)
	if entry == nil {
		slog.Error("Authorization code not found in cache", "auth_code", authCode)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Authorization code not found",
		})
	}

	authCodeObj, ok := entry.(*models.AuthProcess)
	if !ok {
		slog.Error("Invalid authorization request type in cache", "auth_code", authCode)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid authorization request",
		})
	}

	// Get the certificate data that was set by the certificate authentication process
	certData := authCodeObj.CertificateData

	slog.Info("Certificate received exit", "auth_code", authCode, "cert_length", len(certData.Certificate.Raw))

	// Send HTML response
	return s.html.Render(c, "2_certificate_received", fiber.Map{
		"authCode":    authCode,
		"authCodeObj": authCodeObj,
		"certType":    certData.CertificateType,
		"subject":     certData.Subject,
	})

}

// handleJWKS handles the JSON Web Key Set endpoint
func (s *Server) handleJWKS(c *fiber.Ctx) error {
	jwks := s.jwtService.GetJWKS()
	return c.JSON(jwks)
}

// handleTestToken creates a test token with organizational certificate data
func (s *Server) handleTestToken(c *fiber.Ctx) error {
	slog.Debug("Test organizational token generation requested")

	// Create test organizational certificate data
	testCertData := &models.CertificateData{
		Subject: &x509util.ELSIName{
			Country:                "ES",
			Organization:           "Test Organization",
			OrganizationalUnit:     "IT Department",
			CommonName:             "Test User",
			GivenName:              "Test",
			Surname:                "User",
			EmailAddress:           "test@example.com",
			OrganizationIdentifier: "ES-123456789",
			Locality:               "Madrid",
			Province:               "Madrid",
			StreetAddress:          "Calle Test 123",
			PostalCode:             "28001",
			SerialNumber:           "123456789ABC",
		},
		Issuer: &x509util.ELSIName{
			Country:                "ES",
			Organization:           "Test Organization",
			OrganizationIdentifier: "ES-123456789",
		},
		ValidFrom:       time.Now(),
		ValidTo:         time.Now().Add(365 * 24 * time.Hour),
		OrganizationID:  "ES-123456789",
		CertificateType: "organizational",
	}

	return s.generateTestTokens(c, testCertData)
}

// handleTestPersonalToken creates a test token with personal certificate data
func (s *Server) handleTestPersonalToken(c *fiber.Ctx) error {
	slog.Debug("Test personal token generation requested")

	// Create test personal certificate data
	testCertData := &models.CertificateData{
		Subject: &x509util.ELSIName{
			Country:       "ES",
			CommonName:    "Juan Pérez García",
			GivenName:     "Juan",
			Surname:       "Pérez García",
			EmailAddress:  "juan.perez@example.com",
			Locality:      "Barcelona",
			Province:      "Barcelona",
			StreetAddress: "Carrer de Test 456",
			PostalCode:    "08001",
			SerialNumber:  "PERS123456789",
		},
		Issuer: &x509util.ELSIName{
			Country: "ES",
		},
		ValidFrom:       time.Now(),
		ValidTo:         time.Now().Add(365 * 24 * time.Hour),
		OrganizationID:  "", // Empty for personal certificates
		CertificateType: "personal",
	}

	return s.generateTestTokens(c, testCertData)
}

// handleTestCallback handles the test callback endpoint to display the received authorization code
func (s *Server) handleTestCallback(c *fiber.Ctx) error {
	authCode := c.Query("code")
	state := c.Query("state")
	error := c.Query("error")
	errorDescription := c.Query("error_description")

	slog.Info("Test callback received", "auth_code", authCode, "state", state, "error", error)

	// Return a simple HTML page showing the callback parameters
	html := `<!DOCTYPE html>
<html>
<head>
    <title>OIDC Callback Test</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .container { max-width: 800px; margin: 0 auto; }
        .success { background: #d4edda; border: 1px solid #c3e6cb; padding: 15px; border-radius: 4px; margin: 20px 0; }
        .error { background: #f8d7da; border: 1px solid #f5c6cb; padding: 15px; border-radius: 4px; margin: 20px 0; }
        .code { background: #f8f9fa; border: 1px solid #e9ecef; padding: 10px; border-radius: 4px; font-family: monospace; margin: 10px 0; }
    </style>
</head>
<body>
    <div class="container">
        <h1>OIDC Callback Test</h1>`

	if error != "" {
		html += `
        <div class="error">
            <h2>Error Received</h2>
            <p><strong>Error:</strong> ` + error + `</p>
            <p><strong>Description:</strong> ` + errorDescription + `</p>
            <p><strong>State:</strong> ` + state + `</p>
        </div>`
	} else {
		html += `
        <div class="success">
            <h2>Success!</h2>
            <p>The OIDC authorization code flow completed successfully.</p>
            <p><strong>Authorization Code:</strong></p>
            <div class="code">` + authCode + `</div>
            <p><strong>State:</strong> ` + state + `</p>
            <p><em>Note: This is a test callback. In a real application, the RP would exchange this authorization code for tokens.</em></p>
        </div>`
	}

	html += `
    </div>
</body>
</html>`

	c.Set("Content-Type", "text/html; charset=utf-8")
	return c.Send([]byte(html))
}

// generateTestTokens generates test JWT tokens with the provided certificate data
func (s *Server) generateTestTokens(c *fiber.Ctx, certData *models.CertificateData) error {
	// Create test auth code and RP
	testAuthCode := &models.AuthProcess{
		Code:        "test-code-123",
		ClientID:    "test-client",
		RedirectURI: "http://localhost:3000/callback",
		Scope:       "openid eidas",
		CreatedAt:   time.Now(),
	}

	testRP := &models.RelyingParty{
		ID:          1,
		Name:        "Test Application",
		Description: "Test application for development",
		ClientID:    "test-client",
		RedirectURL: "http://localhost:3000/callback",
		OriginURL:   "http://localhost:3000",
		Scopes:      "openid eidas",
		TokenExpiry: 3600,
	}

	// Generate ID token
	idToken, err := s.jwtService.GenerateIDToken(testAuthCode, certData, testRP)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to generate ID token",
		})
	}

	// Generate access token
	accessToken, err := s.jwtService.GenerateAccessToken(testAuthCode, certData, testRP)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to generate access token",
		})
	}

	slog.Info("Test tokens generated successfully",
		"certificate_type", certData.CertificateType,
		"subject", certData.Subject.CommonName,
		"organization_id", certData.OrganizationID,
	)

	return c.JSON(fiber.Map{
		"access_token":     accessToken.AccessToken,
		"token_type":       accessToken.TokenType,
		"expires_in":       accessToken.ExpiresIn,
		"scope":            accessToken.Scope,
		"id_token":         idToken,
		"certificate_type": certData.CertificateType,
		"organization_id":  certData.OrganizationID,
	})
}

// handleRequestEmailVerification handles the email verification form submission
func (s *Server) handleRequestEmailVerification(c *fiber.Ctx) error {
	// Get form data
	email := utils.CopyString(c.FormValue("email"))
	authCode := c.FormValue("auth_code")

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

	// Retrieve the AuthorizationRequest associated with the authCode
	authCodeIntf, _ := s.cache.Get(authCode)
	if authCodeIntf == nil {
		err := errl.Errorf("authorization code not found in cache")
		slog.Error(err.Error(), "auth_code", authCode)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	authProcess, ok := authCodeIntf.(*models.AuthProcess)
	if !ok {
		err := errl.Errorf("invalid authorization request type in cache")
		slog.Error(err.Error(), "auth_code", authCode)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

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

	// Retrieve the AuthProcess associated with the authCode
	authCodeIntf, _ := s.cache.Get(authCode)
	if authCodeIntf == nil {
		err := errl.Errorf("authorization code not found in cache")
		slog.Error(err.Error(), "auth_code", authCode)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	authProcess, ok := authCodeIntf.(*models.AuthProcess)
	if !ok {
		err := errl.Errorf("invalid authorization request type in cache")
		slog.Error(err.Error(), "auth_code", authCode)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
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

	// Render the certificate consent template
	return s.html.Render(c, "4_request_certificate_consent", fiber.Map{
		"authCode":    authCode,
		"authCodeObj": authProcess,
		"certType":    certData.CertificateType,
		"subject":     certData.Subject,
		"email":       storedEmail,
	})
}

// handleConsent is the last step, after the user has given consent to proceed.
// We then generate the SSO cookie and redirect to the RP with the auth code.
// The RP will eventually exchange the auth code for ID and access tokens, which will contain user and certificate data.
func (s *Server) handleConsent(c *fiber.Ctx) error {
	// Get form data
	authCode := utils.CopyString(c.FormValue("auth_code"))
	email := utils.CopyString(c.FormValue("email"))

	if authCode == "" || email == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Missing verification code or email",
		})
	}

	slog.Info("Consent received from user", "email", email, "auth_code", authCode)

	// Retrieve the AuthProcess associated with the authCode
	authCodeIntf, _ := s.cache.Get(authCode)
	if authCodeIntf == nil {
		err := errl.Errorf("authorization code not found in cache")
		slog.Error(err.Error(), "auth_code", authCode)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	authProcess, ok := authCodeIntf.(*models.AuthProcess)
	if !ok {
		err := errl.Errorf("invalid authorization request type in cache")
		slog.Error(err.Error(), "auth_code", authCode)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
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
	cookie.Name = "sso_certauth"
	cookie.Value = token
	cookie.Expires = time.Now().Add(24 * time.Hour)
	cookie.Secure = true
	cookie.HTTPOnly = true
	cookie.SameSite = "Lax"

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

// Start starts the server
func (s *Server) Start(ctx context.Context) error {

	addr := net.JoinHostPort("0.0.0.0", s.cfg.CertAuthPort)
	slog.Info("Starting CertAuth server", "addr", addr)

	// Start server in goroutine
	errChan := make(chan error, 1)
	go func() {
		if err := s.app.Listen(addr); err != nil {
			errChan <- fmt.Errorf("failed to start server: %w", err)
		}
	}()

	// Wait for context cancellation or error
	select {
	case err := <-errChan:
		return err
	case <-ctx.Done():
		return s.app.Shutdown()
	}
}
