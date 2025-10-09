package onboard

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/evidenceledger/certauth/internal/errl"
	"github.com/evidenceledger/certauth/internal/html"
	"github.com/evidenceledger/certauth/internal/models"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

// Server represents the example RP server
type Server struct {
	internalPort  string
	ourURL        string
	providerURL   string
	sessions      map[string]*models.RPSession
	sessionsMutex sync.RWMutex
	clientID      string
	clientSecret  string
	oauth2Config  oauth2.Config
	verifier      *oidc.IDTokenVerifier
	html          *html.RendererStd
}

const templateDebug = true

//go:embed views/*
var viewsfs embed.FS

// New creates a new Application server.
// internalPort is the port on which the server will listen for internal requests.
// ourURL is the public URL of the server.
// providerURL is the URL of the OpenID Provider (OP).
// clientID is our RP client ID as registered in the OP.
// clientSecret is our RP client secret as registered in the OP.
func New(internalPort, ourURL, providerURL, clientID, clientSecret string) *Server {
	slog.Info("Initializing RP", "internal_port", internalPort, "our_url", ourURL, "provider_url", providerURL, "client_id", clientID)

	// Initialize the template engine
	htmlrender, err := html.NewRendererStd(templateDebug, viewsfs, "internal/onboard/views")
	if err != nil {
		slog.Error("Failed to initialize template engine", "error", err)
		panic(err)
	}

	// Initialize the server
	return &Server{
		internalPort: internalPort,
		ourURL:       ourURL,
		providerURL:  providerURL,
		sessions:     make(map[string]*models.RPSession),
		clientID:     clientID,
		clientSecret: clientSecret,
		html:         htmlrender,
	}
}

// Start starts the application server
func (s *Server) Start() error {
	http.HandleFunc("/", s.handleHome)
	http.HandleFunc("/login", s.handleLogin)
	http.HandleFunc("/callback", s.handleCallback)
	http.HandleFunc("/logout", s.handleLogout)

	ctx := context.Background()

	// Configure how to call the provider via discovery
	provider, err := oidc.NewProvider(ctx, s.providerURL)
	if err != nil {
		return errl.Errorf("failed to create provider: %w", err)
	}

	// Get an IDTokenVerifier that uses the provider's key set to verify JWTs
	verifier := provider.Verifier(&oidc.Config{
		ClientID: s.clientID,
		SupportedSigningAlgs: []string{
			"RS256",
			"ES256",
			"PS256",
		},
	})

	// We want the OP to call us back here
	redirectURL, err := url.JoinPath(s.ourURL, "/callback")
	if err != nil {
		return errl.Errorf("failed to parse our URL: %w", err)
	}

	// Configure an OpenID Connect aware OAuth2 client.
	oauth2Config := oauth2.Config{
		ClientID:     s.clientID,
		ClientSecret: s.clientSecret,
		RedirectURL:  redirectURL,

		// Discovery returns the OAuth2 endpoints.
		Endpoint: provider.Endpoint(),

		// "openid" is a required scope for OpenID Connect flows.
		// "eidas" is the scope for the eIDAS flow
		Scopes: []string{oidc.ScopeOpenID, "eidas"},
	}

	s.oauth2Config = oauth2Config
	s.verifier = verifier

	addr := net.JoinHostPort("0.0.0.0", s.internalPort)
	slog.Info("Starting example RP server", "addr", addr, "op_base_url", s.providerURL)

	return http.ListenAndServe(addr, nil)
}

// handleHome handles the home page
func (s *Server) handleHome(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	// Check if user is logged in
	sessionID := s.getSessionID(r)
	if session := s.getSession(sessionID); session != nil {
		s.renderWelcomePage(w, session)
		return
	}

	// Show login page
	s.renderLoginPage(w)
}

// handleLogin initiates the OIDC flow
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	// Generate state for CSRF protection
	state := s.generateRandomString(32)

	// Generate nonce for replay protection
	nonce := s.generateRandomString(32)

	// Store state in session (in a real app, you'd use proper session management)
	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_state",
		Value:    state,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   300, // 5 minutes
	})

	// Redirect to the OP for authentication
	redirectURL := s.oauth2Config.AuthCodeURL(state, oauth2.SetAuthURLParam("nonce", nonce))
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// handleCallback handles the OIDC callback
// The OP calls us here when it has finished authenticating the user
func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	// Get parameters from callback
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	autherror := r.URL.Query().Get("error")
	errorDescription := r.URL.Query().Get("error_description")

	// Validate that the state we received is the same as the one we sent
	cookieState, err := r.Cookie("oauth_state")
	if err != nil || cookieState.Value != state {
		slog.Error("Invalid state parameter", "error", err)
		http.Error(w, "Invalid state parameter", http.StatusBadRequest)
		return
	}

	// Clear state cookie, as the authentication flow has finished
	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_state",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})

	if autherror != "" {
		slog.Error("RP OIDC error received", "error", autherror, "description", errorDescription)
		s.renderErrorPage(w, autherror, errorDescription)
		return
	}

	var oauth2Token *oauth2.Token
	var idToken *oidc.IDToken
	var tokens map[string]any

	ctx := r.Context()

	oauth2Token, err = s.oauth2Config.Exchange(ctx, code)
	if err != nil {
		slog.Error("RP token exchange error received", "error", autherror, "description", errorDescription)
		s.renderErrorPage(w, autherror, errorDescription)
		return
	}

	// Extract the ID Token from OAuth2 token.
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		// handle missing token
	}

	// Parse and verify ID Token payload.
	idToken, err = s.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		slog.Error("RP verifying the ID token error received", "error", autherror, "description", errorDescription)
		s.renderErrorPage(w, autherror, errorDescription)
		return
	}

	// Extract custom claims
	var claims models.ELSI_IDTokenClaims
	if err := idToken.Claims(&claims); err != nil {
		slog.Error("RP extract custom claims error received", "error", autherror, "description", errorDescription)
		s.renderErrorPage(w, autherror, errorDescription)
		return
	}

	tokens = map[string]any{
		"access_token": oauth2Token.AccessToken,
		"id_token":     rawIDToken,
		"token_type":   oauth2Token.Type(),
		"expires_in":   oauth2Token.ExpiresIn,
		"scope":        "",
	}

	// Create user session
	session := s.createSession(tokens)

	// Set session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "rp_session",
		Value:    session.SessionID,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   3600, // 1 hour
	})

	// Redirect to home page
	http.Redirect(w, r, "/", http.StatusFound)
}

// handleLogout handles user logout
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	// Clear session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "rp_session",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})

	// Redirect to home page
	http.Redirect(w, r, "/", http.StatusFound)
}

// Helper methods

func (s *Server) generateRandomString(length int) string {
	bytes := make([]byte, length)
	rand.Read(bytes)
	return base64.URLEncoding.EncodeToString(bytes)
}

func (s *Server) getSessionID(r *http.Request) string {
	cookie, err := r.Cookie("rp_session")
	if err != nil {
		return ""
	}
	return cookie.Value
}

func (s *Server) getSession(sessionID string) *models.RPSession {
	s.sessionsMutex.RLock()
	defer s.sessionsMutex.RUnlock()

	session, exists := s.sessions[sessionID]
	if !exists {
		return nil
	}

	// Check if session is expired (1 hour)
	if time.Since(session.LastAccessed) > time.Hour {
		delete(s.sessions, sessionID)
		return nil
	}

	// Update last accessed time
	session.LastAccessed = time.Now()
	return session
}

func (s *Server) createSession(tokens map[string]any) *models.RPSession {
	sessionID := s.generateRandomString(32)

	// Extract user info from tokens
	var userID string
	if sub, ok := tokens["sub"].(string); ok {
		userID = sub
	} else {
		userID = "unknown"
	}

	session := &models.RPSession{
		SessionID:    sessionID,
		UserID:       userID,
		AccessToken:  tokens["access_token"].(string),
		IDToken:      tokens["id_token"].(string),
		CreatedAt:    time.Now(),
		LastAccessed: time.Now(),
	}

	token, _, err := jwt.NewParser().ParseUnverified(session.IDToken, jwt.MapClaims{})
	if err != nil {
		slog.Error("Failed to parse ID token", "error", err)
		return nil
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		slog.Error("Failed to parse ID token", "error", err)
		return nil
	}

	session.IDTokenClaims = claims

	out, _ := json.MarshalIndent(claims, "", "  ")
	fmt.Println("ID token claims", string(out))

	s.sessionsMutex.Lock()
	s.sessions[sessionID] = session
	s.sessionsMutex.Unlock()

	return session
}

// HTML rendering methods

// renderLoginPage renders the login page, when there is no session yet
func (s *Server) renderLoginPage(w http.ResponseWriter) {

	s.html.Render(w, "login", nil)

}

// renderWelcomePage renders the welcome page, displaying the certificate information
func (s *Server) renderWelcomePage(w http.ResponseWriter, session *models.RPSession) {

	var idTokenClaims models.ELSI_IDTokenClaims
	token, _, err := jwt.NewParser().ParseUnverified(session.IDToken, &idTokenClaims)
	if err != nil {
		slog.Error("Failed to parse ID token", "error", err)
		return
	}

	_ = token

	fmt.Printf("ID token claims: %+v\n", idTokenClaims)

	certInfo := map[string]string{
		"organization":     idTokenClaims.Organization,
		"organization_id":  idTokenClaims.OrganizationIdentifier,
		"common_name":      idTokenClaims.Name,
		"email":            idTokenClaims.Email,
		"country":          idTokenClaims.Country,
		"locality":         idTokenClaims.Locality,
		"province":         idTokenClaims.Province,
		"certificate_type": idTokenClaims.CertificateType,
		"valid_from":       time.Unix(idTokenClaims.IssuedAt, 0).Format("2006-01-02 15:04:05"),
		"valid_to":         time.Unix(idTokenClaims.Expiration, 0).Format("2006-01-02 15:04:05"),
	}

	idTokenClaims.ValidFromStr = time.Unix(idTokenClaims.ValidFrom, 0).Format("2006-01-02 15:04:05")
	idTokenClaims.ValidToStr = time.Unix(idTokenClaims.ValidTo, 0).Format("2006-01-02 15:04:05")

	data := map[string]any{
		"session":  session,
		"certInfo": certInfo,
		"subject":  idTokenClaims,
	}

	s.html.Render(w, "welcome", data)

}

// renderErrorPage renders the error page
func (s *Server) renderErrorPage(w http.ResponseWriter, error, description string) {

	data := map[string]any{
		"error":       error,
		"description": description,
	}

	s.html.Render(w, "error", data)

}
