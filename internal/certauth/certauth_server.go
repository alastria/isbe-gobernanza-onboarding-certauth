package certauth

import (
	"context"
	"embed"
	"fmt"
	"log/slog"
	"math/rand"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/evidenceledger/certauth/internal/cache"
	"github.com/evidenceledger/certauth/internal/certconfig"
	"github.com/evidenceledger/certauth/internal/database"
	"github.com/evidenceledger/certauth/internal/html"
	"github.com/evidenceledger/certauth/internal/jwt"
	"github.com/evidenceledger/certauth/internal/middleware"
	"github.com/evidenceledger/certauth/internal/models"
	"github.com/evidenceledger/certauth/internal/util/x509util"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/gofiber/fiber/v2/utils"
	jwtV5 "github.com/golang-jwt/jwt/v5"
)

// Server represents the CertAuth OpenID Provider server
type Server struct {
	cfg        certconfig.Config
	app        *fiber.App
	db         *database.Database
	adminPW    string
	adminAuth  *middleware.AdminAuth
	jwtService *jwt.Service
	html       *html.RendererFiber
	cache      *cache.Cache
}

const templateDebug = true

//go:embed views/*
var viewsfs embed.FS

// New creates a new CertAuth server
func New(db *database.Database, cache *cache.Cache, adminPassword string, cfg certconfig.Config) *Server {

	htmlrender, err := html.NewRendererFiber(templateDebug, viewsfs, "internal/certauth/views")
	if err != nil {
		slog.Error("Failed to initialize template engine", "error", err)
		panic(err)
	}

	app := fiber.New(fiber.Config{
		AppName:                 "CertAuth OP",
		EnableTrustedProxyCheck: false,
		ReadTimeout:             30 * time.Second,
		WriteTimeout:            30 * time.Second,
	})

	// Middleware
	app.Use(recover.New())
	app.Use(logger.New())
	app.Use(cors.New())

	// Initialize JWT service
	jwtService, err := jwt.NewService(cfg.CertAuthURL)
	if err != nil {
		slog.Error("Failed to initialize JWT service", "error", err)
		panic(err)
	}

	adminAuth := middleware.NewAdminAuth(adminPassword)

	s := &Server{
		app:        app,
		db:         db,
		adminPW:    adminPassword,
		adminAuth:  adminAuth,
		jwtService: jwtService,
		html:       htmlrender,
		cache:      cache,
		cfg:        cfg,
	}

	s.setupRoutes()
	return s
}

// setupRoutes sets up all the server routes
func (s *Server) setupRoutes() {
	// Health check
	s.app.Get("/health", func(c *fiber.Ctx) error {
		slog.Info("Health check", "from", c.Hostname())
		return c.JSON(fiber.Map{"status": "healthy", "hostname": c.Hostname()})
	})

	// OIDC Discovery endpoints
	s.app.Get("/.well-known/openid-configuration", s.handleDiscovery)
	s.app.Get("/.well-known/jwks.json", s.handleJWKS)

	// OIDC endpoints
	s.app.Get("/oauth2/auth", s.Authorization)
	s.app.Post("/oauth2/token", s.Token)
	s.app.Get("/oauth2/userinfo", s.UserInfo)
	s.app.Get("/logout", s.Logout)

	// Certificate selection screen - shows before redirecting to CertSec
	s.app.Get("/certificate-select", s.handleCertificateSelect)

	// Certificate consent screen - shows after redirecting from CertSec
	s.app.Get("/certificate-back", s.handleCertificateReceive)

	// Email verification form submission
	s.app.Post("/request-email-verification", s.handleRequestEmailVerification)

	// Email verification code verification
	s.app.Post("/verify-email-code", s.handleVerifyEmailCode)

	// Handle consent received, generation of SSO cookie and redirection to Relying Party
	s.app.Post("/consent", s.handleConsent)

	// Test callback endpoint for testing the complete flow
	s.app.Get("/callback", s.handleTestCallback)

	// Test endpoints for JWT token generation
	s.app.Post("/test/token", s.handleTestToken)
	s.app.Post("/test/token/personal", s.handleTestPersonalToken)
	s.app.Get("/test/callback", s.handleTestCallback)

	// Admin routes (protected)
	admin := s.app.Group("/admin")
	admin.Use(s.adminAuth.AuthMiddleware())

	admin.Get("/rp", s.ListRP)
	admin.Post("/rp", s.CreateRP)
	admin.Put("/rp/:id", s.UpdateRP)
	admin.Delete("/rp/:id", s.DeleteRP)
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

	// Retrieve the AuthorizationRequest associated with the authCode
	authCodeObj, err := s.db.GetAuthCode(authCode)
	if err != nil {
		slog.Error("Failed to retrieve authorization code from DB", "error", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Internal server error",
		})
	}
	if authCodeObj == nil {
		slog.Error("Authorization code not found in DB", "auth_code", authCode)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid authorization code",
		})
	}

	// Retrieve the entry from the cache
	certDataAny, ok := s.cache.Get(authCode)
	if !ok {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Authorization code not found",
		})
	}

	certData, ok := certDataAny.(*models.CertificateData)
	if !ok {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid certificate data",
		})
	}

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
	testAuthCode := &models.AuthCode{
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

	// Retrieve the certificate data from cache
	certDataAny, ok := s.cache.Get(authCode)
	if !ok {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Certificate data not found",
		})
	}

	certData, ok := certDataAny.(*models.CertificateData)
	if !ok {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid certificate data",
		})
	}

	// Generate a random 6-digit verification code
	verificationCode := generateRandomCode()

	// For testing purposes, we'll store the code in the cache
	// In production, this would be sent via email
	s.cache.Set(authCode+"_email", email, 10*time.Minute)
	s.cache.Set(authCode+"_code", verificationCode, 10*time.Minute)

	slog.Info("Verification code generated", "code", verificationCode, "auth_code", authCode)

	// Render the confirm_email template
	return s.html.Render(c, "3_confirm_email", fiber.Map{
		"email":            email,
		"authCode":         authCode,
		"verificationCode": verificationCode, // For testing - remove in production
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
	code := rand.Intn(900000) + 100000 // 100000 to 999999
	return fmt.Sprintf("%06d", code)
}

// handleVerifyEmailCode handles the email verification code verification
func (s *Server) handleVerifyEmailCode(c *fiber.Ctx) error {
	// Get form data
	verificationCode := utils.CopyString(c.FormValue("verification_code"))
	authCode := utils.CopyString(c.FormValue("auth_code"))
	email := utils.CopyString(c.FormValue("email"))

	if verificationCode == "" || authCode == "" || email == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Missing verification code, authorization code, or email",
		})
	}

	slog.Info("Email verification code verification requested", "email", email, "auth_code", authCode)

	// Retrieve the stored verification code from cache
	storedCodeAny, ok := s.cache.Get(authCode + "_code")
	if !ok {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Verification code expired or not found",
		})
	}

	storedCode, ok := storedCodeAny.(string)
	if !ok {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid stored verification code",
		})
	}

	// Verify the code
	if verificationCode != storedCode {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid verification code",
		})
	}

	slog.Info("Email verification code verified successfully", "email", email, "auth_code", authCode)

	// Retrieve the stored email from cache
	storedEmailAny, ok := s.cache.Get(authCode + "_email")
	if !ok {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Email not found in cache",
		})
	}

	storedEmail, ok := storedEmailAny.(string)
	if !ok {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid stored email",
		})
	}
	slog.Debug("Stored email", "email", storedEmail)

	// Retrieve the AuthorizationRequest associated with the authCode
	authCodeObj, err := s.db.GetAuthCode(authCode)
	if err != nil {
		slog.Error("Failed to retrieve authorization code from DB", "error", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Internal server error",
		})
	}
	if authCodeObj == nil {
		slog.Error("Authorization code not found in DB", "auth_code", authCode)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid authorization code",
		})
	}

	// Retrieve the certificate data from cache
	certDataAny, ok := s.cache.Get(authCode)
	if !ok {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Certificate data not found",
		})
	}

	certData, ok := certDataAny.(*models.CertificateData)
	if !ok {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid certificate data",
		})
	}

	// Update the email field in the certificate data
	certData.Subject.EmailAddress = storedEmail

	// And store it again in the cache
	s.cache.Set(authCode, certData, 10*time.Minute)

	// Store the verified email in cache for the final consent screen
	s.cache.Set(authCode+"_verified_email", storedEmail, 10*time.Minute)

	// Render the certificate consent template
	return s.html.Render(c, "4_request_certificate_consent", fiber.Map{
		"authCode":    authCode,
		"authCodeObj": authCodeObj,
		"certType":    certData.CertificateType,
		"subject":     certData.Subject,
		"email":       storedEmail,
	})
}

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

	// Retrieve the stored email from cache
	storedEmailAny, ok := s.cache.Get(authCode + "_email")
	if !ok {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Email not found in cache",
		})
	}

	storedEmail, ok := storedEmailAny.(string)
	if !ok {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid stored email",
		})
	}
	slog.Debug("Stored email", "email", storedEmail)

	// Retrieve the AuthorizationRequest associated with the authCode
	authCodeObj, err := s.db.GetAuthCode(authCode)
	if err != nil {
		slog.Error("Failed to retrieve authorization code from DB", "error", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Internal server error",
		})
	}
	if authCodeObj == nil {
		slog.Error("Authorization code not found in DB", "auth_code", authCode)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid authorization code",
		})
	}

	// Generate SSO cookie
	ssoCookie, err := s.generateSSOCookie(authCode)
	if err != nil {
		slog.Error("failed to generate sso cookie", "error", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Internal server error",
		})
	}

	// Set cookie
	c.Cookie(ssoCookie)

	// Redirect (302) to RP with auth code
	slog.Info("User consent processed successfully", "email", email, "auth_code", authCode)
	// href="{{ .authCodeObj.RedirectURI }}?code={{ .authCode }}&state={{ .authCodeObj.State }}"
	redirectURL := fmt.Sprintf("%s?code=%s", authCodeObj.RedirectURI, authCode)
	if authCodeObj.State != "" {
		redirectURL += fmt.Sprintf("&state=%s", authCodeObj.State)
	}

	return c.Redirect(redirectURL, fiber.StatusFound)

	// // Render the certificate consent template
	// return s.html.Render(c, "4_request_certificate_consent", fiber.Map{
	// 	"authCode":    authCode,
	// 	"authCodeObj": authCodeObj,
	// 	"certType":    certData.CertificateType,
	// 	"subject":     certData.Subject,
	// 	"email":       storedEmail,
	// })
}

// generateSSOCookie generates the SSO cookie
func (s *Server) generateSSOCookie(authCode string) (*fiber.Cookie, error) {
	// Retrieve the certificate data from cache
	certDataAny, ok := s.cache.Get(authCode)
	if !ok {
		return nil, fmt.Errorf("certificate data not found for auth code: %s", authCode)
	}

	certData, ok := certDataAny.(*models.CertificateData)
	if !ok {
		return nil, fmt.Errorf("invalid certificate data for auth code: %s", authCode)
	}

	// Determine the sub identifier based on certificate type
	var sub string
	if certData.Subject.OrganizationIdentifier != "" {
		sub = certData.Subject.OrganizationIdentifier
	} else {
		// For personal certificates, use serial number or generate a unique identifier
		if certData.Subject.SerialNumber != "" {
			sub = certData.Subject.SerialNumber
		} else if certData.Subject.CommonName != "" {
			sub = certData.Subject.CommonName + "_" + certData.Subject.SerialNumber
		} else {
			// Fallback: generate a hash based on certificate data
			sub = fmt.Sprintf("%s_%s_%s",
				certData.Subject.GivenName,
				certData.Subject.Surname,
				certData.Subject.SerialNumber)
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
	}

	// Generate the token
	token, err := s.jwtService.GenerateSSOCookieToken(claims)
	if err != nil {
		return nil, fmt.Errorf("failed to generate sso token: %w", err)
	}

	// Generate SSO cookie
	cookie := new(fiber.Cookie)
	cookie.Name = "sso.isbe"
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
