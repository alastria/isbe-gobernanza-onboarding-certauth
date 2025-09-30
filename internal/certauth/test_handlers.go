package certauth

import (
	"log/slog"
	"time"

	"github.com/evidenceledger/certauth/internal/models"
	"github.com/evidenceledger/certauth/internal/util/x509util"
	"github.com/gofiber/fiber/v2"
)

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
