package certsec

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"

	"github.com/evidenceledger/certauth/internal/cache"
	"github.com/evidenceledger/certauth/internal/certconfig"
	"github.com/evidenceledger/certauth/internal/database"
	"github.com/evidenceledger/certauth/internal/errl"
	"github.com/evidenceledger/certauth/internal/html"
	"github.com/evidenceledger/certauth/internal/models"
	"github.com/evidenceledger/certauth/internal/tmfservice"
	"github.com/evidenceledger/certauth/internal/util/x509util"
)

// Server represents the CertSec certificate authentication server
type Server struct {
	app        *fiber.App
	db         *database.Database
	cache      *cache.Cache
	cfg        certconfig.Config
	htmlRender *html.RendererFiber
	tmfClient  *tmfservice.TMFClient
}

//go:embed views/*
var viewsfs embed.FS

// New creates a new CertSec server.
// This is a minimal server which requests a client certificate to the client browser.
// It is invoked from the CertAuth server, which is the main OpenID Provider
// supporting eIDAS certificates and Verifiable Credentials.
// The CerSec server requires a reverse proxy (like Caddy or Nginx) in front, terminating the TLS connection
// and configured to actually requesting the client certificate.
func New(db *database.Database, cache *cache.Cache, cfg certconfig.Config) *Server {

	// The engine to display the screens HTML screens to the users
	htmlrender, err := html.NewRendererFiber(cfg.Development, viewsfs, "internal/certsec/views", ".hbs")
	if err != nil {
		slog.Error("Failed to initialize template engine", "error", err)
		panic(err)
	}

	app := fiber.New(fiber.Config{
		AppName: "CertSec Certificate Authentication",
	})

	app.Use(recover.New())
	app.Use(logger.New())

	app.Static("/static", "./internal/certsec/views/assets")

	s := &Server{
		app:        app,
		db:         db,
		cache:      cache,
		cfg:        cfg,
		htmlRender: htmlrender,
	}

	tmfClient, err := tmfservice.NewClient(&tmfservice.TMFClientConfig{
		BaseURL: "https://tmf.evidenceledger.eu",
		Timeout: 30,
	})
	if err != nil {
		slog.Error("Failed to initialize TMF client", "error", err)
		panic(err)
	}
	s.tmfClient = tmfClient

	s.app.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "healthy"})
	})

	// Certificate authentication endpoint
	s.app.Get("/auth", s.handleCertificateAuth)

	// Register admin pages
	s.app.Get("/admin", s.adminPages)
	s.app.Get("/admin/:page", s.adminPages)
	s.app.Post("/admin/:page", s.adminPages)

	return s
}

type RelyingPartyCUDRequest struct {
	ID           int    `form:"id"`
	Action       string `form:"action"`
	Name         string `form:"name"`
	Description  string `form:"description"`
	ClientID     string `form:"client_id"`
	ClientSecret string `form:"client_secret"`
	RedirectURL  string `form:"redirect_url"`
	OriginURL    string `form:"origin_url"`
	Scopes       string `form:"scopes"`
}

// adminPages handles the admin pages
func (s *Server) adminPages(c *fiber.Ctx) error {

	subject, err := s.checkAuthentication(c)
	if err != nil {
		return s.htmlRender.Render(c, "error", fiber.Map{
			"message": err.Error(),
		})
	}

	// Get the page from the path parameter
	page := c.Params("page")

	// Switch based on the page
	switch page {
	case "", "relyingparties":
		return s.relyingpartiesPage(c, subject)
	case "organizations":
		return s.organizationsPage(c, subject)
	default:
		return s.htmlRender.Render(c, "error", fiber.Map{
			"message": "Invalid page: " + page,
		})
	}

}

func (s *Server) relyingpartiesPage(c *fiber.Ctx, subject *x509util.ELSIName) error {

	switch c.Method() {
	case "GET":

		// Retrieve the Relying Parties from the database
		rps, err := s.db.ListRelyingParties()
		if err != nil {
			return s.htmlRender.Render(c, "error", fiber.Map{
				"message": "Failed to retrieve relying parties: " + err.Error(),
			})
		}

		return s.htmlRender.Render(c, "relyingparties", fiber.Map{
			"rps":     rps,
			"subject": subject,
		})

	case "POST":

		var request RelyingPartyCUDRequest
		if err := c.BodyParser(&request); err != nil {
			return c.Status(fiber.StatusBadRequest).SendString("Invalid request")
		}

		// Create the object
		rp := models.RelyingParty{
			ID:          request.ID,
			Name:        request.Name,
			Description: request.Description,
			ClientID:    request.ClientID,
			RedirectURL: request.RedirectURL,
			OriginURL:   request.OriginURL,
			Scopes:      request.Scopes,
		}

		switch request.Action {
		case "create":
			if err := s.db.CreateRelyingParty(&rp, request.ClientSecret); err != nil {
				return s.htmlRender.Render(c, "error", fiber.Map{
					"message": "Failed to create relying party: " + err.Error(),
				})
			}
		case "update":
			if err := s.db.UpdateRelyingParty(&rp, request.ClientSecret); err != nil {
				return s.htmlRender.Render(c, "error", fiber.Map{
					"message": "Failed to update relying party: " + err.Error(),
				})
			}
		case "delete":
			if err := s.db.DeleteRelyingParty(request.ID); err != nil {
				return s.htmlRender.Render(c, "error", fiber.Map{
					"message": "Failed to delete relying party: " + err.Error(),
				})
			}
		}

		return c.Redirect("/admin/relyingparties")

	default:
		return s.htmlRender.Render(c, "error", fiber.Map{
			"message": "Invalid action: " + c.Method(),
		})
	}

}

func (s *Server) organizationsPage(c *fiber.Ctx, subject *x509util.ELSIName) error {

	orgsPath := "/tmf-api/party/v4/organization"

	switch c.Method() {
	case "GET":

		// Retrieve the TMF Organization objects
		orgs, err := s.tmfClient.GetList(orgsPath, nil)
		if err != nil {
			return s.htmlRender.Render(c, "error", fiber.Map{
				"message": "Failed to retrieve organizations: " + err.Error(),
			})
		}

		out, err := json.MarshalIndent(orgs, "", "  ")
		if err != nil {
			return s.htmlRender.Render(c, "error", fiber.Map{
				"message": "Failed to marshal organizations: " + err.Error(),
			})
		}

		return s.htmlRender.Render(c, "organizations", fiber.Map{
			"File":    string(out),
			"subject": subject,
		})

	default:
		return s.htmlRender.Render(c, "error", fiber.Map{
			"message": "Invalid action: " + c.Method(),
		})
	}

}

func (s *Server) checkAuthentication(c *fiber.Ctx) (*x509util.ELSIName, error) {
	// Get the certificate from the TLS connection
	certHeader := c.Get("tls-client-certificate")
	if certHeader == "" {
		return nil, errl.Errorf("No certificate provided")
	}

	// Parse the certificate
	cert, _, subject, err := x509util.ParseEIDASCertB64Der(certHeader)
	if err != nil {
		return nil, errl.Errorf("Failed to parse certificate: %w", err)
	}

	// Check for the serial number
	if subject.SerialNumber != "IDCES-21442837Y" && subject.SerialNumber != "IDCES-12345678V" {
		return nil, errl.Errorf("Certificate serial number is invalid")
	}

	// For testing we accept personal certificates, but we do not accept that both
	// the organizationIdentifier and the serialNumber are empty.
	if subject.OrganizationIdentifier == "" && subject.SerialNumber == "" {
		return nil, errl.Errorf("Both organizationIdentifier and serialNumber are empty")
	}

	// Check certificate expiration
	now := time.Now()
	if now.Before(cert.NotBefore) {
		return nil, errl.Errorf("Certificate not yet valid, not_before: %s", cert.NotBefore.Format(time.RFC3339))
	}
	if now.After(cert.NotAfter) {
		return nil, errl.Errorf("Certificate expired not_after: %s", cert.NotAfter.Format(time.RFC3339))
	}

	return subject, nil
}

// handleCertificateAuth handles the certificate authentication endpoint.
// This endpoint receives the certificate from the browser and sends it to the CertAuth server
// via the global cache. Both CertAuth and CerSec must be running in the same process.
func (s *Server) handleCertificateAuth(c *fiber.Ctx) error {
	// Get auth code from query parameter
	authCode := c.Query("code")
	if authCode == "" {
		slog.Error("missing authorization code")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Missing authorization code",
		})
	}

	// Retrieve the AuthorizationRequest associated with the authCode from the cache
	// to ensure the auth code is valid and was recently issued
	authReqInterface, found := s.cache.Get(authCode)
	if !found {
		slog.Error("Authorization code not found in cache", "auth_code", authCode)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid or expired authorization code",
		})
	}

	authProcess, ok := authReqInterface.(*models.AuthProcess)
	if !ok {
		slog.Error("Invalid type for AuthorizationRequest in cache", "auth_code", authCode)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Internal server error",
		})
	}

	slog.Info("Certificate authentication requested", "auth_code", authCode)

	sendBackError := func(err error) error {
		// Redirect back to certauth with an error
		authProcess.ErrorInProcess = err
		redirectURL := s.cfg.CertAuthURL + "/certificate-back?code=" + authCode + "&error=true"
		return c.Status(fiber.StatusFound).Redirect(redirectURL)
	}

	// Get the certificate from the TLS connection
	certHeader := c.Get("tls-client-certificate")
	if certHeader == "" {
		return sendBackError(errl.Errorf("No certificate provided"))
	}

	slog.Info("Certificate received", "auth_code", authCode, "cert_length", len(certHeader))

	// Parse the certificate
	cert, issuer, subject, err := x509util.ParseEIDASCertB64Der(certHeader)
	if err != nil {
		return sendBackError(errl.Errorf("Failed to parse certificate: %w", err))
	}

	// For testing we accept personal certificates, but we do not accept that both
	// the organizationIdentifier and the serialNumber are empty.
	if subject.OrganizationIdentifier == "" && subject.SerialNumber == "" {
		return sendBackError(errl.Errorf("Both organizationIdentifier and serialNumber are empty"))
	}

	// Check certificate expiration
	now := time.Now()
	if now.Before(cert.NotBefore) {
		return sendBackError(errl.Errorf("Certificate not yet valid, not_before: %s", cert.NotBefore.Format(time.RFC3339)))
	}
	if now.After(cert.NotAfter) {
		return sendBackError(errl.Errorf("Certificate expired not_after: %s", cert.NotAfter.Format(time.RFC3339)))
	}

	// Determine certificate type
	certType := "personal"
	if subject.OrganizationIdentifier != "" {
		certType = "organizational"
	}

	// Log successful processing (Info level with organizational data only)
	logFields := []any{
		"auth_code", authCode,
		"certificate_type", certType,
		"valid_from", cert.NotBefore,
		"valid_to", cert.NotAfter,
	}

	// Only log organizational fields for privacy (exclude personal identifiers)
	if subject.Organization != "" {
		logFields = append(logFields, "organization", subject.Organization)
	}
	if subject.OrganizationIdentifier != "" {
		logFields = append(logFields, "organization_identifier", subject.OrganizationIdentifier)
	}
	if subject.SerialNumber != "" {
		logFields = append(logFields, "serial_number", "************")
	}
	if subject.Country != "" {
		logFields = append(logFields, "country", subject.Country)
	}

	slog.Info("Certificate processed successfully", logFields...)

	// Create the CertificateData struct
	certData := &models.CertificateData{
		Subject:         subject,
		Issuer:          issuer,
		ValidFrom:       cert.NotBefore,
		ValidTo:         cert.NotAfter,
		OrganizationID:  subject.OrganizationIdentifier,
		CertificateType: certType,
		Certificate:     cert,
		CertificateDER:  certHeader,
	}

	// Set the certificate data in the auth request for later retrieval
	authProcess.CertificateData = certData

	// Redirect back to certauth
	redirectURL := s.cfg.CertAuthURL + "/certificate-back?code=" + authCode
	return c.Status(fiber.StatusFound).Redirect(redirectURL)

}

// Start starts the server
func (s *Server) Start(ctx context.Context) error {
	slog.Info("Starting CertSec server", "addr", s.cfg.CertSecPort)

	addr := net.JoinHostPort("0.0.0.0", s.cfg.CertSecPort)

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
