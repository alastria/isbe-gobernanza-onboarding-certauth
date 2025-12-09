package certauth

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/evidenceledger/certauth/internal/cache"
	"github.com/evidenceledger/certauth/internal/certconfig"
	"github.com/evidenceledger/certauth/internal/database"
	"github.com/evidenceledger/certauth/internal/html"
	"github.com/evidenceledger/certauth/internal/jwtservice"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/favicon"
	"github.com/gofiber/fiber/v2/middleware/helmet"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
)

// Server represents the CertAuth server
// It acts as an OpenID Provider with the Relying Parties, and as an OID4VP Relying Party for the Wallet.
// In this way it insulates the OID4VP protocol from the Relying Parties, which just use standard OIDC to
// authenticate users and get an ID Token and an Access Token.
type Server struct {
	cfg        certconfig.Config
	httpServer *fiber.App
	db         *database.Database
	jwtService *jwtservice.JWTService
	htmlRender *html.RendererFiber
	cache      *cache.Cache
}

const templateDebug = true

//go:embed views/*
var viewsfs embed.FS

// New creates a new CertAuth server
func New(db *database.Database, cache *cache.Cache, adminPassword string, cfg certconfig.Config) *Server {

	// The engine to display the screens HTML screens to the users
	htmlrender, err := html.NewRendererFiber(templateDebug, viewsfs, "internal/certauth/views", ".hbs")
	if err != nil {
		slog.Error("Failed to initialize template engine", "error", err)
		panic(err)
	}

	httpServer := fiber.New(fiber.Config{
		AppName:                 "CertAuth OP",
		ServerHeader:            "CertAuth",
		EnableTrustedProxyCheck: false,
		ReadTimeout:             30 * time.Second,
		WriteTimeout:            30 * time.Second,
	})

	// Recovers from panics anywhere in the stack chain and handles the control to the centralized ErrorHandler
	httpServer.Use(recover.New())

	// Helmet middleware helps secure your apps by setting various HTTP headers.
	httpServer.Use(helmet.New())

	// Ignores favicon requests
	httpServer.Use(favicon.New())

	// Logs HTTP request/response details
	httpServer.Use(logger.New())

	// Enable CORS for all origins
	httpServer.Use(cors.New())

	httpServer.Static("/static", "./internal/certauth/views/assets")

	// Initialize JWT service
	jwtService, err := jwtservice.New(cfg.CertAuthURL)
	if err != nil {
		slog.Error("Failed to initialize JWT service", "error", err)
		panic(err)
	}

	// Put everything together in a server
	s := &Server{
		httpServer: httpServer,
		db:         db,
		jwtService: jwtService,
		htmlRender: htmlrender,
		cache:      cache,
		cfg:        cfg,
	}

	// Register the health check endpoint
	s.httpServer.Get("/health", func(c *fiber.Ctx) error {
		slog.Info("Health check", "from", c.Hostname())
		return c.JSON(fiber.Map{"status": "healthy", "hostname": c.Hostname()})
	})

	// Register the OpenID Provider (OP) endpoints to support Relying Parties
	s.registerOIDCHandlers()

	// Register the endpoints for OIDVP with the Wallet
	s.registerWalletHandlers()

	// Register the eIDAS certificate endpoints to talk with CertSec (requesting the certificate from the browser)
	s.registerCertificateHandlers()

	// Register the admin endpoints (protected)
	s.registerAdminHandlers(adminPassword)

	return s
}

// Start starts the server
func (s *Server) Start(ctx context.Context) error {

	if s.httpServer == nil {
		return errors.New("server not initialized")
	}

	addr := net.JoinHostPort("0.0.0.0", s.cfg.CertAuthPort)
	slog.Info("Starting CertAuth server", "addr", addr)

	// Start server in goroutine
	errChan := make(chan error, 1)
	go func() {
		if err := s.httpServer.Listen(addr); err != nil {
			errChan <- fmt.Errorf("failed to start server: %w", err)
		}
	}()

	// Wait for context cancellation or error
	select {
	case err := <-errChan:
		return err
	case <-ctx.Done():
		return s.httpServer.Shutdown()
	}

}
