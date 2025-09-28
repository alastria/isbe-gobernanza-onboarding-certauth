package certauth

import (
	"embed"
	"log/slog"
	"time"

	"github.com/evidenceledger/certauth/internal/cache"
	"github.com/evidenceledger/certauth/internal/certconfig"
	"github.com/evidenceledger/certauth/internal/database"
	"github.com/evidenceledger/certauth/internal/html"
	"github.com/evidenceledger/certauth/internal/jwt"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/basicauth"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/favicon"
	"github.com/gofiber/fiber/v2/middleware/helmet"
	"github.com/gofiber/fiber/v2/middleware/limiter"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
)

// Server represents the CertAuth OpenID Provider server
type Server struct {
	cfg        certconfig.Config
	app        *fiber.App
	db         *database.Database
	jwtService *jwt.Service
	html       *html.RendererFiber
	cache      *cache.Cache
}

const templateDebug = true

//go:embed views/*
var viewsfs embed.FS

// New creates a new CertAuth server
func New(db *database.Database, cache *cache.Cache, adminPassword string, cfg certconfig.Config) *Server {

	// The engine to display the screens (HTML) to the users
	htmlrender, err := html.NewRendererFiber(templateDebug, viewsfs, "internal/certauth/views")
	if err != nil {
		slog.Error("Failed to initialize template engine", "error", err)
		panic(err)
	}

	app := fiber.New(fiber.Config{
		AppName:                 "CertAuth OP",
		ServerHeader:            "CertAuth",
		EnableTrustedProxyCheck: false,
		ReadTimeout:             30 * time.Second,
		WriteTimeout:            30 * time.Second,
	})

	// Recovers from panics anywhere in the stack chain and handles the control to the centralized ErrorHandler
	app.Use(recover.New())

	// Helmet middleware helps secure your apps by setting various HTTP headers.
	app.Use(helmet.New())

	// Ignores favicon requests
	app.Use(favicon.New())

	// Logs HTTP request/response details
	app.Use(logger.New())

	// Enable CORS for all origins
	app.Use(cors.New())

	// Limit repeat requests to our APIs
	app.Use(limiter.New(limiter.Config{
		Max:        20,
		Expiration: 5 * time.Minute,
	}))

	// Initialize JWT service
	jwtService, err := jwt.NewService(cfg.CertAuthURL)
	if err != nil {
		slog.Error("Failed to initialize JWT service", "error", err)
		panic(err)
	}

	s := &Server{
		app:        app,
		db:         db,
		jwtService: jwtService,
		html:       htmlrender,
		cache:      cache,
		cfg:        cfg,
	}

	// Health check
	s.app.Get("/health", func(c *fiber.Ctx) error {
		slog.Info("Health check", "from", c.Hostname())
		return c.JSON(fiber.Map{"status": "healthy", "hostname": c.Hostname()})
	})

	// OIDC Discovery endpoints
	s.app.Get(oidc_configuration, s.handleDiscovery)
	s.app.Get(jwks_uri, s.handleJWKS)

	// OIDC endpoints
	s.app.Get(authorization_endpoint, s.Authorization)
	s.app.Post(token_endpoint, s.handleTokenExchange)
	s.app.Get(userinfo_endpoint, s.UserInfo)
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

	// Protect the admin area with basic auth
	adminAuth := basicauth.New(basicauth.Config{
		Users: map[string]string{
			"admin": adminPassword,
		},
		Realm: "Admin Area",
	})

	admin.Use(adminAuth)

	admin.Get("/admin", s.AdminDashboard)

	admin.Get("/rp", s.ListRP)
	admin.Post("/rp", s.CreateRP)
	admin.Put("/rp/:id", s.UpdateRP)
	admin.Delete("/rp/:id", s.DeleteRP)

	return s
}
