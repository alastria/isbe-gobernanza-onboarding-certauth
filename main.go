package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/evidenceledger/certauth/internal/mainserver"
)

var (
	development bool

	adminPassword string
	certauthPort  string
	certsecPort   string
	certauthURL   string
	certsecURL    string
	onboardURL    string
	onboardPort   string
)

func main() {
	// If we are in development environment or not
	flag.BoolVar(&development, "dev", false, "Development mode")

	// The password for admin screens
	flag.StringVar(&adminPassword, "admin-password", "", "Admin password for the server")

	// The URL and port for the CertAuth server, which is the OP url also
	flag.StringVar(&certauthPort, "certauth-port", "8090", "Port for the main OP server")
	flag.StringVar(&certauthURL, "certauth-url", "", "URL for the CertAuth server")

	// The URL and port for the CertSec server, the one asking for the certificate via TLS client authentication
	flag.StringVar(&certsecPort, "certsec-port", "8091", "Port for the CertSec server")
	flag.StringVar(&certsecURL, "certsec-url", "", "URL for the CertSec server")

	// The URL and port for the Onboard server, the example RP
	flag.StringVar(&onboardPort, "onboard-port", "8092", "Port for the Onboard server")
	flag.StringVar(&onboardURL, "onboard-url", "", "URL for the Onboard server")

	flag.Parse()

	// Initialize logging
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))
	slog.SetDefault(logger)

	// Say if we are in development or not
	if development {
		slog.Info("Running in development mode")
	}

	// Get admin password from command line (priority) or environment variable
	if adminPassword == "" {
		adminPassword = os.Getenv("CERTAUTH_ADMIN_PASSWORD")
		if adminPassword == "" {
			if development {
				adminPassword = "pepe"
			} else {
				slog.Error("Admin password required. Set CERTAUTH_ADMIN_PASSWORD environment variable")
				os.Exit(1)
			}
		}
	}

	if certauthURL == "" {
		certauthURL = os.Getenv("CERTAUTH_URL")
		if certauthURL == "" {
			certauthURL = "https://certauth.mycredential.eu"
		}
	}

	if certsecURL == "" {
		certsecURL = os.Getenv("CERTSEC_URL")
		if certsecURL == "" {
			certsecURL = "https://certsec.mycredential.eu"
		}
	}

	if onboardURL == "" {
		onboardURL = os.Getenv("ONBOARD_URL")
		if onboardURL == "" {
			onboardURL = "https://onboard.mycredential.eu"
		}
	}

	// Create the configuration
	cfg := mainserver.Config{
		Development:  development,
		CertAuthPort: certauthPort,
		CertAuthURL:  certauthURL,
		CertSecPort:  certsecPort,
		CertSecURL:   certsecURL,
		OnboardPort:  onboardPort,
		OnboardURL:   onboardURL,
	}

	// Create the main server. This will initialize the individual HTTP services and the database.
	srv := mainserver.New(adminPassword, cfg)

	// Setup graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		slog.Info("Shutdown signal received")
		cancel()
	}()

	// Start server
	if err := srv.Start(ctx); err != nil {
		slog.Error("Server failed", "error", err)
		os.Exit(1)
	}
}
