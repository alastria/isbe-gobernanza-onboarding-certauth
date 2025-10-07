package onboardserver

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/evidenceledger/certauth/internal/cache"
	"github.com/evidenceledger/certauth/internal/certauth"
	"github.com/evidenceledger/certauth/internal/certconfig"
	"github.com/evidenceledger/certauth/internal/certsec"
	"github.com/evidenceledger/certauth/internal/database"
	onboard "github.com/evidenceledger/certauth/internal/onboard"
)

// Config is the configuration for the server
type Config struct {
	Development  bool
	CertAuthPort string
	CertAuthURL  string
	CertSecPort  string
	CertSecURL   string
	OnboardPort  string
	OnboardURL   string
}

// Server manages both CertAuth and CertSec servers
type Server struct {
	cfg       Config
	certauth  *certauth.Server
	certsec   *certsec.Server
	examplerp *onboard.Server
	db        *database.Database
	adminPW   string
}

// New creates a new server instance
func New(adminPassword string, cfg Config) *Server {

	// Create a global cache with expiration time of 10 minutes
	cache := cache.New(10 * time.Minute)

	// Initialize database
	db := database.New()

	// Create the authentication and authorization servers.
	// They share the same database and cache.

	certCfg := certconfig.Config{
		Development:  cfg.Development,
		CertAuthURL:  cfg.CertAuthURL,
		CertAuthPort: cfg.CertAuthPort,
		CertSecURL:   cfg.CertSecURL,
		CertSecPort:  cfg.CertSecPort,
	}

	ca := certauth.New(db, cache, adminPassword, certCfg)
	cs := certsec.New(db, cache, certCfg)

	// Create the example RP server.
	// It uses the CertAuth server as the OP.

	clientid := "isbeonboard"
	clientsecret := "isbesecret"
	if cfg.Development {
		clientid = "testonboard"
		clientsecret = "isbesecret"
	}
	erp := onboard.New(cfg.OnboardPort, cfg.OnboardURL, cfg.CertAuthURL, clientid, clientsecret)

	return &Server{
		certauth:  ca,
		certsec:   cs,
		examplerp: erp,
		db:        db,
		adminPW:   adminPassword,
		cfg:       cfg,
	}

}

// Start starts both servers: CertAuth and CertSec. Also it starts (for the moment) the demo RP server
func (s *Server) Start(ctx context.Context) error {
	// Initialize database
	if err := s.db.Initialize(); err != nil {
		return fmt.Errorf("failed to initialize database: %w", err)
	}

	var wg sync.WaitGroup
	errChan := make(chan error, 3)

	// Start CertAuth server (port 8090)
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := s.certauth.Start(ctx); err != nil {
			errChan <- fmt.Errorf("certauth server failed: %w", err)
		}
	}()

	// Start CertSec server (port 8091)
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := s.certsec.Start(ctx); err != nil {
			errChan <- fmt.Errorf("certsec server failed: %w", err)
		}
	}()

	// Start Example RP server (port 8092)
	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(2 * time.Second)
		if err := s.examplerp.Start(); err != nil {
			errChan <- fmt.Errorf("example rp server failed: %w", err)
		}
	}()

	slog.Info("Servers started",
		"certauth_port", s.cfg.CertAuthPort,
		"certsec_port", s.cfg.CertSecPort,
		"examplerp_port", s.cfg.OnboardPort,
		"certauth_domain", s.cfg.CertAuthURL,
		"certsec_domain", s.cfg.CertSecURL,
		"examplerp_url", s.cfg.OnboardURL)

	// Wait for either server to fail or context to be cancelled
	select {
	case err := <-errChan:
		return err
	case <-ctx.Done():
		slog.Info("Shutting down servers")
		s.db.Close()
		return nil
	}
}
