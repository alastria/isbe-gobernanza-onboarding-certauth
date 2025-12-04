package database

import (
	"fmt"
	"log/slog"

	"github.com/evidenceledger/certauth/internal/models"
)

// initializeTestData adds some test data if the database is empty
func (d *Database) initializeTestData() error {

	// Add the main Private Area as RP
	portalMainRP := &models.RelyingParty{
		Name:        "ISBE Main Private Area",
		Description: "The ISBE Main Private Area application",
		ClientID:    "https://idp.dev.cloud-w.envs.redisbe.com",
		RedirectURL: "https://idp.dev.cloud-w.envs.redisbe.com/auth/realms/dev-isbe/broker/certificado-representante/endpoint",
		OriginURL:   "https://idp.dev.cloud-w.envs.redisbe.com/",
		Scopes:      "openid eidas",
		TokenExpiry: 3600,
	}

	d.CreateRelyingParty(portalMainRP, "isbesecret")

	// Add Private Area as RP
	portalRP := &models.RelyingParty{
		Name:        "ISBE Private Area",
		Description: "The ISBE Private Area application",
		ClientID:    "https://idp-isbe.digitelts.com",
		RedirectURL: "https://idp-isbe.digitelts.com/realms/portal/broker/certificates-idp/endpoint",
		OriginURL:   "https://idp-isbe.digitelts.com/",
		Scopes:      "openid eidas",
		TokenExpiry: 3600,
	}

	d.CreateRelyingParty(portalRP, "isbesecret")

	// Add Catalog as RP
	catalogRP := &models.RelyingParty{
		Name:        "ISBE Catalog",
		Description: "The ISBE Catalog application",
		ClientID:    "https://catalog.isbeonboard.com",
		RedirectURL: "https://isbecatalog.netlify.app/",
		OriginURL:   "https://isbecatalog.netlify.app/",
		Scopes:      "openid eidas",
		TokenExpiry: 3600,
	}

	d.CreateRelyingParty(catalogRP, "isbesecret")

	// Add ISBE Onboarding RP
	onboardRP := &models.RelyingParty{
		Name:        "ISBE Onboarding",
		Description: "The ISBE Onboarding Application",
		ClientID:    "isbeonboard",
		RedirectURL: "https://onboard.evidenceledger.eu/callback",
		OriginURL:   "https://onboard.evidenceledger.eu",
		Scopes:      "openid eidas",
		TokenExpiry: 3600,
	}

	if err := d.CreateRelyingParty(onboardRP, "isbesecret"); err != nil {
		slog.Error("Failed to create ISBE Onboarding RP", "error", err)
	}

	// Add development ISBE Onboarding RP
	testOnboardRP := &models.RelyingParty{
		Name:        "ISBE Onboarding",
		Description: "The ISBE Onboarding Application",
		ClientID:    "testonboard",
		RedirectURL: "https://onboard.mycredential.eu/callback",
		OriginURL:   "https://onboard.mycredential.eu",
		Scopes:      "openid eidas",
		TokenExpiry: 3600,
	}

	if err := d.CreateRelyingParty(testOnboardRP, "isbesecret"); err != nil {
		slog.Error("Failed to create ISBE Onboarding RP", "error", err)
	}

	// Add development ISBE Onboarding RP
	testIssuerRP := &models.RelyingParty{
		Name:        "ISBE Issuer for test",
		Description: "The ISBE Credential Issuer Application",
		ClientID:    "https://issuer.mycredential.eu",
		RedirectURL: "https://issuer.mycredential.eu/lear/auth/callback",
		OriginURL:   "https://issuer.mycredential.eu",
		Scopes:      "openid eidas",
		TokenExpiry: 3600,
	}

	if err := d.CreateRelyingParty(testIssuerRP, "isbesecret"); err != nil {
		slog.Error("Failed to create ISBE Onboarding RP", "error", err)
	}

	// Check if we already have test data
	var count int
	err := d.db.QueryRow("SELECT COUNT(*) FROM relying_parties").Scan(&count)
	if err != nil {
		return fmt.Errorf("failed to check existing data: %w", err)
	}

	if count > 0 {
		slog.Debug("Database already contains data, skipping test data initialization")
		return nil
	}

	// Add test relying party
	testRP := &models.RelyingParty{
		Name:        "Test Application",
		Description: "A test application for development",
		ClientID:    "test-client",
		RedirectURL: "https://certauth.mycredential.eu/callback",
		OriginURL:   "http://localhost:3000",
		Scopes:      "openid eidas",
		TokenExpiry: 3600,
	}

	if err := d.CreateRelyingParty(testRP, "test-secret"); err != nil {
		return fmt.Errorf("failed to create test RP: %w", err)
	}

	// Add example RP
	exampleRP := &models.RelyingParty{
		Name:        "Example RP Application",
		Description: "Example Relying Party application demonstrating certificate authentication",
		ClientID:    "example-rp",
		RedirectURL: "https://onboard.mycredential.eu/callback",
		OriginURL:   "http://onboard.mycredential.eu",
		Scopes:      "openid eidas",
		TokenExpiry: 3600,
	}

	if err := d.CreateRelyingParty(exampleRP, "example-secret"); err != nil {
		return fmt.Errorf("failed to create example RP: %w", err)
	}

	slog.Info("Test data initialized", "rp_count", 3)
	return nil
}
