package database

import (
	"database/sql"
	"log/slog"
	"time"

	"github.com/evidenceledger/certauth/internal/errl"
	"github.com/evidenceledger/certauth/internal/models"
)

func (d *Database) CreateRegistration(certificateData *models.CertificateData, email string) error {

	query := `
		INSERT INTO registrations (
			organization_identifier,
			organization,
			email,
			country,
			created_at,
			updated_at
		) VALUES (?, ?, ?, ?, ?, ?)
	`

	now := time.Now()

	_, err := d.db.Exec(query,
		certificateData.OrganizationID,
		certificateData.Subject.Organization,
		email,
		certificateData.Subject.Country,
		now,
		now,
	)

	if err != nil {
		return errl.Errorf("failed to create registration for %s: %w", email, err)
	}

	slog.Info("Created registration", "email", email, "org_id", certificateData.OrganizationID)
	return nil
}

func (d *Database) GetRegistrationEmail(organizationIdentifier string) (string, error) {
	query := `
		SELECT email
		FROM registrations
		WHERE organization_identifier = ? 
	`

	var email string
	err := d.db.QueryRow(query, organizationIdentifier).Scan(
		&email,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return "", nil
		}
		return "", errl.Errorf("failed to get relying party: %w", err)
	}

	return email, nil
}
