package database

import (
	"database/sql"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/evidenceledger/certauth/internal/errl"
	"github.com/evidenceledger/certauth/internal/models"
)

func (d *Database) CreateRegistration(certificateData *models.CertificateData, email string, formData *models.ContractForm) error {

	// Convert form data into JSON
	formDataJSON, err := json.Marshal(formData)
	if err != nil {
		return errl.Errorf("failed to marshal form data: %w", err)
	}

	query := `
		INSERT INTO registrations (
			organization_identifier,
			organization,
			email,
			country,
			contract_form,
			eidas_cert,
			created_at,
			updated_at
		) VALUES (?, ?, ?, ?, jsonb(?), ?, ?, ?)
	`

	now := time.Now()

	_, err = d.db.Exec(query,
		certificateData.OrganizationID,
		certificateData.Subject.Organization,
		email,
		certificateData.Subject.Country,
		formDataJSON,
		certificateData.CertificateDER,
		now,
		now,
	)

	if err != nil {
		return errl.Errorf("failed to create registration for %s: %w", email, err)
	}

	slog.Info("Created registration", "email", email, "org_id", certificateData.OrganizationID)
	return nil
}

func (d *Database) GetRegistration(organizationIdentifier string) (string, *models.ContractForm, string, error) {
	query := `
		SELECT email, json(contract_form), eidas_cert
		FROM registrations
		WHERE organization_identifier = ? 
	`

	var email string
	var formData string
	var eidasCert string
	err := d.db.QueryRow(query, organizationIdentifier).Scan(
		&email,
		&formData,
		&eidasCert,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return "", nil, "", nil
		}
		return "", nil, "", errl.Errorf("failed to get relying party: %w", err)
	}

	var form models.ContractForm
	if err := json.Unmarshal([]byte(formData), &form); err != nil {
		return "", nil, "", errl.Errorf("failed to unmarshal form data: %w", err)
	}

	return email, &form, eidasCert, nil
}
