package database

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/evidenceledger/certauth/internal/errl"
	"github.com/evidenceledger/certauth/internal/models"
	"github.com/evidenceledger/certauth/tsaservice"
)

func (d *Database) CreateRegistration(tsaService *tsaservice.TSAService, certificateData *models.CertificateData, email string, formData *models.ContractForm) error {

	// Convert form data into JSON
	formDataJSON, err := json.Marshal(formData)
	if err != nil {
		return errl.Errorf("failed to marshal form data: %w", err)
	}

	buf := bytes.Buffer{}
	buf.Write(formDataJSON)
	buf.WriteString(certificateData.CertificateDER)
	tstDataToTimestamp := buf.Bytes()

	timestamp, err := tsaService.Timestamp(tstDataToTimestamp)
	if err != nil {
		return errl.Errorf("failed to timestamp data: %w", err)
	}

	query := `
		INSERT INTO registrations (
			organization_identifier,
			organization,
			email,
			country,
			contract_form,
			eidas_cert,
			timestamp,
			created_at,
			updated_at
		) VALUES (?, ?, ?, ?, jsonb(?), ?, ?, ?, ?)
	`

	now := time.Now()

	_, err = d.db.Exec(query,
		certificateData.OrganizationID,
		certificateData.Subject.Organization,
		email,
		certificateData.Subject.Country,
		formDataJSON,
		certificateData.CertificateDER,
		timestamp,
		now,
		now,
	)

	if err != nil {
		return errl.Errorf("failed to create registration for %s: %w", email, err)
	}

	slog.Info("Created registration", "email", email, "org_id", certificateData.OrganizationID)
	fmt.Printf("Timestamp: %x\n", timestamp)
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
		return "", nil, "", errl.Errorf("failed to get registration: %w", err)
	}

	var form models.ContractForm
	if err := json.Unmarshal([]byte(formData), &form); err != nil {
		return "", nil, "", errl.Errorf("failed to unmarshal form data: %w", err)
	}

	return email, &form, eidasCert, nil
}

type Registration struct {
	Email     string
	FormData  string
	EidasCert string
}

func (d *Database) GetRegistrations() ([]Registration, error) {
	query := `
		SELECT email, json(contract_form), eidas_cert
		FROM registrations 
	`

	rows, err := d.db.Query(query)
	if err != nil {
		return nil, errl.Errorf("failed to get registrations: %w", err)
	}
	defer rows.Close()

	var registrations []Registration
	for rows.Next() {
		var registration Registration
		if err := rows.Scan(&registration.Email, &registration.FormData, &registration.EidasCert); err != nil {
			return nil, errl.Errorf("failed to scan registration: %w", err)
		}
		registrations = append(registrations, registration)
	}

	if err := rows.Err(); err != nil {
		return nil, errl.Errorf("failed to iterate registrations: %w", err)
	}

	return registrations, nil
}
