package database

import (
	"database/sql"
	"log/slog"
	"time"

	"github.com/evidenceledger/certauth/internal/errl"
	"github.com/evidenceledger/certauth/internal/models"
)

// CreateAuthCode creates a new authorization code
func (d *Database) CreateAuthCode(code *models.AuthProcess) error {
	query := `
		INSERT INTO authentication_attempts (
			auth_code, client_id, redirect_uri, state, nonce, scope, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?)
	`

	_, err := d.db.Exec(query,
		code.Code, code.ClientID, code.RedirectURI, code.State, code.Nonce, code.Scope, code.CreatedAt,
	)

	if err != nil {
		return errl.Errorf("failed to create auth code: %w", err)
	}

	slog.Debug("Created auth code", "client_id", code.ClientID, "state", code.State)
	return nil
}

// GetAuthCode retrieves an authorization code by code value
func (d *Database) GetAuthCode(code string) (*models.AuthProcess, error) {
	query := `
		SELECT auth_code, client_id, redirect_uri, state, nonce, scope, created_at
		FROM authentication_attempts 
		WHERE auth_code = ? AND created_at > datetime('now', '-10 minutes')
	`

	var authCode models.AuthProcess
	err := d.db.QueryRow(query, code).Scan(
		&authCode.Code,
		&authCode.ClientID, &authCode.RedirectURI, &authCode.State, &authCode.Nonce, &authCode.Scope,
		&authCode.CreatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, errl.Errorf("failed to get auth code: %w", err)
	}

	// Set expiration to 10 minutes from creation
	authCode.ExpiresAt = authCode.CreatedAt.Add(10 * time.Minute)

	return &authCode, nil
}

// DeleteAuthCode deletes an authorization code (after use)
func (d *Database) DeleteAuthCode(code string) error {
	query := `DELETE FROM authentication_attempts WHERE auth_code = ?`

	_, err := d.db.Exec(query, code)
	if err != nil {
		return errl.Errorf("failed to delete auth code: %w", err)
	}

	slog.Debug("Deleted auth code", "code", code)
	return nil
}

// CleanupExpiredAuthCodes removes expired authorization codes
func (d *Database) CleanupExpiredAuthCodes() error {
	query := `DELETE FROM authentication_attempts WHERE created_at < datetime('now', '-10 minutes')`

	result, err := d.db.Exec(query)
	if err != nil {
		return errl.Errorf("failed to cleanup expired auth codes: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected > 0 {
		slog.Debug("Cleaned up expired auth codes", "count", rowsAffected)
	}

	return nil
}
