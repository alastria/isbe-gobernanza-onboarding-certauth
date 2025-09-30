package database

import (
	"database/sql"
	"fmt"
	"log/slog"

	_ "github.com/mattn/go-sqlite3"
)

// Database manages SQLite operations
type Database struct {
	db *sql.DB
}

// New creates a new database instance
func New() *Database {
	return &Database{}
}

// Initialize creates tables and initializes the database
func (d *Database) Initialize() error {
	db, err := sql.Open("sqlite3", "./certauth.db")
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	d.db = db

	// Create tables
	if err := d.createTables(); err != nil {
		return fmt.Errorf("failed to create tables: %w", err)
	}

	// Initialize with test data if empty
	if err := d.initializeTestData(); err != nil {
		return fmt.Errorf("failed to initialize test data: %w", err)
	}

	slog.Info("Database initialized")
	return nil
}

// createTables creates all necessary tables
func (d *Database) createTables() error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS relying_parties (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			description TEXT,
			client_id TEXT UNIQUE NOT NULL,
			client_secret_hash TEXT NOT NULL,
			redirect_url TEXT NOT NULL,
			origin_url TEXT NOT NULL,
			scopes TEXT DEFAULT 'openid eidas',
			token_expiry INTEGER DEFAULT 3600,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS authentication_attempts (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			auth_code TEXT UNIQUE NOT NULL,
			client_id TEXT NOT NULL,
			redirect_uri TEXT NOT NULL,
			state TEXT NOT NULL,
			nonce TEXT,
			scope TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS registrations (
		    organization_identifier TEXT UNIQUE NOT NULL,
			organization TEXT,
			email TEXT,
			country TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
	}

	for _, query := range queries {
		if _, err := d.db.Exec(query); err != nil {
			return fmt.Errorf("failed to execute query: %w", err)
		}
	}

	return nil
}

// Close closes the database connection
func (d *Database) Close() error {
	if d.db != nil {
		return d.db.Close()
	}
	return nil
}
