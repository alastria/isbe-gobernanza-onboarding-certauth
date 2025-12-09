package database

import (
	"database/sql"
	"log/slog"

	"github.com/evidenceledger/certauth/internal/errl"
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
		return errl.Errorf("failed to open database: %w", err)
	}
	d.db = db

	// Create tables
	if err := d.createTables(); err != nil {
		return errl.Errorf("failed to create tables: %w", err)
	}

	// Initialize with test data if empty
	if err := d.initializeTestData(); err != nil {
		return errl.Errorf("failed to initialize test data: %w", err)
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
		`CREATE TABLE IF NOT EXISTS registrations (
		    organization_identifier TEXT UNIQUE NOT NULL,
			organization TEXT,
			email TEXT,
			country TEXT,
			contract_form BLOB,
			eidas_cert TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
	}

	for _, query := range queries {
		if _, err := d.db.Exec(query); err != nil {
			return errl.Errorf("failed to execute query: %w", err)
		}
	}

	// Run the migrations
	if err := RunMigrationsUp(d.db); err != nil {
		return errl.Errorf("failed to run migrations: %w", err)
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
