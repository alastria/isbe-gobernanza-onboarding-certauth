package database

import (
	"database/sql"
)

func init() {
	RegisterMigration("20251209T210848", migration_up_20251209T210848, nil)
}

func migration_up_20251209T210848(db *sql.DB) error {

	// Add a BLOB column "timestamp" with the registration timestamp
	_, err := db.Exec(`
		ALTER TABLE registrations
		ADD COLUMN timestamp BLOB NOT NULL;
	`)
	if err != nil {
		return err
	}

	return nil
}
