package database

import (
	"database/sql"
)

func init() {
	RegisterMigration("20251209T091700", migration_up_20251209T091700, nil)
}

func migration_up_20251209T091700(db *sql.DB) error {

	// This is an example migration, which does nothing.
	// For new migrations, copy this file and replace the name and the content.

	return nil
}
