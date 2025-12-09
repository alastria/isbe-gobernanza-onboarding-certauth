package database

import (
	"crypto/rand"
	"database/sql"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/evidenceledger/certauth/internal/errl"
)

const createMigrationsTableSQL = `CREATE TABLE IF NOT EXISTS migrations (
    version TEXT NOT NULL,
	"created_at" INTEGER
);`

type migrationfun func(db *sql.DB) error

type oneMigration struct {
	version string
	up      migrationfun
	down    migrationfun
}

var migrations = map[string]oneMigration{}
var migrationMutex sync.Mutex

// RegisterMigration is called by the migration functions in their init() to register a migration.
// version must be a timestamp in the format YYYYMMDDTHHMMSS (YearMonthDayTHoursMinutesSeconds),
// like '20251102T203201'.
// The migrations are ordered by timestamp before being applied. This guarantees that migrations are
// applied in the correct order, independent from the order in which the init() functions have run.
// Both an UP migration and a DOWN migration can be registered, with nil if no action has to be taken.
// If a registered migration function returns an error, the migration is cancelled.
// Each migration function is run inside a SQLite SAVEPOINT, which allows nesting in case that the
// migration function needs nested savepoints.
func RegisterMigration(version string, up migrationfun, down migrationfun) {
	migrationMutex.Lock()
	defer migrationMutex.Unlock()
	migrations[version] = oneMigration{
		version: version,
		up:      up,
		down:    down,
	}
}

// RunMigrationsUp ensures the database migrations table exists and applies any pending migrations.
//
// RunMigrationsUp performs the following steps:
//  1. Ensures the migrations table exists by executing createMigrationsTableSQL.
//  2. Reads the version of the last applied migration from the migrations table
//     using "SELECT version FROM migrations ORDER BY version DESC LIMIT 1".
//     If the table is empty, no rows is treated as no previously applied migrations.
//  3. Collects available migrations from the global `migrations` map, sorts their
//     keys lexicographically, and iterates them in that order.
//  4. Skips any migration whose version is less than or equal to the last applied version.
//  5. For each pending migration, calls applyMigration(db, migration) to apply it,
//     logs successful application, and stops on the first error returned by applyMigration.
//
// Notes and expectations:
//   - Version comparison is lexicographical string comparison; migration version keys must be
//     chosen so that lexicographical order corresponds to the intended application order.
//   - Recommended version format is a timestamp in the format YYYYMMDDTHHMMSS (YearMonthDayTHoursMinutesSeconds),
//     like '20251102T203201'.
func RunMigrationsUp(db *sql.DB) error {

	slog.Info("Running migrations")
	defer slog.Info("Migrations done")

	// Create the migrations table if it doesn't exist
	if _, err := db.Exec(createMigrationsTableSQL); err != nil {
		return errl.Errorf("failed to create migrations table: %w", err)
	}

	// Read the version of the last applied migration
	var lastAppliedVersion string
	err := db.QueryRow("SELECT version FROM migrations ORDER BY version DESC LIMIT 1").Scan(&lastAppliedVersion)
	if err != nil && err != sql.ErrNoRows {
		return errl.Errorf("failed to read last applied migration version: %w", err)
	}
	slog.Debug("Last applied migration version", slog.String("version", lastAppliedVersion))

	// lastAppliedVersion is either "" (no migrations applied yet) or a valid version string
	// The empty string is lexicographically less than any valid version string, so this is OK

	if len(migrations) == 0 {
		slog.Info("There are no registered migrations")
		return nil
	}

	// Order registered migrations to apply by version lexicographically
	keys := make([]string, 0, len(migrations))
	for k := range migrations {
		keys = append(keys, k)
	}

	sort.Strings(keys)

	// Loop the keys for applying the migration or not
	for _, currentMigrationVersion := range keys {
		if currentMigrationVersion <= lastAppliedVersion {
			slog.Debug("Skipping migration", slog.String("version", currentMigrationVersion))
			continue
		}
		migration := migrations[currentMigrationVersion]

		err := applyMigration(db, migration)
		if err != nil {
			return errl.Errorf("failed to apply migration %s: %w", currentMigrationVersion, err)
		}

		slog.Info("Migration applied", slog.String("version", currentMigrationVersion))

	}

	return nil

}

// applyMigration runs a single migration inside a SQLite savepoint and records it
// in the migrations table. It creates a random, unguessable SAVEPOINT so user
// migration code can create nested savepoints safely. The function defers a plain
// ROLLBACK so that if any step fails before the savepoint is released, changes are
// undone; releasing the savepoint makes the deferred rollback a no-op.
//
// The function performs these steps in order:
//  1. Generate a random savepoint name and execute "SAVEPOINT <name>".
//  2. Execute migration.up(db). If that returns an error, the error is logged
//     and returned (the deferred rollback will undo any partial changes).
//  3. Insert the migration version into the migrations table.
//  4. Execute "RELEASE <name>" to commit the savepoint and persist changes.
//
// Parameters:
//
//	db        - a *sqlx.DB connected to the SQLite database to operate on.
//	migration - a oneMigration describing the migration to execute (provides up
//	            and the version to record).
//
// Errors:
//
//	Any error encountered while starting the savepoint, running the migration,
//	recording the version, or releasing the savepoint is returned to the caller.
//	The function ensures uncommitted changes are rolled back on error.
func applyMigration(db *sql.DB, migration oneMigration) error {

	// Generate a random string
	savepointName := "S_" + rand.Text()

	// Start a SQLite SAVEPOINT with an unguessable name.
	// SAVEPOINTs are a method of creating transactions, similar to BEGIN and COMMIT, except that the SAVEPOINT and RELEASE commands
	// are named and may be nested.
	// We need this because we want to run the migration code and update the migrations table in a single transaction.
	// User migration code does not have to create a transaction but can nest SAVEPOINTS if they wish.
	// IMPORTANT: migration code can not use BEGIN and COMMIT, only SAVEPOINT and RELEASE. BEGIN will receive an error, as per SQLite documentation.
	_, err := db.Exec("SAVEPOINT " + savepointName)
	if err != nil {
		return errl.Error(err)
	}
	// Defer a plain rollback, which will cancel the transaction if it is not commited, and be a no-op otherwise
	defer db.Exec("ROLLBACK")

	slog.Debug("Savepoint started", slog.String("name", savepointName))

	// Run the migration
	err = migration.up(db)
	if err != nil {
		err = errl.Error(err)
		slog.Error("Error in migration", "error", err)
		return err
	}

	// Mark the migration as applied
	_, err = db.Exec("INSERT INTO migrations (version, created_at) VALUES (?, ?)", migration.version, time.Now().Unix())
	if err != nil {
		return errl.Error(err)
	}

	// Commit the SAVEPOINT
	_, err = db.Exec("RELEASE " + savepointName)
	if err != nil {
		return errl.Error(err)
	}

	return nil

}
