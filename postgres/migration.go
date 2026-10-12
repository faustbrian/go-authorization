package postgres

import migrations "github.com/faustbrian/go-migrations/v2"

// Migration is caller-owned executable schema SQL metadata; it is not applied here.
type Migration struct {
	// Version is caller-owned migration ordering; SchemaMigration returns 1.
	Version uint
	// Name is the exact application label; do not place secrets in error-visible names.
	Name string
	// Up is forward SQL; SchemaMigration supplies singleton-table creation.
	Up string
	// Down is reverse SQL; SchemaMigration supplies a destructive table drop.
	Down string
}

// SchemaMigration returns version-1 singleton-table SQL. Down irreversibly
// drops policy data; caller migration policy owns transactions/deployment/rollback.
func SchemaMigration() Migration {
	return Migration{
		Version: 1,
		Name:    "create_authorization_policy_manifests",
		Up: `CREATE TABLE authorization_policy_manifests (
    singleton smallint PRIMARY KEY CHECK (singleton = 1),
    revision bigint NOT NULL CHECK (revision > 0),
    manifest jsonb NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);`,
		Down: `DROP TABLE authorization_policy_manifests;`,
	}
}

// GoMigration binds the SQL to go-migrations/v2 default transaction policy;
// it creates a definition, not a database migration execution.
func GoMigration() (migrations.Migration, error) {
	migration := SchemaMigration()
	return migrations.NewMigration(
		migrations.Version(migration.Version),
		migration.Name,
		migrations.TransactionModeDefault,
		migration.Up,
		migration.Down,
	)
}
