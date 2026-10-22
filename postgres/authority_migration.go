package postgres

import (
	migrations "github.com/faustbrian/go-migrations/v4"
	"math"
)

// AuthoritySchemaMigration appends opt-in scoped lifecycle epoch storage without
// altering the released v1 manifest schema. Allocate a permanent version later
// than every existing application migration (at least 2). It bootstraps no rows.
// Downgrade is deliberately absent: dropping/recreating authority could reset
// epochs and resurrect old artifacts. Restore must preserve all authoritative
// rows or use the platform's explicit compromise/invalidation procedure.
func AuthoritySchemaMigration(version uint) (Migration, error) {
	if version <= 1 || uint64(version) > math.MaxInt64 {
		return Migration{}, ErrInvalidAuthority
	}
	return Migration{Version: version, Name: "create_authorization_subject_authorities", Up: authoritySchemaSQL}, nil
}

// AuthorityGoMigration adapts the separately allocated forward-only authority
// migration to the existing owned migrations library. Historical v1 bytes and
// legacy manifest APIs are unchanged; no implicit dependency on identity exists.
func AuthorityGoMigration(version uint) (migrations.Migration, error) {
	m, err := AuthoritySchemaMigration(version)
	if err != nil {
		return migrations.Migration{}, err
	}
	return migrations.NewMigration(migrations.Version(m.Version), m.Name, migrations.TransactionModeDefault, m.Up, m.Down)
}

const authoritySchemaSQL = `CREATE TABLE authorization_subject_authorities (
 tenant_id text NOT NULL CHECK (octet_length(tenant_id) BETWEEN 1 AND 128),
 policy_namespace text NOT NULL CHECK (octet_length(policy_namespace) BETWEEN 1 AND 128),
 subject_id text NOT NULL CHECK (octet_length(subject_id) BETWEEN 1 AND 128),
 version numeric NOT NULL CHECK (version > 0 AND version <= 18446744073709551615 AND version = trunc(version)),
 PRIMARY KEY (tenant_id,policy_namespace,subject_id)
);`
