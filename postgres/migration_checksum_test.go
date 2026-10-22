package postgres

import "testing"

// Deployed ledgers recorded these checksums through the published v3.1.0
// module on go-migrations/v2; a changed version, name, mode or SQL would fail
// validation of their history after the v4 ledger name upgrade.
func TestGoMigrationChecksumsMatchPublishedV3(t *testing.T) {
	t.Parallel()

	schema, err := GoMigration()
	if err != nil {
		t.Fatalf("GoMigration() error = %v", err)
	}
	authority, err := AuthorityGoMigration(2)
	if err != nil {
		t.Fatalf("AuthorityGoMigration(2) error = %v", err)
	}
	if schema.Version() != 1 || schema.Name() != "create_authorization_policy_manifests" ||
		schema.Checksum().String() != "sha256:4493f6b52f1df7bb47c7c3cbdbf8a754b4d52b4c1566967328aa59cc82264a87" {
		t.Errorf("GoMigration() = %d/%s/%s", schema.Version(), schema.Name(), schema.Checksum())
	}
	if authority.Version() != 2 || authority.Name() != "create_authorization_subject_authorities" ||
		authority.Checksum().String() != "sha256:de9f77054d681ac44a3c31dbead7f1bfc8045b3e9e18bcc19730918a7c544618" {
		t.Errorf("AuthorityGoMigration(2) = %d/%s/%s", authority.Version(), authority.Name(), authority.Checksum())
	}
}
