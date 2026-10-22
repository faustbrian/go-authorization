// Package postgres persists a complete manifest in one PostgreSQL singleton row.
// New borrows pgxpool; Update uses one conditional SQL statement to match expected
// revision and store a newer manifest. It does not authorize publishers, run schema
// migrations, retry failures, invalidate caches or close the pool.
// Public revisions are uint64 but the schema uses signed bigint; select a compatible
// range. Driver responses materialize before policy.Decode byte admission. Database
// errors can contain sensitive diagnostics, and failures may require reconciliation
// when a write committed but response/decoding failed. No DB qualification is implied.
package postgres

import (
	"context"
	"errors"

	authorization "github.com/faustbrian/go-authorization/v4"
	"github.com/faustbrian/go-authorization/v4/policy"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	// ErrNilPool identifies authorization postgres pool is nil. Compare with errors.Is, not error text.
	ErrNilPool = errors.New("authorization postgres pool is nil")
	// ErrNotInitialized identifies authorization policy is not initialized. Compare with errors.Is, not error text.
	ErrNotInitialized = errors.New("authorization policy is not initialized")
	// ErrRevisionConflict identifies authorization policy revision conflict. Compare with errors.Is, not error text.
	ErrRevisionConflict = errors.New("authorization policy revision conflict")
	// ErrRevisionNotMonotonic identifies authorization policy revision is not monotonic. Compare with errors.Is, not error text.
	ErrRevisionNotMonotonic = errors.New("authorization policy revision is not monotonic")
)

const (
	loadManifestSQL = "SELECT manifest FROM authorization_policy_manifests " +
		"WHERE singleton = 1"
	updateManifestSQL = "WITH updated AS (" +
		"UPDATE authorization_policy_manifests SET revision = $2, " +
		"manifest = $3, updated_at = clock_timestamp() " +
		"WHERE singleton = 1 AND revision = $1 AND $2 > revision " +
		"RETURNING manifest), inserted AS (" +
		"INSERT INTO authorization_policy_manifests " +
		"(singleton, revision, manifest) SELECT 1, $2, $3 " +
		"WHERE $1 = 0 AND NOT EXISTS (SELECT 1 FROM " +
		"authorization_policy_manifests WHERE singleton = 1) " +
		"ON CONFLICT (singleton) DO NOTHING RETURNING manifest) " +
		"SELECT manifest FROM updated UNION ALL " +
		"SELECT manifest FROM inserted"
)

type row = pgx.Row

type database interface {
	queryRow(context.Context, string, ...any) row
}

// Store borrows a pgx query seam; construct with New, keep schema/pool
// lifecycle valid and use contexts with deadlines. The zero value is unusable.
type Store struct {
	queryRow func(context.Context, string, ...any) pgx.Row
}

// New borrows a non-nil pool without opening/migrating/closing it.
func New(pool *pgxpool.Pool) (*Store, error) {
	if pool == nil {
		return nil, ErrNilPool
	}
	return &Store{queryRow: pool.QueryRow}, nil
}

func newStore(database database) *Store {
	return &Store{queryRow: database.queryRow}
}

// Load reads/decodes the singleton manifest, mapping no rows to
// ErrNotInitialized. It trusts database content and does not cross-check JSON
// revision against the separate SQL revision column. Row materialization precedes
// parser admission; raw driver diagnostics remain caller-protected.
func (store *Store) Load(ctx context.Context) (policy.Manifest, error) {
	var encoded []byte
	if err := store.queryRow(ctx, loadManifestSQL).Scan(&encoded); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return policy.Manifest{}, ErrNotInitialized
		}
		return policy.Manifest{}, err
	}
	return policy.Decode(encoded)
}

// Update validates/encodes next, then conditionally writes one newer
// revision under expected (zero for initialization). No rows is conflict; raw
// query errors or post-write decode errors can leave commit state uncertain.
// Reconcile with Load before repeating unknown outcomes. Revisions must fit SQL
// bigint; caller graphs are borrowed during encode. No retry/invalidation is owned.
func (store *Store) Update(
	ctx context.Context,
	expected authorization.Revision,
	next policy.Manifest,
) (policy.Manifest, error) {
	encoded, err := policy.Encode(next)
	if err != nil {
		return policy.Manifest{}, err
	}
	if next.Revision <= expected {
		return policy.Manifest{}, ErrRevisionNotMonotonic
	}

	var stored []byte
	err = store.queryRow(
		ctx,
		updateManifestSQL,
		expected,
		next.Revision,
		encoded,
	).Scan(&stored)
	if errors.Is(err, pgx.ErrNoRows) {
		return policy.Manifest{}, ErrRevisionConflict
	}
	if err != nil {
		return policy.Manifest{}, err
	}
	return policy.Decode(stored)
}
