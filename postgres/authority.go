package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"reflect"
	"strconv"
	"time"
	"unicode/utf8"

	authorization "github.com/faustbrian/go-authorization/v4"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	// ErrInvalidAuthority denotes malformed scope, version, duration or handle.
	ErrInvalidAuthority = errors.New("invalid authorization authority input")
	// ErrAuthorityDenied covers both absent and mismatched authority, without
	// disclosing whether an unrelated principal exists.
	ErrAuthorityDenied = errors.New("authorization authority denied")
	// ErrAuthorityConflict denotes an initialization or expected-epoch CAS conflict.
	ErrAuthorityConflict = errors.New("authorization authority conflict")
	// ErrAuthorityOverflow is terminal; authority must never wrap or reset.
	ErrAuthorityOverflow = errors.New("authorization authority exhausted")
	// ErrAuthorityUnavailable redacts database, schema and corrupt-row failures.
	ErrAuthorityUnavailable = errors.New("authorization authority unavailable")
)

// AuthorityScope identifies one lifecycle epoch independently of policy revision.
// Every component is an exact 1..128-byte UTF-8 opaque ID, with ASCII whitespace
// and controls forbidden. No normalization occurs. PolicyNamespace must select
// a domain in which SubjectID is unique across subject kinds; an untrusted
// Subject.Kind or attribute cannot select that domain. Zero is invalid.
type AuthorityScope struct {
	// TenantID is the exact tenant isolation boundary, not a defaultable label.
	TenantID authorization.TenantID
	// PolicyNamespace is a trusted domain in which SubjectID is unambiguous.
	PolicyNamespace string
	// SubjectID is the exact lifecycle subject within tenant and namespace.
	SubjectID authorization.SubjectID
}

// Validate checks the complete scope without reading or provisioning authority.
func (s AuthorityScope) Validate() error {
	for _, id := range []string{string(s.TenantID), s.PolicyNamespace, string(s.SubjectID)} {
		if len(id) == 0 || len(id) > 128 || !utf8.ValidString(id) {
			return ErrInvalidAuthority
		}
		for i := 0; i < len(id); i++ {
			if id[i] <= 32 || id[i] == 127 {
				return ErrInvalidAuthority
			}
		}
	}
	return nil
}

// Key returns a stable version-one session-vector binding, not an authorization
// decision or private identifier. SHA-256 hashes the fixed domain followed by
// the three exact UTF-8 components, each framed with its big-endian uint16 byte
// length, in tenant/namespace/subject order. The unpadded base64url digest fits
// bounded snapshot keys; owner lookups still compare all three original IDs.
// Hashing avoids ambiguous delimiter joins, not correlation or disclosure.
func (s AuthorityScope) Key() (string, error) {
	if err := s.Validate(); err != nil {
		return "", err
	}
	h := sha256.New()
	_, _ = h.Write([]byte("golib.authorization.authority.v1\x00"))
	for _, id := range []string{string(s.TenantID), s.PolicyNamespace, string(s.SubjectID)} {
		// Keep the admitted byte bound visible at the fixed-width encoding.
		length := len(id)
		if length < 1 || length > 128 {
			return "", ErrInvalidAuthority
		}
		var size [2]byte
		binary.BigEndian.PutUint16(size[:], uint16(length))
		_, _ = h.Write(size[:])
		_, _ = h.Write([]byte(id))
	}
	return "authorization:v1:" + base64.RawURLEncoding.EncodeToString(h.Sum(nil)), nil
}

// Format redacts internal correlation scope in diagnostics.
func (AuthorityScope) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "postgres.AuthorityScope(redacted)")
}

// MarshalJSON rejects accidental scope export.
func (AuthorityScope) MarshalJSON() ([]byte, error) { return nil, ErrInvalidAuthority }

// AuthorityRecord is a structural primary projection of one positive uint64
// epoch. It is neither a policy decision nor freshness evidence, and must not
// be promoted into a renewable positive-cache lease.
type AuthorityRecord struct {
	// Scope is the exact primary row identity, not caller-selected authority.
	Scope AuthorityScope
	// Version is its positive epoch; zero never represents initialized authority.
	Version uint64
}

// Format hides internal scope/version correlation.
func (AuthorityRecord) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "postgres.AuthorityRecord(redacted)")
}

// MarshalJSON rejects accidental authority projection export.
func (AuthorityRecord) MarshalJSON() ([]byte, error) { return nil, ErrInvalidAuthority }

// AuthorityRows is the minimum synchronous borrowed cursor contract. Implemented
// by pgx.Rows and identity's generation-bound WorkRows. Close must drain or
// cancel the result without terminalizing the owning transaction.
type AuthorityRows interface {
	// Next advances the borrowed cursor and reports whether a row is available.
	Next() bool
	// Scan copies the current row into supplied destinations without retaining them.
	Scan(...any) error
	// Err reports iteration failures after Next returns false.
	Err() error
	// Close drains or cancels this cursor without closing the owning transaction.
	Close()
}

// AuthorityQueryer supplies one trusted owner's synchronous query capability.
// The generic row type preserves narrower generation-bound cursors without
// importing identity or exposing raw connections. Protected operations require
// a real borrowed transaction, never a pool/autocommit or replica. The owner
// must fence participant scope/lifetime and abort/poison on any returned error.
// Methods below never retain this handle or begin/commit/rollback a transaction.
type AuthorityQueryer[R AuthorityRows] interface {
	// Query honors the bounded context and returns an owned cursor to close.
	Query(context.Context, string, ...any) (R, error)
}

const authoritySelect = `SELECT tenant_id,policy_namespace,subject_id,version::text FROM authorization_subject_authorities WHERE tenant_id=$1 AND policy_namespace=$2 AND subject_id=$3`
const authorityInsert = `INSERT INTO authorization_subject_authorities(tenant_id,policy_namespace,subject_id,version) VALUES($1,$2,$3,1) ON CONFLICT(tenant_id,policy_namespace,subject_id) DO NOTHING RETURNING tenant_id,policy_namespace,subject_id,version::text`
const authorityAdvance = `UPDATE authorization_subject_authorities SET version=version+1 WHERE tenant_id=$1 AND policy_namespace=$2 AND subject_id=$3 AND version=$4::numeric RETURNING tenant_id,policy_namespace,subject_id,version::text`

// AuthorityStore borrows a primary pool for structural reads only. Concurrent
// reads are safe; the caller retains pool shutdown ownership. Zero is invalid.
type AuthorityStore struct {
	pool            *pgxpool.Pool
	maximumDuration time.Duration
}

// NewAuthorityStore requires a primary pool and finite 0..1-minute read budget.
// Earlier caller deadlines win. The constructor performs no IO or bootstrap.
func NewAuthorityStore(pool *pgxpool.Pool, maximumDuration time.Duration) (*AuthorityStore, error) {
	if pool == nil || maximumDuration <= 0 || maximumDuration > time.Minute {
		return nil, ErrInvalidAuthority
	}
	return &AuthorityStore{pool: pool, maximumDuration: maximumDuration}, nil
}

// Get reads the exact primary scope without locks or implicit initialization.
// Missing authority denies; corrupt/storage errors are redacted. Cancellation
// preserves context errors. No policy decision or validity lease is returned.
func (s *AuthorityStore) Get(ctx context.Context, scope AuthorityScope) (AuthorityRecord, error) {
	if s == nil || s.pool == nil {
		return AuthorityRecord{}, ErrInvalidAuthority
	}
	return authorityQuery(ctx, s.pool, scope, s.maximumDuration, authoritySelect, ErrAuthorityDenied)
}

// InitializeAuthority stages explicit trusted bootstrap at epoch one. Existing
// scopes return Conflict, including newer epochs: bootstrap never resets them.
// The returned projection is provisional until the owner proves commit. The
// owner must authorize bootstrap and abort on error; reads never call this API.
func InitializeAuthority[R AuthorityRows](ctx context.Context, q AuthorityQueryer[R], scope AuthorityScope, maximumDuration time.Duration) (AuthorityRecord, error) {
	return authorityQuery(ctx, q, scope, maximumDuration, authorityInsert, ErrAuthorityConflict)
}

// AdvanceAuthority stages one exact expected-epoch successor under row locking.
// Role/statement/policy/entitlement mutation and required audit must share this
// transaction. Missing/stale scopes conflict; MaxUint64 fails terminally before
// SQL. Restore/import cannot reset authority. This is not a standalone admin
// workflow: caller authorization, immutable intent and recovery remain owned by
// the existing coordinator. A returned record is provisional, not commit proof.
func AdvanceAuthority[R AuthorityRows](ctx context.Context, q AuthorityQueryer[R], scope AuthorityScope, expected uint64, maximumDuration time.Duration) (AuthorityRecord, error) {
	if expected == 0 {
		return AuthorityRecord{}, ErrInvalidAuthority
	}
	if expected == math.MaxUint64 {
		return AuthorityRecord{}, ErrAuthorityOverflow
	}
	return authorityQuery(ctx, q, scope, maximumDuration, authorityAdvance, ErrAuthorityConflict, strconv.FormatUint(expected, 10))
}

// RequireAuthority compares exact current authority under a primary share lock
// retained until the original transaction owner commits/aborts. Missing or any
// unequal epoch denies, including a future expected value. No row/version is
// created or refreshed and no policy decision, proof or session is issued.
// The trusted native adapter must poison/abort its Work on every error, including
// ignored denial; passing an independent pool cannot prove protected admission.
func RequireAuthority[R AuthorityRows](ctx context.Context, q AuthorityQueryer[R], scope AuthorityScope, expected uint64, maximumDuration time.Duration) error {
	if expected == 0 {
		return ErrInvalidAuthority
	}
	current, err := authorityQuery(ctx, q, scope, maximumDuration, authoritySelect+" FOR SHARE", ErrAuthorityDenied)
	if err != nil {
		return err
	}
	if current.Version != expected {
		return ErrAuthorityDenied
	}
	return nil
}

func authorityQuery[R AuthorityRows](ctx context.Context, q AuthorityQueryer[R], scope AuthorityScope, duration time.Duration, sql string, missing error, extra ...any) (AuthorityRecord, error) {
	if ctx == nil || nilAuthorityHandle(q) || duration <= 0 || duration > time.Minute || scope.Validate() != nil {
		return AuthorityRecord{}, ErrInvalidAuthority
	}
	bounded, cancel := context.WithTimeout(ctx, duration)
	defer cancel()
	if err := bounded.Err(); err != nil {
		return AuthorityRecord{}, err
	}
	args := []any{string(scope.TenantID), scope.PolicyNamespace, string(scope.SubjectID)}
	args = append(args, extra...)
	rows, err := q.Query(bounded, sql, args...)
	if err != nil {
		return AuthorityRecord{}, authorityFailure(bounded, err)
	}
	if nilAuthorityHandle(rows) {
		return AuthorityRecord{}, ErrAuthorityUnavailable
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return AuthorityRecord{}, authorityFailure(bounded, err)
		}
		if err := bounded.Err(); err != nil {
			return AuthorityRecord{}, err
		}
		return AuthorityRecord{}, missing
	}
	var tenant, namespace, subject, version string
	if err := rows.Scan(&tenant, &namespace, &subject, &version); err != nil {
		return AuthorityRecord{}, authorityFailure(bounded, err)
	}
	if rows.Next() {
		return AuthorityRecord{}, ErrAuthorityUnavailable
	}
	if err := rows.Err(); err != nil {
		return AuthorityRecord{}, authorityFailure(bounded, err)
	}
	if err := bounded.Err(); err != nil {
		return AuthorityRecord{}, err
	}
	return decodeAuthority(scope, tenant, namespace, subject, version)
}

func decodeAuthority(scope AuthorityScope, tenant, namespace, subject, version string) (AuthorityRecord, error) {
	n, err := strconv.ParseUint(version, 10, 64)
	if scope.Validate() != nil || string(scope.TenantID) != tenant || scope.PolicyNamespace != namespace || string(scope.SubjectID) != subject || err != nil || n == 0 || strconv.FormatUint(n, 10) != version {
		return AuthorityRecord{}, ErrAuthorityUnavailable
	}
	return AuthorityRecord{Scope: scope, Version: n}, nil
}
func authorityFailure(ctx context.Context, _ error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return ErrAuthorityUnavailable
}

// Reflection is limited to literal/typed-nil validation, never wiring or calls.
func nilAuthorityHandle(v any) bool {
	if v == nil {
		return true
	}
	r := reflect.ValueOf(v)
	switch r.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return r.IsNil()
	}
	return false
}
