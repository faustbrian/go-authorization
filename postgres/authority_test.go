package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"testing"
	"time"

	authorization "github.com/faustbrian/go-authorization/v3"
)

func TestAuthorityScopeAndCanonicalEpoch(t *testing.T) {
	scope := AuthorityScope{TenantID: "tenant", PolicyNamespace: "policy", SubjectID: "subject"}
	if err := scope.Validate(); err != nil {
		t.Fatal(err)
	}
	key, err := scope.Key()
	if err != nil || len(key) > 256 || key == "" {
		t.Fatal("invalid bounded scope key", err)
	}
	for _, component := range []string{strings.Repeat("x", 128), strings.Repeat("é", 64)} {
		maximum := AuthorityScope{TenantID: authorization.TenantID(component), PolicyNamespace: component, SubjectID: authorization.SubjectID(component)}
		if key, err := maximum.Key(); err != nil || key == "" {
			t.Fatal("maximum byte-width scope rejected", err)
		}
	}
	// Independent Ruby Digest::SHA256/Base64 framing fixture, version one.
	if key != "authorization:v1:5YlukGgCIlz7w-9ronIG7oquOfZ89ieUR0FL1i_Gv_Y" {
		t.Fatal("stored scope-key profile changed")
	}
	other := AuthorityScope{TenantID: "tenant:policy", PolicyNamespace: "subject", SubjectID: "tail"}
	collision := AuthorityScope{TenantID: "tenant", PolicyNamespace: "policy:subject", SubjectID: "tail"}
	a, _ := other.Key()
	b, _ := collision.Key()
	if a == b {
		t.Fatal("delimiter collision")
	}
	for _, n := range []uint64{1, math.MaxInt64, math.MaxInt64 + 1, math.MaxUint64 - 1, math.MaxUint64} {
		got, err := decodeAuthority(scope, "tenant", "policy", "subject", strconv.FormatUint(n, 10))
		if err != nil || got.Scope != scope || got.Version != n {
			t.Fatal("epoch narrowed", err)
		}
	}
	for _, bad := range []string{"", "0", "01", "-1", "1.5", "18446744073709551616"} {
		if _, err := decodeAuthority(scope, "tenant", "policy", "subject", bad); !errors.Is(err, ErrAuthorityUnavailable) {
			t.Fatal("corrupt epoch admitted", err)
		}
	}
	if _, err := decodeAuthority(scope, "foreign", "policy", "subject", "1"); !errors.Is(err, ErrAuthorityUnavailable) {
		t.Fatal("scope changed", err)
	}
	if _, err := json.Marshal(scope); err == nil || strings.Contains(fmt.Sprintf("%#v", scope), "subject") {
		t.Fatal("scope disclosed")
	}
	if _, err := (*AuthorityStore)(nil).Get(context.Background(), scope); !errors.Is(err, ErrInvalidAuthority) {
		t.Fatal("zero store admitted", err)
	}
}

func TestAuthorityBoundaryRejectsInvalidWithoutQuery(t *testing.T) {
	good := AuthorityScope{TenantID: "tenant", PolicyNamespace: "namespace", SubjectID: "subject"}
	for _, s := range []AuthorityScope{{}, {TenantID: "tenant", PolicyNamespace: "", SubjectID: "subject"}, {TenantID: "tenant", PolicyNamespace: "namespace", SubjectID: "\x00"}, {TenantID: "tenant", PolicyNamespace: "namespace", SubjectID: "bad id"}, {TenantID: "tenant", PolicyNamespace: strings.Repeat("x", 129), SubjectID: "subject"}, {TenantID: "\xff", PolicyNamespace: "namespace", SubjectID: "subject"}} {
		if s.Validate() == nil {
			t.Fatal("invalid scope accepted")
		}
		if k, e := s.Key(); e == nil || k != "" {
			t.Fatal("invalid scope key")
		}
	}
	var nilRows *authorityRowsFixture
	var nilQuery *authorityQueryFixture
	if err := RequireAuthority(context.Background(), nilQuery, good, 1, time.Second); !errors.Is(err, ErrInvalidAuthority) {
		t.Fatal("typed nil query accepted", err)
	}
	q := &authorityQueryFixture{rows: nilRows}
	if err := RequireAuthority(context.Background(), q, good, 1, time.Second); !errors.Is(err, ErrAuthorityUnavailable) {
		t.Fatal("nil rows admitted", err)
	}
	for _, duration := range []time.Duration{0, -1, time.Minute + 1} {
		if _, e := InitializeAuthority(context.Background(), q, good, duration); !errors.Is(e, ErrInvalidAuthority) {
			t.Fatal("invalid duration", e)
		}
	}
	// Exercise the API's defensive zero-context contract, not normal usage.
	var missingContext context.Context
	if err := RequireAuthority(missingContext, q, good, 1, time.Second); !errors.Is(err, ErrInvalidAuthority) {
		t.Fatal("nil context", err)
	}
	if err := RequireAuthority(context.Background(), q, good, 0, time.Second); !errors.Is(err, ErrInvalidAuthority) {
		t.Fatal("zero epoch", err)
	}
	if _, e := AdvanceAuthority(context.Background(), q, good, math.MaxUint64, time.Second); !errors.Is(e, ErrAuthorityOverflow) {
		t.Fatal("overflow", e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := RequireAuthority(ctx, q, good, 1, time.Second); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled call", err)
	}
	invalidVersions := []uint{0, 1}
	if uint64(math.MaxUint) > math.MaxInt64 {
		invalidVersions = append(invalidVersions, math.MaxUint)
	}
	for _, v := range invalidVersions {
		if _, err := AuthoritySchemaMigration(v); !errors.Is(err, ErrInvalidAuthority) {
			t.Fatal("invalid migration allocation", err)
		}
	}
	if _, err := AuthoritySchemaMigration(uint(4294967295)); err != nil {
		t.Fatal("valid 32-bit maximum allocation rejected", err)
	}
	if m, err := AuthorityGoMigration(2); err != nil || m.Version() != 2 {
		t.Fatal("migration adapter", err)
	}
}

type authorityQueryFixture struct{ rows *authorityRowsFixture }

func (q *authorityQueryFixture) Query(context.Context, string, ...any) (*authorityRowsFixture, error) {
	return q.rows, nil
}

type authorityRowsFixture struct{}

func (*authorityRowsFixture) Next() bool        { return false }
func (*authorityRowsFixture) Scan(...any) error { return nil }
func (*authorityRowsFixture) Err() error        { return nil }
func (*authorityRowsFixture) Close()            {}

func FuzzAuthorityScope(f *testing.F) {
	f.Add("tenant", "namespace", "subject")
	f.Add("", "a", "b")
	f.Add("t:namespace", "subject", "tail")
	f.Fuzz(func(t *testing.T, tenant, namespace, subject string) {
		s := AuthorityScope{TenantID: authorization.TenantID(tenant), PolicyNamespace: namespace, SubjectID: authorization.SubjectID(subject)}
		key, err := s.Key()
		if s.Validate() != nil {
			if err == nil || key != "" {
				t.Fatal("invalid key")
			}
			return
		}
		if err != nil || len(key) > 256 || !strings.HasPrefix(key, "authorization:v1:") {
			t.Fatal("unbounded key", err)
		}
	})
}
