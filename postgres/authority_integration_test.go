package postgres_test

import (
	"context"
	"errors"
	"math"
	"os"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"

	store "github.com/faustbrian/go-authorization/v4/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestIntegrationScopedAuthority(t *testing.T) {
	url := os.Getenv("POSTGRES_URL")
	if url == "" {
		t.Skip("POSTGRES_URL is not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	config, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = "authorization_authority_test"
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if _, err = pool.Exec(ctx, "CREATE SCHEMA authorization_authority_test"); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), time.Second)
		defer stop()
		if _, err := pool.Exec(cleanup, "DROP SCHEMA authorization_authority_test CASCADE"); err != nil {
			t.Error("owned test schema cleanup failed", err)
		}
	}()
	legacy := store.SchemaMigration()
	if _, err = pool.Exec(ctx, legacy.Up); err != nil {
		t.Fatal(err)
	}
	manifest, err := store.New(pool)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = manifest.Update(ctx, 0, integrationManifest(1)); err != nil {
		t.Fatal(err)
	}
	migration, err := store.AuthoritySchemaMigration(2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, migration.Up); err != nil {
		t.Fatal(err)
	}
	if got, err := manifest.Load(ctx); err != nil || got.Revision != 1 {
		t.Fatal("legacy manifest changed", err)
	}
	owner, err := store.NewAuthorityStore(pool, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	scope := store.AuthorityScope{TenantID: "tenant", PolicyNamespace: "namespace", SubjectID: "subject"}
	if _, err = owner.Get(ctx, scope); !errors.Is(err, store.ErrAuthorityDenied) {
		t.Fatal("missing scope defaulted", err)
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackAuthorityFixture(tx)
	if _, err = store.InitializeAuthority(ctx, tx, scope, time.Second); err != nil {
		t.Fatal(err)
	}
	if err = tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err = owner.Get(ctx, scope); !errors.Is(err, store.ErrAuthorityDenied) {
		t.Fatal("bootstrap escaped rollback", err)
	}
	// FailNow exits via Goexit. Exercise that exact defer mechanism with a real
	// acquired connection, without deliberately failing the parent test suite.
	abandoned, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackAuthorityFixture(abandoned)
	released := make(chan struct{})
	go func() { defer close(released); defer rollbackAuthorityFixture(abandoned); runtime.Goexit() }()
	select {
	case <-released:
	case <-ctx.Done():
		t.Fatal("failure-path cleanup did not finish")
	}
	if err := abandoned.Commit(ctx); !errors.Is(err, pgx.ErrTxClosed) {
		t.Fatal("Goexit retained transaction", err)
	}
	if pool.Stat().AcquiredConns() != 0 {
		t.Fatal("failure-path connection not returned")
	}
	scopes := []store.AuthorityScope{scope, {TenantID: "other", PolicyNamespace: "namespace", SubjectID: "subject"}, {TenantID: "tenant", PolicyNamespace: "other", SubjectID: "subject"}, {TenantID: "tenant", PolicyNamespace: "namespace", SubjectID: "other"}}
	for _, s := range scopes {
		tx, err = pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer rollbackAuthorityFixture(tx)
		if got, err := store.InitializeAuthority(ctx, tx, s, time.Second); err != nil || got.Version != 1 {
			t.Fatal("explicit bootstrap failed", err)
		}
		if err = tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
	for _, n := range []uint64{1, math.MaxInt64, math.MaxInt64 + 1, math.MaxUint64 - 1, math.MaxUint64} {
		if _, err = pool.Exec(ctx, `UPDATE authorization_subject_authorities SET version=$1::numeric WHERE tenant_id='tenant' AND policy_namespace='namespace' AND subject_id='subject'`, strconv.FormatUint(n, 10)); err != nil {
			t.Fatal(err)
		}
		if got, err := owner.Get(ctx, scope); err != nil || got.Version != n {
			t.Fatal("unsigned persisted epoch changed", err)
		}
	}
	for _, bad := range []string{"0", "-1", "1.5", "18446744073709551616"} {
		if _, err = pool.Exec(ctx, `UPDATE authorization_subject_authorities SET version=$1::numeric WHERE tenant_id='tenant' AND policy_namespace='namespace' AND subject_id='subject'`, bad); err == nil {
			t.Fatal("invalid epoch persisted")
		}
	}
	if _, err = pool.Exec(ctx, `UPDATE authorization_subject_authorities SET version=$1::numeric WHERE tenant_id='tenant' AND policy_namespace='namespace' AND subject_id='subject'`, strconv.FormatUint(math.MaxUint64-1, 10)); err != nil {
		t.Fatal(err)
	}
	tx, err = pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackAuthorityFixture(tx)
	if got, err := store.AdvanceAuthority(ctx, tx, scope, math.MaxUint64-1, time.Second); err != nil || got.Version != math.MaxUint64 {
		t.Fatal("last successor failed", err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	tx, err = pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackAuthorityFixture(tx)
	if _, err = store.InitializeAuthority(ctx, tx, scope, time.Second); !errors.Is(err, store.ErrAuthorityConflict) {
		t.Fatal("bootstrap reset newer authority", err)
	}
	if _, err = store.AdvanceAuthority(ctx, tx, scope, math.MaxUint64, time.Second); !errors.Is(err, store.ErrAuthorityOverflow) {
		t.Fatal("epoch overflow admitted", err)
	}
	if err = tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if got, err := owner.Get(ctx, scope); err != nil || got.Version != math.MaxUint64 {
		t.Fatal("overflow changed authority", err)
	}
	// A real borrowed transaction retains the admission lock across the protected
	// mutation. NOWAIT gives an independent deterministic lock oracle, no sleeps.
	scope = scopes[1]
	if _, err = pool.Exec(ctx, `CREATE TABLE authority_protected(id int PRIMARY KEY,value int NOT NULL); INSERT INTO authority_protected VALUES(1,0)`); err != nil {
		t.Fatal(err)
	}
	tx, err = pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackAuthorityFixture(tx)
	if err = store.RequireAuthority(ctx, tx, scope, 1, time.Second); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `UPDATE authority_protected SET value=1 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	contender, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackAuthorityFixture(contender)
	_, err = contender.Exec(ctx, `SELECT version FROM authorization_subject_authorities WHERE tenant_id=$1 AND policy_namespace=$2 AND subject_id=$3 FOR UPDATE NOWAIT`, string(scope.TenantID), scope.PolicyNamespace, string(scope.SubjectID))
	var pgerr *pgconn.PgError
	if !errors.As(err, &pgerr) || pgerr.Code != "55P03" {
		t.Fatal("admission lock not retained", err)
	}
	if err = contender.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if err = tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	var protected int
	if err = pool.QueryRow(ctx, `SELECT value FROM authority_protected WHERE id=1`).Scan(&protected); err != nil || protected != 0 {
		t.Fatal("protected mutation escaped rollback", err)
	}
	tx, err = pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackAuthorityFixture(tx)
	if _, err = store.AdvanceAuthority(ctx, tx, scope, 1, time.Second); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `UPDATE authority_protected SET value=2 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if err = tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if got, err := owner.Get(ctx, scope); err != nil || got.Version != 1 {
		t.Fatal("invalidation escaped rollback", err)
	}
	if err = pool.QueryRow(ctx, `SELECT value FROM authority_protected WHERE id=1`).Scan(&protected); err != nil || protected != 0 {
		t.Fatal("coupled mutation escaped rollback", err)
	}
	tx, err = pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackAuthorityFixture(tx)
	if _, err = store.AdvanceAuthority(ctx, tx, scope, 1, time.Second); err != nil {
		t.Fatal(err)
	}
	blocked, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackAuthorityFixture(blocked)
	short, stop := context.WithTimeout(ctx, 20*time.Millisecond)
	err = store.RequireAuthority(short, blocked, scope, 1, time.Second)
	stop()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("lock deadline lost", err)
	}
	_ = blocked.Rollback(ctx) // pgx may close a cancelled connection; no commit claim.
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	tx, err = pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackAuthorityFixture(tx)
	if err = store.RequireAuthority(ctx, tx, scope, 1, time.Second); !errors.Is(err, store.ErrAuthorityDenied) {
		t.Fatal("writer-first stale authority admitted", err)
	}
	if _, err = store.AdvanceAuthority(ctx, tx, scope, 1, time.Second); !errors.Is(err, store.ErrAuthorityConflict) {
		t.Fatal("stale invalidator admitted", err)
	}
	if err = tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	for _, s := range scopes[2:] {
		if got, err := owner.Get(ctx, s); err != nil || got.Version != 1 {
			t.Fatal("unrelated scope changed", err)
		}
	}
	// Both contenders use the same expected epoch. A caller's transaction owns
	// terminalization, and all test goroutines are joined before resource cleanup.
	results := make(chan error, 2)
	start := make(chan struct{})
	var workers sync.WaitGroup
	for range 2 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			borrowed, e := pool.Begin(ctx)
			if e != nil {
				results <- e
				return
			}
			defer rollbackAuthorityFixture(borrowed)
			_, e = store.AdvanceAuthority(ctx, borrowed, scopes[2], 1, time.Second)
			if e == nil {
				e = borrowed.Commit(ctx)
			} else {
				_ = borrowed.Rollback(ctx)
			}
			results <- e
		}()
	}
	close(start)
	workers.Wait()
	close(results)
	winners, conflicts := 0, 0
	for e := range results {
		if e == nil {
			winners++
		} else if errors.Is(e, store.ErrAuthorityConflict) {
			conflicts++
		} else {
			t.Fatal("unexpected CAS result", e)
		}
	}
	if winners != 1 || conflicts != 1 {
		t.Fatal("CAS did not select one winner")
	}
	if got, err := owner.Get(ctx, scopes[2]); err != nil || got.Version != 2 {
		t.Fatal("CAS epoch lost", err)
	}
	if _, err = manifest.Update(ctx, 1, integrationManifest(2)); err != nil {
		t.Fatal("legacy update incompatible", err)
	}
}

// Assert the generic borrowed-row surface accepts the real pgx transaction,
// not only a fake store. Identity Work's narrower row type is also supported.
var _ store.AuthorityQueryer[pgx.Rows] = (pgx.Tx)(nil)

// Capture each exact acquisition immediately, including on assertion/Goexit
// paths. Rollback must run before schema/pool cleanup, with a new finite budget
// independent of an expired test context. Already-terminal transactions are safe.
func rollbackAuthorityFixture(tx pgx.Tx) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = tx.Rollback(ctx)
}
