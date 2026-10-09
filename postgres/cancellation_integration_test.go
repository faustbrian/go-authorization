package postgres_test

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	store "github.com/faustbrian/go-authorization/v3/postgres"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestIntegrationCanceledBlockedUpdateReleasesConnection(t *testing.T) {
	connectionString := os.Getenv("POSTGRES_URL")
	if connectionString == "" {
		t.Skip("POSTGRES_URL is not configured")
	}
	ctx, cancelTest := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancelTest()
	observer, err := pgxpool.New(ctx, connectionString)
	if err != nil {
		t.Fatal(err)
	}
	defer observer.Close()
	migration := store.SchemaMigration()
	if _, err := observer.Exec(ctx, "DROP TABLE IF EXISTS authorization_policy_manifests"); err != nil {
		t.Fatal(err)
	}
	if _, err := observer.Exec(ctx, migration.Up); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := observer.Exec(ctx, migration.Down); err != nil {
			t.Error(err)
		}
	}()
	config, err := pgxpool.ParseConfig(connectionString)
	if err != nil {
		t.Fatal(err)
	}
	config.MaxConns = 1
	config.ConnConfig.RuntimeParams["application_name"] = "authorization-canceled-update"
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	repository, err := store.New(pool)
	if err != nil {
		t.Fatal(err)
	}
	first := integrationManifest(1)
	if _, err := repository.Update(ctx, 0, first); err != nil {
		t.Fatal(err)
	}
	blocker, err := observer.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = blocker.Rollback(ctx) }()
	if _, err := blocker.Exec(ctx, "SELECT singleton FROM authorization_policy_manifests WHERE singleton = 1 FOR UPDATE"); err != nil {
		t.Fatal(err)
	}
	writeCtx, cancelWrite := context.WithCancel(ctx)
	defer cancelWrite()
	done := make(chan error, 1)
	go func() {
		_, updateErr := repository.Update(writeCtx, 1, integrationManifest(2))
		done <- updateErr
	}()
	// Observe a server-side lock wait: pre-cancellation alone does not reach
	// pgconn's in-flight cancellation and socket cleanup path.
	deadline := time.Now().Add(5 * time.Second)
	for {
		var waiting bool
		err := observer.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE application_name = $1 AND state = 'active' AND wait_event_type = 'Lock')", "authorization-canceled-update").Scan(&waiting)
		if err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("update did not enter the independently observed row-lock wait")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancelWrite()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("blocked Update() error = %v, want context.Canceled", err)
		}
	case <-ctx.Done():
		t.Fatal("canceled update did not return within the test deadline")
	}
	assertPersistedManifest(t, ctx, observer, first)
	if err := blocker.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	loaded, err := repository.Load(ctx)
	if err != nil {
		t.Fatalf("Load() after canceled blocked update: %v", err)
	}
	assertIntegrationManifest(t, loaded, first)
	if acquired := pool.Stat().AcquiredConns(); acquired != 0 {
		t.Fatalf("acquired pool connections after Load() = %d, want 0", acquired)
	}
	if err := pool.Ping(ctx); err != nil {
		t.Fatalf("caller-owned pool cannot be reused: %v", err)
	}
}
