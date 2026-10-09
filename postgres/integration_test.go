package postgres_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"sync"
	"testing"
	"time"

	authorization "github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-authorization/v3/policy"
	store "github.com/faustbrian/go-authorization/v3/postgres"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestIntegrationAtomicManifestUpdates(t *testing.T) {
	connectionString := os.Getenv("POSTGRES_URL")
	if connectionString == "" {
		t.Skip("POSTGRES_URL is not configured")
	}
	ctx, cancelTest := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancelTest()
	pool, err := pgxpool.New(ctx, connectionString)
	if err != nil {
		t.Fatalf("pgxpool.New() error = %v", err)
	}
	defer pool.Close()

	migration := store.SchemaMigration()
	_, _ = pool.Exec(ctx, migration.Down)
	if _, err := pool.Exec(ctx, migration.Up); err != nil {
		t.Fatalf("apply migration error = %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), migration.Down) })

	repository, err := store.New(pool)
	if err != nil {
		t.Fatalf("postgres.New() error = %v", err)
	}
	if _, err := repository.Load(ctx); !errors.Is(err, store.ErrNotInitialized) {
		t.Fatalf("initial Load() error = %v, want ErrNotInitialized", err)
	}
	if _, err := repository.Update(ctx, 99, integrationManifest(100)); !errors.Is(err, store.ErrRevisionConflict) {
		t.Fatalf("invalid initialization error = %v, want ErrRevisionConflict", err)
	}

	first := integrationManifest(1)
	stored, err := repository.Update(ctx, 0, first)
	if err != nil || stored.Revision != 1 {
		t.Fatalf("initial Update() = (%+v, %v)", stored, err)
	}
	assertIntegrationManifest(t, stored, first)
	loaded, err := repository.Load(ctx)
	if err != nil || loaded.Revision != 1 {
		t.Fatalf("Load() = (%+v, %v)", loaded, err)
	}

	assertIntegrationManifest(t, loaded, first)
	assertPersistedManifest(t, ctx, pool, first)
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := repository.Update(canceled, 1, integrationManifest(2)); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Update() error = %v, want context.Canceled", err)
	}
	loaded, err = repository.Load(ctx)
	if err != nil || loaded.Revision != 1 {
		t.Fatalf("Load() after canceled update = (%+v, %v), want revision 1", loaded, err)
	}

	assertIntegrationManifest(t, loaded, first)
	type updateResult struct {
		revision authorization.Revision
		err      error
	}
	results := make(chan updateResult, 2)
	var updates sync.WaitGroup
	for revision := authorization.Revision(2); revision <= 3; revision++ {
		updates.Add(1)
		go func() {
			defer updates.Done()
			stored, updateErr := repository.Update(ctx, 1, integrationManifest(revision))
			results <- updateResult{revision: stored.Revision, err: updateErr}
		}()
	}
	updates.Wait()
	close(results)
	successes := 0
	conflicts := 0
	winner := authorization.Revision(0)
	for result := range results {
		switch {
		case result.err == nil:
			successes++
			winner = result.revision
		case errors.Is(result.err, store.ErrRevisionConflict):
			conflicts++
		default:
			t.Fatalf("concurrent Update() error = %v", result.err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("concurrent updates = %d successes, %d conflicts; want 1 each", successes, conflicts)
	}
	loaded, err = repository.Load(ctx)
	if err != nil || loaded.Revision != winner {
		t.Fatalf("Load() after concurrent updates = (%+v, %v), want revision %d", loaded, err, winner)
	}

	assertIntegrationManifest(t, loaded, integrationManifest(winner))
	assertPersistedManifest(t, ctx, pool, integrationManifest(winner))
	victim, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire backend connection: %v", err)
	}
	backendPID := victim.Conn().PgConn().PID()
	var terminated bool
	if err := pool.QueryRow(ctx, "SELECT pg_terminate_backend($1)", backendPID).Scan(&terminated); err != nil {
		victim.Release()
		t.Fatalf("terminate backend: %v", err)
	}
	victim.Release()
	if !terminated {
		t.Fatal("pg_terminate_backend() = false")
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		loaded, err = repository.Load(ctx)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("Load() did not recover after backend termination: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if loaded.Revision != winner {
		t.Fatalf("reconnected Load().Revision = %d, want %d", loaded.Revision, winner)
	}

	assertIntegrationManifest(t, loaded, integrationManifest(winner))
	if _, err := repository.Update(ctx, 0, integrationManifest(2)); !errors.Is(err, store.ErrRevisionConflict) {
		t.Fatalf("conflicting Update() error = %v, want ErrRevisionConflict", err)
	}
	if _, err := repository.Update(ctx, 1, first); !errors.Is(err, store.ErrRevisionNotMonotonic) {
		t.Fatalf("stale Update() error = %v, want ErrRevisionNotMonotonic", err)
	}
}

func integrationManifest(revision authorization.Revision) policy.Manifest {
	return policy.Manifest{
		Format: policy.FormatV1, Revision: revision,
		Algorithm: policy.AlgorithmDenyOverrides,
		Policies: []policy.Record{
			{ID: "documents", Revision: revision, Model: policy.ModelACL,
				Priority: 10, Metadata: map[string]string{"owner": fmt.Sprintf("revision-%d", revision)},
				Document: json.RawMessage(fmt.Sprintf(`{"version":1,"entries":[{"id":"read","subject_kind":"user","subject_id":"user-%d","action":"read","resource_type":"doc","effect":"allow"}]}`, revision))},
			{ID: "roles", Revision: revision + 10, Model: policy.ModelRBAC,
				Priority: 20, Metadata: map[string]string{"owner": "security"},
				Document: json.RawMessage(`{"version":1,"roles":[],"permissions":[],"assignments":[]}`)},
		},
	}
}

func assertIntegrationManifest(t *testing.T, got, want policy.Manifest) {
	t.Helper()
	if got.Format != want.Format || got.Revision != want.Revision || got.Algorithm != want.Algorithm || len(got.Policies) != len(want.Policies) {
		t.Fatalf("manifest envelope = %+v, want %+v", got, want)
	}
	for index, expected := range want.Policies {
		actual := got.Policies[index]
		var actualDocument, expectedDocument any
		if err := json.Unmarshal(actual.Document, &actualDocument); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(expected.Document, &expectedDocument); err != nil {
			t.Fatal(err)
		}
		actual.Document, expected.Document = nil, nil
		if !reflect.DeepEqual(actual, expected) || !reflect.DeepEqual(actualDocument, expectedDocument) {
			t.Fatalf("policy %d or its JSON document changed: got %+v / %v, want %+v / %v", index, actual, actualDocument, expected, expectedDocument)
		}
	}
}

func assertPersistedManifest(t *testing.T, ctx context.Context, pool *pgxpool.Pool, want policy.Manifest) {
	t.Helper()
	var count int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM authorization_policy_manifests").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("persisted manifest row count = %d, want 1", count)
	}
	var revision authorization.Revision
	var encoded []byte
	if err := pool.QueryRow(ctx, "SELECT revision, manifest FROM authorization_policy_manifests WHERE singleton = 1").Scan(&revision, &encoded); err != nil {
		t.Fatal(err)
	}
	var persisted policy.Manifest
	if err := json.Unmarshal(encoded, &persisted); err != nil {
		t.Fatal(err)
	}
	if revision != want.Revision {
		t.Fatalf("persisted revision = %d, want %d", revision, want.Revision)
	}
	assertIntegrationManifest(t, persisted, want)
}
