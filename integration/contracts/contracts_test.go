package contracts_test

import (
	"context"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	authentication "github.com/faustbrian/go-authentication"
	authorization "github.com/faustbrian/go-authorization/v3"
	authorizationcache "github.com/faustbrian/go-authorization/v3/adapters/cache"
	authorizationotel "github.com/faustbrian/go-authorization/v3/adapters/otel"
	authorizationslog "github.com/faustbrian/go-authorization/v3/adapters/slog"
	"github.com/faustbrian/go-authorization/v3/authn"
	"github.com/faustbrian/go-authorization/v3/policy"
	cache "github.com/faustbrian/go-cache/v2"
	memory "github.com/faustbrian/go-cache/v2/adapters/memory"
	log "github.com/faustbrian/go-log"
	"github.com/faustbrian/go-log/handler/capture"
	"github.com/faustbrian/go-telemetry/testtelemetry"
)

func TestPublishedManifestCacheLoadsThenHits(t *testing.T) {
	t.Parallel()
	clock := cache.SystemClock{}
	backend, err := memory.New(memory.Config{MaxEntries: 2, MaxBytes: 1 << 20, Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	store, err := authorizationcache.New(authorizationcache.Config{
		Namespace: "contracts", Backend: backend, Clock: clock,
		TTL: cache.TTLPolicy{TTL: time.Minute},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := store.Shutdown(ctx); err != nil {
			t.Error(err)
		}
	})
	manifest := policy.Manifest{
		Format: policy.FormatV1, Revision: 7, Algorithm: policy.AlgorithmDenyOverrides,
		Policies: []policy.Record{},
	}
	var calls atomic.Int32
	loader := func(context.Context, authorization.Revision) (cache.LoadResult[policy.Manifest], error) {
		calls.Add(1)
		return cache.LoadResult[policy.Manifest]{Value: manifest, Found: true}, nil
	}
	for attempt := 0; attempt < 2; attempt++ {
		result, err := store.GetOrLoad(context.Background(), manifest.Revision, loader)
		if err != nil || result.State != cache.Hit || result.Value.Revision != manifest.Revision ||
			result.Value.Format != manifest.Format || result.Value.Algorithm != manifest.Algorithm {
			t.Fatalf("load/hit attempt %d = (%+v, %v)", attempt, result, err)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("loader calls = %d, want one load followed by a stored hit", got)
	}
}

func TestOwnedModuleInteroperability(t *testing.T) {
	t.Parallel()

	principal, err := authentication.NewPrincipal(authentication.PrincipalSpec{
		Subject: "alice",
		Method:  "oidc",
		Claims: map[string]any{
			"department": "finance",
			"groups":     []string{"reviewers"},
			"labels":     []string{"audited", "trusted"},
		},
	})
	if err != nil {
		t.Fatalf("authentication.NewPrincipal() error = %v", err)
	}
	subject, err := authn.Subject(principal, authn.Config{
		Kind:        authorization.SubjectUser,
		GroupsClaim: "groups",
		AttributeClaims: map[authorization.AttributeName]string{
			"department": "department",
			"labels":     "labels",
		},
	})
	if err != nil {
		t.Fatalf("authn.Subject() error = %v", err)
	}
	if subject.ID != "alice" || len(subject.Groups) != 1 ||
		subject.Groups[0] != "reviewers" {
		t.Fatalf("mapped subject = %+v", subject)
	}
	labels, ok := subject.Attributes["labels"].StringSet()
	if !ok || len(labels) != 2 || labels[0] != "audited" {
		t.Fatalf("mapped labels = %v, %v", labels, ok)
	}

	handler := capture.New()
	logger, err := log.New(handler)
	if err != nil {
		t.Fatalf("log.New() error = %v", err)
	}
	logInstrumenter, err := authorizationslog.New(logger, slog.LevelInfo)
	if err != nil {
		t.Fatalf("authorizationslog.New() error = %v", err)
	}
	_, finishLog := logInstrumenter.Start(context.Background())
	finishLog(authorization.Event{Outcome: authorization.Allow, Revision: 1})
	if handler.Len() != 1 {
		t.Fatalf("captured audit events = %d, want 1", handler.Len())
	}

	telemetry := testtelemetry.New()
	t.Cleanup(func() {
		if err := telemetry.Shutdown(context.Background()); err != nil {
			t.Errorf("telemetry.Shutdown() error = %v", err)
		}
	})
	telemetryInstrumenter, err := authorizationotel.New(authorizationotel.Config{
		TracerProvider: telemetry.TracerProvider(),
		MeterProvider:  telemetry.MeterProvider(),
	})
	if err != nil {
		t.Fatalf("authorizationotel.New() error = %v", err)
	}
	_, finishTelemetry := telemetryInstrumenter.Start(context.Background())
	finishTelemetry(authorization.Event{Outcome: authorization.Allow, Revision: 1})
	if len(telemetry.Spans()) != 1 {
		t.Fatalf("recorded authorization spans = %d, want 1", len(telemetry.Spans()))
	}
	if _, err := telemetry.Metrics(context.Background()); err != nil {
		t.Fatalf("telemetry.Metrics() error = %v", err)
	}
}
