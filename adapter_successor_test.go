//nolint:staticcheck // This compatibility test intentionally exercises deprecated facades.
package authorization_test

//lint:file-ignore SA1019 This compatibility test intentionally exercises deprecated facades.

import (
	"context"
	"errors"
	"log/slog"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	authorization "github.com/faustbrian/go-authorization/v3"
	authorizationcache "github.com/faustbrian/go-authorization/v3/adapters/cache"
	authorizationhttp "github.com/faustbrian/go-authorization/v3/adapters/http"
	authorizationjsonrpc "github.com/faustbrian/go-authorization/v3/adapters/jsonrpc"
	authorizationotel "github.com/faustbrian/go-authorization/v3/adapters/otel"
	authorizationslog "github.com/faustbrian/go-authorization/v3/adapters/slog"
	legacycache "github.com/faustbrian/go-authorization/v3/authcache"
	legacyhttpa "github.com/faustbrian/go-authorization/v3/authhttp"
	legacylog "github.com/faustbrian/go-authorization/v3/authlog"
	legacyotel "github.com/faustbrian/go-authorization/v3/authotel"
	legacyjsonrpc "github.com/faustbrian/go-authorization/v3/authrpc"
	legacyhttpb "github.com/faustbrian/go-authorization/v3/httpauth"
	"github.com/faustbrian/go-authorization/v3/policy"
	cache "github.com/faustbrian/go-cache/v2"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
)

func TestAdapterSuccessorsPreserveSentinelIdentity(t *testing.T) {
	t.Parallel()

	for _, pair := range [][2]error{
		{legacycache.ErrManifestTooLarge, authorizationcache.ErrManifestTooLarge},
		{legacycache.ErrInvalidRevision, authorizationcache.ErrInvalidRevision},
		{legacycache.ErrNilRepository, authorizationcache.ErrNilRepository},
		{legacyhttpb.ErrNilRequestMapper, authorizationhttp.ErrNilRequestMapper},
		{legacyhttpb.ErrNilNextHandler, authorizationhttp.ErrNilNextHandler},
		{legacylog.ErrNilLogger, authorizationslog.ErrNilLogger},
		{legacyotel.ErrNilTracerProvider, authorizationotel.ErrNilTracerProvider},
		{legacyotel.ErrNilMeterProvider, authorizationotel.ErrNilMeterProvider},
		{legacyjsonrpc.ErrNilAuthorizer, authorizationjsonrpc.ErrNilAuthorizer},
		{legacyjsonrpc.ErrNilRequestMapper, authorizationjsonrpc.ErrNilRequestMapper},
	} {
		if !errors.Is(pair[0], pair[1]) || pair[0] != pair[1] {
			t.Fatalf("sentinel identity differs: %v, %v", pair[0], pair[1])
		}
	}
}

func TestLegacyAdaptersRetainNamedReflectionIdentity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		value any
		path  string
	}{
		{legacycache.ManifestCodec{}, "github.com/faustbrian/go-authorization/v3/authcache"},
		{legacycache.RevisionKeyEncoder{}, "github.com/faustbrian/go-authorization/v3/authcache"},
		{legacycache.Config{}, "github.com/faustbrian/go-authorization/v3/authcache"},
		{(*legacyhttpa.Authorizer)(nil), "github.com/faustbrian/go-authorization/v3/httpauth"},
		{legacyhttpa.RequestMapper(nil), "github.com/faustbrian/go-authorization/v3/httpauth"},
		{legacyhttpa.Option(nil), "github.com/faustbrian/go-authorization/v3/httpauth"},
		{(*legacyhttpb.Authorizer)(nil), "github.com/faustbrian/go-authorization/v3/httpauth"},
		{legacyhttpb.RequestMapper(nil), "github.com/faustbrian/go-authorization/v3/httpauth"},
		{legacyhttpb.Option(nil), "github.com/faustbrian/go-authorization/v3/httpauth"},
		{legacylog.Instrumenter{}, "github.com/faustbrian/go-authorization/v3/authlog"},
		{legacyotel.Config{}, "github.com/faustbrian/go-authorization/v3/authotel"},
		{legacyotel.Instrumenter{}, "github.com/faustbrian/go-authorization/v3/authotel"},
		{(*legacyjsonrpc.Authorizer)(nil), "github.com/faustbrian/go-authorization/v3/authrpc"},
		{legacyjsonrpc.RequestMapper(nil), "github.com/faustbrian/go-authorization/v3/authrpc"},
		{legacyjsonrpc.DeniedError(nil), "github.com/faustbrian/go-authorization/v3/authrpc"},
		{legacyjsonrpc.ErrorMapper(nil), "github.com/faustbrian/go-authorization/v3/authrpc"},
		{legacyjsonrpc.Option(nil), "github.com/faustbrian/go-authorization/v3/authrpc"},
	}
	for _, test := range tests {
		typeOf := reflect.TypeOf(test.value)
		if typeOf.Kind() == reflect.Pointer && typeOf.Elem().Kind() == reflect.Interface {
			typeOf = typeOf.Elem()
		}
		if typeOf.PkgPath() != test.path {
			t.Errorf("%v package = %q, want %q", typeOf, typeOf.PkgPath(), test.path)
		}
	}
}

func TestLegacyInstrumentersRetainReflectionVisibleLayouts(t *testing.T) {
	t.Parallel()

	tests := []struct {
		value  any
		fields []reflect.StructField
	}{
		{
			value: authorization.Instrumented{},
			fields: []reflect.StructField{
				{Name: "authorizer", Type: reflect.TypeOf((*authorization.Authorizer)(nil)).Elem()},
				{Name: "instrumenter", Type: reflect.TypeOf((*authorization.Instrumenter)(nil)).Elem()},
				{Name: "clock", Type: reflect.TypeOf((func() time.Time)(nil))},
				{Name: "maxPolicyIDs", Type: reflect.TypeOf(int(0))},
			},
		},
		{
			value: legacylog.Instrumenter{},
			fields: []reflect.StructField{
				{Name: "logger", Type: reflect.TypeOf((*slog.Logger)(nil))},
				{Name: "level", Type: reflect.TypeOf(slog.Level(0))},
			},
		},
		{
			value: legacyotel.Instrumenter{},
			fields: []reflect.StructField{
				{Name: "tracer", Type: reflect.TypeOf((*trace.Tracer)(nil)).Elem()},
				{Name: "duration", Type: reflect.TypeOf((*metric.Float64Histogram)(nil)).Elem()},
				{Name: "decisions", Type: reflect.TypeOf((*metric.Int64Counter)(nil)).Elem()},
			},
		},
	}
	for _, test := range tests {
		typeOf := reflect.TypeOf(test.value)
		if typeOf.NumField() != len(test.fields) {
			t.Errorf("%v field count = %d, want %d", typeOf, typeOf.NumField(), len(test.fields))
			continue
		}
		for index, want := range test.fields {
			got := typeOf.Field(index)
			if got.Name != want.Name || got.Type != want.Type {
				t.Errorf("%v field %d = %s %v, want %s %v", typeOf, index, got.Name, got.Type, want.Name, want.Type)
			}
		}
	}
}

func TestSuccessorAdaptersExposeTargetOrientedNamedIdentities(t *testing.T) {
	t.Parallel()

	tests := []struct {
		value any
		path  string
	}{
		{authorizationcache.ManifestCodec{}, "github.com/faustbrian/go-authorization/v3/adapters/cache"},
		{authorizationcache.RevisionKeyEncoder{}, "github.com/faustbrian/go-authorization/v3/adapters/cache"},
		{authorizationcache.Config{}, "github.com/faustbrian/go-authorization/v3/adapters/cache"},
		{(*authorizationhttp.Authorizer)(nil), "github.com/faustbrian/go-authorization/v3/adapters/http"},
		{authorizationhttp.RequestMapper(nil), "github.com/faustbrian/go-authorization/v3/adapters/http"},
		{authorizationhttp.Option(nil), "github.com/faustbrian/go-authorization/v3/adapters/http"},
		{authorizationslog.Instrumenter{}, "github.com/faustbrian/go-authorization/v3/adapters/slog"},
		{authorizationotel.Config{}, "github.com/faustbrian/go-authorization/v3/adapters/otel"},
		{authorizationotel.Instrumenter{}, "github.com/faustbrian/go-authorization/v3/adapters/otel"},
		{(*authorizationjsonrpc.Authorizer)(nil), "github.com/faustbrian/go-authorization/v3/adapters/jsonrpc"},
		{authorizationjsonrpc.RequestMapper(nil), "github.com/faustbrian/go-authorization/v3/adapters/jsonrpc"},
		{authorizationjsonrpc.DeniedError(nil), "github.com/faustbrian/go-authorization/v3/adapters/jsonrpc"},
		{authorizationjsonrpc.ErrorMapper(nil), "github.com/faustbrian/go-authorization/v3/adapters/jsonrpc"},
		{authorizationjsonrpc.Option(nil), "github.com/faustbrian/go-authorization/v3/adapters/jsonrpc"},
	}
	for _, test := range tests {
		typeOf := reflect.TypeOf(test.value)
		if typeOf.Kind() == reflect.Pointer && typeOf.Elem().Kind() == reflect.Interface {
			typeOf = typeOf.Elem()
		}
		if typeOf.PkgPath() != test.path {
			t.Errorf("%v package = %q, want %q", typeOf, typeOf.PkgPath(), test.path)
		}
	}
}

type manifestCache = cache.Cache[authorization.Revision, policy.Manifest]

func cacheConstructors() map[string]func(cache.Backend) (*manifestCache, error) {
	return map[string]func(cache.Backend) (*manifestCache, error){
		"canonical": func(backend cache.Backend) (*manifestCache, error) {
			return authorizationcache.New(authorizationcache.Config{
				Namespace: "adoption", Backend: backend, Clock: cache.SystemClock{},
				TTL: cache.TTLPolicy{TTL: time.Minute},
			})
		},
		"legacy": func(backend cache.Backend) (*manifestCache, error) {
			return legacycache.New(legacycache.Config{
				Namespace: "adoption", Backend: backend, Clock: cache.SystemClock{},
				TTL: cache.TTLPolicy{TTL: time.Minute},
			})
		},
	}
}

// cancellationAfterMiss models cancellation arriving after a backend has
// completed its miss lookup, rather than before the operation is admitted.
type cancellationAfterMiss struct{}
type lookupAfterMiss struct{}

type missBackend struct{}

func (missBackend) Get(ctx context.Context, _ string) (cache.Record, bool, error) {
	if cancel, ok := ctx.Value(cancellationAfterMiss{}).(context.CancelFunc); ok {
		cancel()
	}
	if completed, ok := ctx.Value(lookupAfterMiss{}).(func()); ok {
		completed()
	}
	return cache.Record{}, false, nil
}

func (missBackend) Set(context.Context, string, cache.Record, cache.Condition) (bool, error) {
	return true, nil
}

func (missBackend) Delete(context.Context, string) (bool, error) { return true, nil }

func TestManifestCacheBoundsCanceledDistinctKeyFlights(t *testing.T) {
	for name, construct := range cacheConstructors() {
		t.Run(name, func(t *testing.T) {
			store, err := construct(missBackend{})
			if err != nil {
				t.Fatal(err)
			}
			release := make(chan struct{})
			var releaseOnce sync.Once
			t.Cleanup(func() {
				releaseOnce.Do(func() { close(release) })
				if err := store.Close(); err != nil {
					t.Errorf("join released loads: %v", err)
				}
			})
			loader := func(context.Context, authorization.Revision) (cache.LoadResult[policy.Manifest], error) {
				<-release
				return cache.LoadResult[policy.Manifest]{}, nil
			}
			for revision := authorization.Revision(1); revision <= 1024; revision++ {
				ctx, cancel := context.WithCancel(context.Background())
				ctx = context.WithValue(ctx, cancellationAfterMiss{}, cancel)
				_, err := store.GetOrLoad(ctx, revision, loader)
				cancel()
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("admitted revision %d: %v", revision, err)
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			_, err = store.GetOrLoad(ctx, 1025, loader)
			if !errors.Is(err, cache.ErrFlightLimit) {
				t.Fatalf("new distinct key must reject retained-flight saturation, got %v", err)
			}
			lookupCompleted := make(chan struct{})
			follower, cancelFollower := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancelFollower()
			follower = context.WithValue(follower, lookupAfterMiss{}, func() { close(lookupCompleted) })
			_, followerErr := store.GetOrLoad(follower, 1, loader)
			select {
			case <-lookupCompleted:
			default:
				t.Fatal("follower expired before its live backend lookup")
			}
			if !errors.Is(followerErr, context.DeadlineExceeded) || errors.Is(followerErr, cache.ErrFlightLimit) {
				t.Fatalf("live existing-key follower must join retained work without another flight: %v", followerErr)
			}
		})
	}
}

func TestManifestCacheProtectsRepositoryDiagnostics(t *testing.T) {
	for name, construct := range cacheConstructors() {
		t.Run(name, func(t *testing.T) {
			store, err := construct(missBackend{})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := store.Close(); err != nil {
					t.Error(err)
				}
			})
			source := errors.New("private-repository-diagnostic")
			_, err = store.GetOrLoad(context.Background(), 1,
				func(context.Context, authorization.Revision) (cache.LoadResult[policy.Manifest], error) {
					return cache.LoadResult[policy.Manifest]{}, source
				})
			if !errors.Is(err, source) || !errors.Is(err, cache.ErrLoader) {
				t.Fatalf("loader identity must remain classifiable: %v", err)
			}
			if strings.Contains(err.Error(), source.Error()) {
				t.Fatalf("public cache error exposes repository diagnostic: %v", err)
			}
		})
	}
}

func TestManifestCacheCloseBoundsNonCooperativeRepository(t *testing.T) {
	for name, construct := range cacheConstructors() {
		t.Run(name, func(t *testing.T) {
			store, err := construct(missBackend{})
			if err != nil {
				t.Fatal(err)
			}
			started, release := make(chan struct{}), make(chan struct{})
			loaded := make(chan struct{})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			go func() {
				defer close(loaded)
				_, _ = store.GetOrLoad(ctx, 1,
					func(context.Context, authorization.Revision) (cache.LoadResult[policy.Manifest], error) {
						close(started)
						<-release
						return cache.LoadResult[policy.Manifest]{}, nil
					})
			}()
			select {
			case <-started:
			case <-time.After(5 * time.Second):
				close(release)
				t.Fatal("repository load did not start")
			}
			cancel()
			closed := make(chan error, 1)
			go func() { closed <- store.Close() }()
			select {
			case err := <-closed:
				if !errors.Is(err, cache.ErrShutdownIncomplete) {
					t.Errorf("incomplete close must classify active repository work: %v", err)
				}
			case <-time.After(8 * time.Second):
				t.Error("Close did not return within the bounded lifecycle interval")
			}
			if _, err := store.Get(context.Background(), 2); !errors.Is(err, cache.ErrClosed) {
				t.Errorf("incomplete close must reject new work: %v", err)
			}
			close(release)
			select {
			case <-loaded:
			case <-time.After(5 * time.Second):
				t.Fatal("released caller did not finish")
			}
			if err := store.Close(); err != nil {
				t.Fatalf("released repository must permit successful final join: %v", err)
			}
		})
	}
}

func TestManifestCacheShutdownPropagatesCancellationAndJoins(t *testing.T) {
	for name, construct := range cacheConstructors() {
		t.Run(name, func(t *testing.T) {
			store, err := construct(missBackend{})
			if err != nil {
				t.Fatal(err)
			}
			release := make(chan struct{})
			var releaseOnce sync.Once
			t.Cleanup(func() {
				releaseOnce.Do(func() { close(release) })
				if err := store.Close(); err != nil {
					t.Errorf("released work did not join: %v", err)
				}
			})
			loaderContext := make(chan context.Context, 1)
			callerDone := make(chan error, 1)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			go func() {
				_, err := store.GetOrLoad(ctx, 1,
					func(ctx context.Context, _ authorization.Revision) (cache.LoadResult[policy.Manifest], error) {
						loaderContext <- ctx
						<-release
						return cache.LoadResult[policy.Manifest]{}, nil
					})
				callerDone <- err
			}()
			var loadCtx context.Context
			select {
			case loadCtx = <-loaderContext:
			case <-time.After(5 * time.Second):
				t.Fatal("repository load did not start")
			}
			cancel()
			select {
			case err := <-callerDone:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("canceled caller: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("caller did not detach")
			}
			if loadCtx.Err() != nil {
				t.Fatal("caller cancellation must not cancel the retained shared load")
			}
			shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), 40*time.Millisecond)
			defer cancelShutdown()
			if err := store.Shutdown(shutdownCtx); !errors.Is(err, cache.ErrShutdownIncomplete) ||
				!errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("bounded incomplete shutdown: %v", err)
			}
			if !errors.Is(loadCtx.Err(), context.Canceled) {
				t.Fatalf("shutdown must propagate loader cancellation: %v", loadCtx.Err())
			}
			releaseOnce.Do(func() { close(release) })
			joinCtx, cancelJoin := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancelJoin()
			if err := store.Shutdown(joinCtx); err != nil {
				t.Fatalf("released loader must join successfully: %v", err)
			}
		})
	}
}
