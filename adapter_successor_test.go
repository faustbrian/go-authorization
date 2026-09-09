//nolint:staticcheck // This compatibility test intentionally exercises deprecated facades.
package authorization_test

//lint:file-ignore SA1019 This compatibility test intentionally exercises deprecated facades.

import (
	"errors"
	"log/slog"
	"reflect"
	"testing"
	"time"

	authorization "github.com/faustbrian/go-authorization"
	authorizationcache "github.com/faustbrian/go-authorization/adapters/cache"
	authorizationhttp "github.com/faustbrian/go-authorization/adapters/http"
	authorizationjsonrpc "github.com/faustbrian/go-authorization/adapters/jsonrpc"
	authorizationotel "github.com/faustbrian/go-authorization/adapters/otel"
	authorizationslog "github.com/faustbrian/go-authorization/adapters/slog"
	legacycache "github.com/faustbrian/go-authorization/authcache"
	legacyhttpa "github.com/faustbrian/go-authorization/authhttp"
	legacylog "github.com/faustbrian/go-authorization/authlog"
	legacyotel "github.com/faustbrian/go-authorization/authotel"
	legacyjsonrpc "github.com/faustbrian/go-authorization/authrpc"
	legacyhttpb "github.com/faustbrian/go-authorization/httpauth"
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
		{legacycache.ManifestCodec{}, "github.com/faustbrian/go-authorization/authcache"},
		{legacycache.RevisionKeyEncoder{}, "github.com/faustbrian/go-authorization/authcache"},
		{legacycache.Config{}, "github.com/faustbrian/go-authorization/authcache"},
		{(*legacyhttpa.Authorizer)(nil), "github.com/faustbrian/go-authorization/httpauth"},
		{legacyhttpa.RequestMapper(nil), "github.com/faustbrian/go-authorization/httpauth"},
		{legacyhttpa.Option(nil), "github.com/faustbrian/go-authorization/httpauth"},
		{(*legacyhttpb.Authorizer)(nil), "github.com/faustbrian/go-authorization/httpauth"},
		{legacyhttpb.RequestMapper(nil), "github.com/faustbrian/go-authorization/httpauth"},
		{legacyhttpb.Option(nil), "github.com/faustbrian/go-authorization/httpauth"},
		{legacylog.Instrumenter{}, "github.com/faustbrian/go-authorization/authlog"},
		{legacyotel.Config{}, "github.com/faustbrian/go-authorization/authotel"},
		{legacyotel.Instrumenter{}, "github.com/faustbrian/go-authorization/authotel"},
		{(*legacyjsonrpc.Authorizer)(nil), "github.com/faustbrian/go-authorization/authrpc"},
		{legacyjsonrpc.RequestMapper(nil), "github.com/faustbrian/go-authorization/authrpc"},
		{legacyjsonrpc.DeniedError(nil), "github.com/faustbrian/go-authorization/authrpc"},
		{legacyjsonrpc.ErrorMapper(nil), "github.com/faustbrian/go-authorization/authrpc"},
		{legacyjsonrpc.Option(nil), "github.com/faustbrian/go-authorization/authrpc"},
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
		{authorizationcache.ManifestCodec{}, "github.com/faustbrian/go-authorization/adapters/cache"},
		{authorizationcache.RevisionKeyEncoder{}, "github.com/faustbrian/go-authorization/adapters/cache"},
		{authorizationcache.Config{}, "github.com/faustbrian/go-authorization/adapters/cache"},
		{(*authorizationhttp.Authorizer)(nil), "github.com/faustbrian/go-authorization/adapters/http"},
		{authorizationhttp.RequestMapper(nil), "github.com/faustbrian/go-authorization/adapters/http"},
		{authorizationhttp.Option(nil), "github.com/faustbrian/go-authorization/adapters/http"},
		{authorizationslog.Instrumenter{}, "github.com/faustbrian/go-authorization/adapters/slog"},
		{authorizationotel.Config{}, "github.com/faustbrian/go-authorization/adapters/otel"},
		{authorizationotel.Instrumenter{}, "github.com/faustbrian/go-authorization/adapters/otel"},
		{(*authorizationjsonrpc.Authorizer)(nil), "github.com/faustbrian/go-authorization/adapters/jsonrpc"},
		{authorizationjsonrpc.RequestMapper(nil), "github.com/faustbrian/go-authorization/adapters/jsonrpc"},
		{authorizationjsonrpc.DeniedError(nil), "github.com/faustbrian/go-authorization/adapters/jsonrpc"},
		{authorizationjsonrpc.ErrorMapper(nil), "github.com/faustbrian/go-authorization/adapters/jsonrpc"},
		{authorizationjsonrpc.Option(nil), "github.com/faustbrian/go-authorization/adapters/jsonrpc"},
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
