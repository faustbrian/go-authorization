// Package authorizationotel records bounded authorization metrics and traces
// through explicit OpenTelemetry providers.
package authorizationotel

import (
	"context"
	"errors"
	"reflect"

	authorization "github.com/faustbrian/go-authorization"
	internal "github.com/faustbrian/go-authorization/internal/authorizationotel"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
)

const scopeName = "github.com/faustbrian/go-authorization/adapters/otel"

var (
	// ErrNilTracerProvider reports that New received a literal or typed-nil tracer provider.
	ErrNilTracerProvider = errors.New("authorization OpenTelemetry tracer provider is nil")
	// ErrNilMeterProvider reports that New received a literal or typed-nil meter provider.
	ErrNilMeterProvider = errors.New("authorization OpenTelemetry meter provider is nil")
)

// Config provides the caller-owned OpenTelemetry providers used by Instrumenter.
type Config struct {
	// TracerProvider owns span construction and export lifecycle.
	TracerProvider trace.TracerProvider
	// MeterProvider owns metric construction and export lifecycle.
	MeterProvider metric.MeterProvider
}

// Instrumenter records one bounded metric and span observation per Begin call.
// It does not shut down or otherwise take ownership of either provider.
type Instrumenter struct{ instrumenter *internal.Instrumenter }

// New constructs an Instrumenter and rejects literal or typed-nil providers.
func New(config Config) (*Instrumenter, error) {
	if isNil(config.TracerProvider) {
		return nil, ErrNilTracerProvider
	}
	if isNil(config.MeterProvider) {
		return nil, ErrNilMeterProvider
	}
	instrumenter, err := internal.New(scopeName, config.TracerProvider, config.MeterProvider)
	if err != nil {
		return nil, err
	}
	return &Instrumenter{instrumenter: instrumenter}, nil
}

// Begin starts an authorization span and returns an idempotent completion function.
func (instrumenter *Instrumenter) Begin(ctx context.Context) (context.Context, func(authorization.Event)) {
	return instrumenter.instrumenter.Begin(ctx)
}

// Start delegates to Begin for compatibility with authorization.Instrumenter.
func (instrumenter *Instrumenter) Start(ctx context.Context) (context.Context, func(authorization.Event)) {
	return instrumenter.Begin(ctx)
}

func isNil(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

var (
	_ authorization.BeginInstrumenter = (*Instrumenter)(nil)
	_ authorization.Instrumenter      = (*Instrumenter)(nil)
)
