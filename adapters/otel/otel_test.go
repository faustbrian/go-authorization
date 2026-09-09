package authorizationotel

import (
	"context"
	"errors"
	"testing"

	authorization "github.com/faustbrian/go-authorization"
	"go.opentelemetry.io/otel/metric"
	metricnoop "go.opentelemetry.io/otel/metric/noop"
	"go.opentelemetry.io/otel/trace"
	tracenoop "go.opentelemetry.io/otel/trace/noop"
)

type typedNilTracerProvider struct{ trace.TracerProvider }
type typedNilMeterProvider struct{ metric.MeterProvider }

func TestNewRejectsLiteralAndTypedNilProviders(t *testing.T) {
	t.Parallel()
	tracer := tracenoop.NewTracerProvider()
	meter := metricnoop.NewMeterProvider()
	var typedTracer *typedNilTracerProvider
	var typedMeter *typedNilMeterProvider
	for _, test := range []struct {
		name   string
		config Config
		want   error
	}{
		{name: "literal tracer", config: Config{MeterProvider: meter}, want: ErrNilTracerProvider},
		{name: "typed tracer", config: Config{TracerProvider: typedTracer, MeterProvider: meter}, want: ErrNilTracerProvider},
		{name: "literal meter", config: Config{TracerProvider: tracer}, want: ErrNilMeterProvider},
		{name: "typed meter", config: Config{TracerProvider: tracer, MeterProvider: typedMeter}, want: ErrNilMeterProvider},
	} {
		if _, err := New(test.config); !errors.Is(err, test.want) {
			t.Errorf("%s error = %v, want %v", test.name, err, test.want)
		}
	}
}

func TestBeginAndStartUseExplicitProviders(t *testing.T) {
	t.Parallel()
	instrumenter, err := New(Config{
		TracerProvider: tracenoop.NewTracerProvider(),
		MeterProvider:  metricnoop.NewMeterProvider(),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, finish := instrumenter.Begin(context.Background())
	finish(authorization.Event{Outcome: authorization.Allow})
	if ctx == nil {
		t.Fatal("Begin returned nil context")
	}
	ctx, finish = instrumenter.Start(context.Background())
	finish(authorization.Event{Outcome: authorization.Deny})
	if ctx == nil {
		t.Fatal("Start returned nil context")
	}
}

func TestNewPreservesInstrumentConstructionErrors(t *testing.T) {
	t.Parallel()
	want := errors.New("instrument failed")
	for _, meter := range []*failingMeter{{histogramErr: want}, {counterErr: want}} {
		_, err := New(Config{
			TracerProvider: tracenoop.NewTracerProvider(),
			MeterProvider:  failingMeterProvider{meter: meter},
		})
		if !errors.Is(err, want) {
			t.Errorf("New() error = %v", err)
		}
	}
}

type failingMeterProvider struct {
	metric.MeterProvider
	meter metric.Meter
}

func (provider failingMeterProvider) Meter(string, ...metric.MeterOption) metric.Meter {
	return provider.meter
}

type failingMeter struct {
	metric.Meter
	histogramErr error
	counterErr   error
}

func (meter *failingMeter) Float64Histogram(string, ...metric.Float64HistogramOption) (metric.Float64Histogram, error) {
	if meter.histogramErr != nil {
		return nil, meter.histogramErr
	}
	return metricnoop.NewMeterProvider().Meter("test").Float64Histogram("duration")
}

func (meter *failingMeter) Int64Counter(string, ...metric.Int64CounterOption) (metric.Int64Counter, error) {
	if meter.counterErr != nil {
		return nil, meter.counterErr
	}
	return metricnoop.NewMeterProvider().Meter("test").Int64Counter("decisions")
}
