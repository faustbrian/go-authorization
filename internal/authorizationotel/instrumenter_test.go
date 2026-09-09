package authorizationotel

import (
	"context"
	"errors"
	"testing"
	"time"

	authorization "github.com/faustbrian/go-authorization"
	"go.opentelemetry.io/otel/metric"
	metricnoop "go.opentelemetry.io/otel/metric/noop"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	tracenoop "go.opentelemetry.io/otel/trace/noop"
)

func TestInstrumenterRecordsOneBoundedCompletion(t *testing.T) {
	t.Parallel()
	reader := sdkmetric.NewManualReader()
	meterProvider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	exporter := tracetest.NewInMemoryExporter()
	tracerProvider := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	instrumenter, err := New("test", tracerProvider, meterProvider)
	if err != nil {
		t.Fatal(err)
	}
	ctx, finish := instrumenter.Begin(context.Background())
	finish(authorization.Event{
		Outcome: authorization.Allow, Reason: "allow", Revision: 7,
		MatchedPolicyIDs: []authorization.PolicyID{"one"}, MatchedPolicyIDsTruncated: true,
		TraceCount: 2, TraceTruncated: true, Duration: -time.Second, Failed: true,
	})
	finish(authorization.Event{Outcome: authorization.Deny})
	if ctx == nil || len(exporter.GetSpans()) != 1 {
		t.Fatalf("context/spans = %v/%d", ctx, len(exporter.GetSpans()))
	}
	var metrics metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &metrics); err != nil {
		t.Fatal(err)
	}
	if len(metrics.ScopeMetrics) != 1 || len(metrics.ScopeMetrics[0].Metrics) != 2 {
		t.Fatalf("metrics = %+v", metrics)
	}
}

func TestNewPreservesInstrumentConstructionErrors(t *testing.T) {
	t.Parallel()
	want := errors.New("instrument failed")
	for _, meter := range []*failingMeter{{histogramErr: want}, {counterErr: want}} {
		_, err := New("test", tracenoop.NewTracerProvider(), failingMeterProvider{meter: meter})
		if !errors.Is(err, want) {
			t.Errorf("New() error = %v", err)
		}
	}
}

func TestResultClassifications(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		event authorization.Event
		want  string
	}{
		{event: authorization.Event{Outcome: authorization.Allow}, want: "allow"},
		{event: authorization.Event{Outcome: authorization.Deny}, want: "deny"},
		{event: authorization.Event{Outcome: authorization.NotApplicable}, want: "not-applicable"},
		{event: authorization.Event{Outcome: 99}, want: "error"},
		{event: authorization.Event{Outcome: authorization.Allow, Failed: true}, want: "error"},
	} {
		if got := Result(test.event); got != test.want {
			t.Errorf("Result(%+v) = %q, want %q", test.event, got, test.want)
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
