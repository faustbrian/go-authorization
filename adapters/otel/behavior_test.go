package authorizationotel

import (
	"context"
	"testing"
	"time"

	authorization "github.com/faustbrian/go-authorization/v4"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

func TestInstrumenterRecordsBoundedMetricsAndSpan(t *testing.T) {
	t.Parallel()

	reader := sdkmetric.NewManualReader()
	meterProvider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	exporter := tracetest.NewInMemoryExporter()
	tracerProvider := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	instrumenter, err := New(Config{MeterProvider: meterProvider, TracerProvider: tracerProvider})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	ctx, finish := instrumenter.Begin(context.Background())
	finish(authorization.Event{
		Outcome: authorization.Allow, Reason: "acl-allow", Revision: 7,
		MatchedPolicyIDs: []authorization.PolicyID{"one"}, TraceCount: 2,
		Duration: 5 * time.Millisecond,
	})
	finish(authorization.Event{Outcome: authorization.Deny})
	if !trace.SpanContextFromContext(ctx).IsValid() {
		t.Error("Begin() did not return span context")
	}

	var metrics metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &metrics); err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	names := map[string]bool{}
	for _, scope := range metrics.ScopeMetrics {
		for _, value := range scope.Metrics {
			names[value.Name] = true
		}
	}
	if !names["authorization.decision.count"] || !names["authorization.decision.duration"] {
		t.Errorf("metric names = %v", names)
	}
	spans := exporter.GetSpans()
	if len(spans) != 1 || spans[0].Name != "authorization.decide" {
		t.Fatalf("spans = %+v", spans)
	}
	if _, finish := instrumenter.Start(context.Background()); finish == nil {
		t.Fatal("Start() did not delegate to Begin()")
	}
}
