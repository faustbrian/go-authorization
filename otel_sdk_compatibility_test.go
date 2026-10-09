//nolint:staticcheck // Characterize both supported instrumentation surfaces.
//lint:file-ignore SA1019 Compatibility characterization includes the legacy adapter.
package authorization_test

import (
	"context"
	"math"
	"sync"
	"testing"
	"time"

	authorization "github.com/faustbrian/go-authorization/v3"
	canonical "github.com/faustbrian/go-authorization/v3/adapters/otel"
	legacy "github.com/faustbrian/go-authorization/v3/authotel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

func TestOTelSDKPreservesBoundedCompletionData(t *testing.T) {
	for _, adapter := range []struct {
		scope     string
		construct func(trace.TracerProvider, metric.MeterProvider) (authorization.BeginInstrumenter, error)
	}{
		{"github.com/faustbrian/go-authorization/adapters/otel", func(tracer trace.TracerProvider, meter metric.MeterProvider) (authorization.BeginInstrumenter, error) {
			return canonical.New(canonical.Config{TracerProvider: tracer, MeterProvider: meter})
		}},
		{"github.com/faustbrian/go-authorization/authotel", func(tracer trace.TracerProvider, meter metric.MeterProvider) (authorization.BeginInstrumenter, error) {
			return legacy.New(legacy.Config{TracerProvider: tracer, MeterProvider: meter})
		}},
	} {
		t.Run(adapter.scope, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			reader := sdkmetric.NewManualReader()
			meter := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
			exporter := tracetest.NewInMemoryExporter()
			tracer := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
			defer func() {
				if err := meter.Shutdown(ctx); err != nil {
					t.Error(err)
				}
				if err := tracer.Shutdown(ctx); err != nil {
					t.Error(err)
				}
			}()
			instrumenter, err := adapter.construct(tracer, meter)
			if err != nil {
				t.Fatal(err)
			}
			allowed := authorization.Event{
				Outcome: authorization.Allow, Reason: "allow", Revision: 7, Duration: 5 * time.Millisecond,
				MatchedPolicyIDs:          []authorization.PolicyID{"policy-one", "policy-two"},
				MatchedPolicyIDsTruncated: true, TraceCount: 3, TraceTruncated: true,
			}
			failed := authorization.Event{
				Outcome: authorization.Allow, Reason: "engine-failure", Revision: 9,
				Duration: -time.Second, Failed: true, TraceCount: 1,
			}
			for _, event := range []authorization.Event{allowed, allowed, failed} {
				derived, finish := instrumenter.Begin(ctx)
				if !trace.SpanContextFromContext(derived).IsValid() {
					t.Fatal("Begin did not return a span context")
				}
				finish(event)
				finish(authorization.Event{Outcome: authorization.Deny, Duration: time.Hour})
			}
			spans := exporter.GetSpans()
			if len(spans) != 3 {
				t.Fatalf("completed spans = %d, want 3", len(spans))
			}
			for i, span := range spans {
				wantResult, wantReason, wantRevision := "allow", "allow", "7"
				policyCount, traceCount, truncated := 2, 3, true
				wantStatus := codes.Unset
				if i == 2 {
					wantResult, wantReason, wantRevision = "error", "engine-failure", "9"
					policyCount, traceCount, truncated, wantStatus = 0, 1, false, codes.Error
				}
				want := attribute.NewSet(
					attribute.String("authorization.result", wantResult),
					attribute.String("authorization.reason", wantReason),
					attribute.String("authorization.revision", wantRevision),
					attribute.Int("authorization.matched_policy_count", policyCount),
					attribute.Bool("authorization.matched_policy_ids_truncated", truncated),
					attribute.Int("authorization.trace_count", traceCount),
					attribute.Bool("authorization.trace_truncated", truncated),
				)
				actual := attribute.NewSet(span.Attributes...)
				if span.Name != "authorization.decide" || span.SpanKind != trace.SpanKindInternal || span.InstrumentationScope.Name != adapter.scope || span.Status.Code != wantStatus || !actual.Equals(&want) {
					t.Fatalf("span %d = %+v, want scope=%q attributes=%v status=%v", i, span, adapter.scope, want, wantStatus)
				}
			}
			var destination metricdata.ResourceMetrics
			for range 2 {
				if err := reader.Collect(ctx, &destination); err != nil {
					t.Fatal(err)
				}
				assertOTelCompletionMetrics(t, destination, adapter.scope, 2, .010)
			}
			var joined sync.WaitGroup
			start := make(chan struct{})
			for range 4 {
				joined.Go(func() {
					<-start
					for range 8 {
						_, finish := instrumenter.Begin(ctx)
						event := allowed
						event.Duration = time.Millisecond
						finish(event)
						finish(authorization.Event{Outcome: authorization.Deny, Duration: time.Hour})
					}
				})
			}
			close(start)
			var collectErr error
			for range 4 {
				if err := reader.Collect(ctx, &destination); err != nil {
					collectErr = err
					break
				}
			}
			joined.Wait()
			if collectErr != nil {
				t.Fatal(collectErr)
			}
			if got := len(exporter.GetSpans()); got != 35 {
				t.Fatalf("joined completed spans = %d, want 35", got)
			}
			for range 2 {
				if err := reader.Collect(ctx, &destination); err != nil {
					t.Fatal(err)
				}
				assertOTelCompletionMetrics(t, destination, adapter.scope, 34, .042)
			}
		})
	}
}

func assertOTelCompletionMetrics(t *testing.T, result metricdata.ResourceMetrics, scope string, allowedCount uint64, allowedSum float64) {
	t.Helper()
	if len(result.ScopeMetrics) != 1 || result.ScopeMetrics[0].Scope.Name != scope || len(result.ScopeMetrics[0].Metrics) != 2 {
		t.Fatalf("metric scopes/instruments = %+v", result.ScopeMetrics)
	}
	seenInstruments := make(map[string]bool)
	for _, instrument := range result.ScopeMetrics[0].Metrics {
		if seenInstruments[instrument.Name] {
			t.Fatalf("duplicate instrument %q", instrument.Name)
		}
		seenInstruments[instrument.Name] = true
		seen := make(map[string]bool)
		check := func(attributes attribute.Set, count uint64, sum float64, histogram bool) {
			t.Helper()
			value, present := attributes.Value("authorization.result")
			classification := value.AsString()
			wantCount, wantSum := allowedCount, allowedSum
			if classification == "error" {
				wantCount, wantSum = 1, 0
			}
			if !present || attributes.Len() != 1 || classification != "allow" && classification != "error" || seen[classification] || count != wantCount || histogram && (math.IsNaN(sum) || math.IsInf(sum, 0) || math.Abs(sum-wantSum) > 1e-12) {
				t.Fatalf("%s classification=%q attributes=%v count=%d sum=%g", instrument.Name, classification, attributes, count, sum)
			}
			seen[classification] = true
		}
		switch instrument.Name {
		case "authorization.decision.count":
			data, ok := instrument.Data.(metricdata.Sum[int64])
			if !ok || !data.IsMonotonic || data.Temporality != metricdata.CumulativeTemporality || instrument.Unit != "{decision}" || instrument.Description != "Authorization decisions by bounded result" {
				t.Fatalf("counter = %+v", instrument)
			}
			for _, point := range data.DataPoints {
				if point.Value < 0 {
					t.Fatalf("negative count: %d", point.Value)
				}
				check(point.Attributes, uint64(point.Value), 0, false)
			}
		case "authorization.decision.duration":
			data, ok := instrument.Data.(metricdata.Histogram[float64])
			if !ok || data.Temporality != metricdata.CumulativeTemporality || instrument.Unit != "s" || instrument.Description != "Authorization decision latency" {
				t.Fatalf("histogram = %+v", instrument)
			}
			for _, point := range data.DataPoints {
				var buckets uint64
				for _, count := range point.BucketCounts {
					buckets += count
				}
				if buckets != point.Count {
					t.Fatalf("buckets=%d count=%d", buckets, point.Count)
				}
				check(point.Attributes, point.Count, point.Sum, true)
			}
		default:
			t.Fatalf("unexpected instrument %q", instrument.Name)
		}
		if len(seen) != 2 {
			t.Fatalf("%s series = %v, want allow and error", instrument.Name, seen)
		}
	}
}
