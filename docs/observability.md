# Observability and audit

[Documentation index](README.md) · [Repository entry](../README.md)

`authorization.NewInstrumentedWithBegin` decorates any authorizer through the
context-first `BeginInstrumenter` contract without changing its decision or
error. The released `NewInstrumented` constructor remains available for
`Start`-based implementations. Instrumentation panics and nil derived contexts
are isolated at observation start/finish/clock calls, not authorizer execution
or blocked callbacks. Events contain selected count-bounded decision metadata:
outcome, reason, revision, bounded matched policy IDs, trace counts, duration,
and failure state. There are no dedicated subjects, tenants, resources,
attributes or document fields; reason/ID strings remain caller-controlled, unsanitized and byte-unbounded.

## Structured audit events

`adapters/slog` accepts the standard `*slog.Logger` returned by `log`. The
released `authlog` path remains a deprecated compatibility implementation:

```go
audit, err := authorizationslog.New(logger, slog.LevelInfo)
if err != nil {
    return err
}
authorizer, err := authorization.NewInstrumentedWithBegin(engine, audit,
    authorization.InstrumentationConfig{MaxPolicyIDs: 100})
```

The wrapper invokes completion once after a normal authorizer return; a panic
in the authorizer bypasses completion. The slog callback logs on each direct
invocation, so it is not itself idempotent or a durable delivery guarantee.
Matched policy IDs are
bounded and explicitly marked when truncated. Applications should apply their
normal log access controls because policy identifiers may describe internal
business rules.

## Metrics and traces

`adapters/otel` accepts explicit OpenTelemetry providers, including providers
owned by a `telemetry` runtime. The released `authotel` path remains a
deprecated compatibility implementation and retains its no-op defaults:

```go
instrumenter, err := authorizationotel.New(authorizationotel.Config{
    TracerProvider: telemetryRuntime.TracerProvider(),
    MeterProvider:  telemetryRuntime.MeterProvider(),
})
```

Metrics use only the closed results `allow`, `deny`, `not-applicable`, and
`error`. Subject IDs, policy IDs, reasons, tenants, actions, resources, and
revisions are not metric labels. Spans include bounded counts, reason, and
revision for diagnosis. Providers/exporters and shutdown remain caller-owned.
OTel completion is once-only; an SDK panic before End can leave an unfinished
span without retry. No dedicated request values are included, but reasons remain
application text and direct adapter calls add no wrapper count or byte caps.

Choose the next guide in the [documentation index](README.md)
or return to the [repository entry](../README.md) for installation and ownership.
