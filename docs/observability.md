# Observability and audit

`authorization.NewInstrumentedWithBegin` decorates any authorizer through the
context-first `BeginInstrumenter` contract without changing its decision or
error. The released `NewInstrumented` constructor remains available for
`Start`-based instrumenters. Instrumentation panics and nil derived contexts
are isolated from authorization behavior. Events contain bounded decision
metadata only:
outcome, reason, revision, bounded matched policy IDs, trace counts, duration,
and failure state. They never contain subjects, tenants, resources, attributes,
or policy documents.

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

One `authorization decision` record is emitted per call. Matched policy IDs are
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
revision for diagnosis but do not include request or attribute values.
