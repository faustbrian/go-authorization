// Package authorizationslog emits authorization audit events through
// log/slog. New borrows a logger/handler and owns no sink shutdown or delivery
// persistence. Begin/finish run inline; finish is repeatable, not idempotent.
// Event count caps are enforced by the outer Instrumented wrapper, not direct
// callbacks. IDs/reasons are application text and must remain non-secret.
package authorizationslog

import (
	"context"
	"errors"
	"log/slog"

	authorization "github.com/faustbrian/go-authorization/v4"
)

// ErrNilLogger reports that New received no logger.
var ErrNilLogger = errors.New("authorization audit logger is nil")

// Instrumenter emits a structured audit record on each completion invocation.
// The caller retains ownership of the logger and its handler.
type Instrumenter struct {
	logger *slog.Logger
	level  slog.Level
}

// New constructs an audit Instrumenter at level and rejects a nil logger.
func New(logger *slog.Logger, level slog.Level) (*Instrumenter, error) {
	if logger == nil {
		return nil, ErrNilLogger
	}
	return &Instrumenter{logger: logger, level: level}, nil
}

// Begin returns the same context and a callback that logs on every invocation.
// No direct event cap, panic containment or exactly-once/durable delivery is added.
// The logger/handler controls blocking, enabled levels and concurrent reuse.
func (instrumenter *Instrumenter) Begin(
	ctx context.Context,
) (context.Context, func(authorization.Event)) {
	return ctx, func(event authorization.Event) {
		instrumenter.logger.LogAttrs(ctx, instrumenter.level, "authorization decision",
			slog.String("outcome", event.Outcome.String()),
			slog.String("reason", string(event.Reason)),
			slog.Uint64("revision", uint64(event.Revision)),
			slog.Any("matched_policy_ids", event.MatchedPolicyIDs),
			slog.Bool("matched_policy_ids_truncated", event.MatchedPolicyIDsTruncated),
			slog.Int("trace_count", event.TraceCount),
			slog.Bool("trace_truncated", event.TraceTruncated),
			slog.Float64("duration_ms", float64(event.Duration.Microseconds())/1000),
			slog.Bool("failed", event.Failed),
		)
	}
}

// Start delegates to Begin for compatibility with authorization.Instrumenter.
func (instrumenter *Instrumenter) Start(
	ctx context.Context,
) (context.Context, func(authorization.Event)) {
	return instrumenter.Begin(ctx)
}

var (
	_ authorization.BeginInstrumenter = (*Instrumenter)(nil)
	_ authorization.Instrumenter      = (*Instrumenter)(nil)
)
