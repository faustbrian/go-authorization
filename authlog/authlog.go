// Package authlog provides the legacy bounded authorization slog adapter.
//
// Deprecated: use github.com/faustbrian/go-authorization/v2/adapters/slog. This
// package remains supported for the longer of 180 days after successor public
// availability and two subsequently published stable root-module minor
// releases.
package authlog

import (
	"context"
	"log/slog"

	authorization "github.com/faustbrian/go-authorization/v2"
	adapter "github.com/faustbrian/go-authorization/v2/adapters/slog"
)

var ErrNilLogger = adapter.ErrNilLogger

type Instrumenter struct {
	logger *slog.Logger
	level  slog.Level
}

func New(logger *slog.Logger, level slog.Level) (*Instrumenter, error) {
	if logger == nil {
		return nil, ErrNilLogger
	}
	return &Instrumenter{logger: logger, level: level}, nil
}

// Begin starts one bounded authorization audit observation.
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

func (instrumenter *Instrumenter) Start(
	ctx context.Context,
) (context.Context, func(authorization.Event)) {
	return instrumenter.Begin(ctx)
}

var (
	_ authorization.BeginInstrumenter = (*Instrumenter)(nil)
	_ authorization.Instrumenter      = (*Instrumenter)(nil)
)
