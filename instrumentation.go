package authorization

import (
	"context"
	"errors"
	"reflect"
	"time"
)

const defaultMaxInstrumentationPolicyIDs = 100

var (
	// ErrNilAuthorizer identifies authorization instrumented authorizer is nil. Compare with errors.Is, not error text.
	ErrNilAuthorizer = errors.New("authorization instrumented authorizer is nil")
	// ErrNilInstrumenter identifies authorization instrumenter is nil. Compare with errors.Is, not error text.
	ErrNilInstrumenter = errors.New("authorization instrumenter is nil")
	// ErrInvalidInstrumentationConfig identifies authorization instrumentation config is invalid. Compare with errors.Is, not error text.
	ErrInvalidInstrumentationConfig = errors.New("authorization instrumentation config is invalid")
)

// Event contains bounded decision metadata without subject, resource, tenant,
// attribute, or policy-document contents as dedicated fields. Reason and policy
// identifiers are trusted application text, not sanitized or byte-bounded; keep
// them non-secret. Direct adapter callbacks do not enforce this wrapper's caps.
type Event struct {
	// Outcome is Allow, Deny or NotApplicable; Engine validates and default-denies.
	Outcome Outcome
	// Reason is caller/model-defined diagnostic text; it must not contain secrets.
	Reason ReasonCode
	// Revision identifies the declared policy/view generation; it is not an authenticity signature.
	Revision Revision
	// MatchedPolicyIDs preserves match order; count caps do not bound identifier bytes.
	MatchedPolicyIDs []PolicyID
	// MatchedPolicyIDsTruncated signals incomplete identifier diagnostics, not changed outcome.
	MatchedPolicyIDsTruncated bool
	// TraceCount is the observed number of retained trace entries, not every evaluated policy.
	TraceCount int
	// TraceTruncated signals incomplete trace diagnostics.
	TraceTruncated bool
	// Duration is elapsed instrumentation clock time, clamped nonnegative by the wrapper.
	Duration time.Duration
	// Failed reports a non-nil authorizer error; it does not inspect sensitive cause text.
	Failed bool
}

// Instrumenter starts synchronous observation using borrowed context/state.
// Derived contexts must preserve cancellation and metadata obligations; finish
// callbacks may block, so callers must keep them cooperative/concurrency-safe.
type Instrumenter interface {
	// Start returns an optional derived context and completion callback, without owning authorization.
	Start(context.Context) (context.Context, func(Event))
}

// BeginInstrumenter starts one bounded authorization observation.
type BeginInstrumenter interface {
	// Begin returns an optional derived context and completion callback; preserve caller cancellation.
	Begin(context.Context) (context.Context, func(Event))
}

// InstrumentationConfig selects borrowed clock and copied event-ID count
// admission, not total logging/tracing bytes or callback duration.
type InstrumentationConfig struct {
	// Clock is borrowed time policy and must be prompt/concurrency-safe; no lifecycle is owned.
	Clock func() time.Time
	// MaxPolicyIDs caps copied event identifiers; zero selects 100, negative is invalid.
	MaxPolicyIDs int
}

// Instrumented is a borrowed authorizer decorator, constructed by either
// instrumentation constructor; the zero value is unusable and no shutdown is owned.
type Instrumented struct {
	authorizer   Authorizer
	instrumenter Instrumenter
	clock        func() time.Time
	maxPolicyIDs int
}

// NewInstrumented borrows Start-based collaborators and rejects literal nil only.
// Typed-nil behavior differs from NewInstrumentedWithBegin; custom code must be valid.
func NewInstrumented(
	authorizer Authorizer,
	instrumenter Instrumenter,
	config InstrumentationConfig,
) (*Instrumented, error) {
	if authorizer == nil {
		return nil, ErrNilAuthorizer
	}
	if instrumenter == nil {
		return nil, ErrNilInstrumenter
	}
	return newInstrumented(authorizer, instrumenter, config)
}

// NewInstrumentedWithBegin constructs an authorizer using the common Begin
// observation lifecycle. Literal and typed-nil dependencies are rejected
// before any decision work begins. The underlying authorizer/callbacks are
// borrowed. No provider shutdown or export scheduling is owned.
func NewInstrumentedWithBegin(
	authorizer Authorizer,
	instrumenter BeginInstrumenter,
	config InstrumentationConfig,
) (*Instrumented, error) {
	if isNilInterface(authorizer) {
		return nil, ErrNilAuthorizer
	}
	if isNilInterface(instrumenter) {
		return nil, ErrNilInstrumenter
	}
	return newInstrumented(authorizer, beginInstrumenterAdapter{instrumenter: instrumenter}, config)
}

func newInstrumented(
	authorizer Authorizer,
	instrumenter Instrumenter,
	config InstrumentationConfig,
) (*Instrumented, error) {
	if config.MaxPolicyIDs < 0 {
		return nil, ErrInvalidInstrumentationConfig
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	if config.MaxPolicyIDs == 0 {
		config.MaxPolicyIDs = defaultMaxInstrumentationPolicyIDs
	}
	return &Instrumented{
		authorizer: authorizer, instrumenter: instrumenter,
		clock: config.Clock, maxPolicyIDs: config.MaxPolicyIDs,
	}, nil
}

// Decide observes one inline authorizer call without changing its returned
// decision/error. Observation clock/start/finish panics are contained; blocking
// callbacks are not preempted. Authorizer panics bypass normal completion, so an
// observation/span may remain unfinished. Finish gets a copied capped ID slice,
// while the returned decision remains borrowed from the authorizer. A derived
// context may change cancellation; Start/Begin must preserve caller obligations.
func (instrumented *Instrumented) Decide(
	ctx context.Context,
	request Request,
) (Decision, error) {
	started := safeInstrumentationNow(instrumented.clock, time.Time{})
	next, finish := safeInstrumentationStart(instrumented.instrumenter, ctx)
	decision, err := instrumented.authorizer.Decide(next, request)
	finished := safeInstrumentationNow(instrumented.clock, started)
	duration := max(finished.Sub(started), 0)
	matched := decision.MatchedPolicyIDs
	truncated := decision.MatchedPolicyIDsTruncated
	matchedCount := min(len(matched), instrumented.maxPolicyIDs)
	if matchedCount != len(matched) {
		matched = matched[:matchedCount]
		truncated = true
	}
	event := Event{
		Outcome: decision.Outcome, Reason: decision.Reason,
		Revision:                  decision.Revision,
		MatchedPolicyIDs:          append([]PolicyID(nil), matched...),
		MatchedPolicyIDsTruncated: truncated,
		TraceCount:                len(decision.Trace), TraceTruncated: decision.TraceTruncated,
		Duration: duration, Failed: err != nil,
	}
	safeInstrumentationFinish(finish, event)
	return decision, err
}

// Authorizer decides from trusted caller-mapped input. Implementations must
// cooperate with ctx and support concurrent reuse; this seam performs no authentication.
type Authorizer interface {
	// Decide returns a valid outcome or error; map errors to failure, never allow.
	Decide(context.Context, Request) (Decision, error)
}

func safeInstrumentationStart(
	instrumenter Instrumenter,
	ctx context.Context,
) (next context.Context, finish func(Event)) {
	next = ctx
	defer func() {
		if recover() != nil {
			next = ctx
			finish = nil
		}
	}()
	candidate, callback := instrumenter.Start(ctx)
	if candidate != nil {
		next = candidate
	}
	return next, callback
}

type beginInstrumenterAdapter struct{ instrumenter BeginInstrumenter }

func (adapter beginInstrumenterAdapter) Start(ctx context.Context) (context.Context, func(Event)) {
	return adapter.instrumenter.Begin(ctx)
}

func isNilInterface(value any) bool {
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

func safeInstrumentationFinish(finish func(Event), event Event) {
	if finish == nil {
		return
	}
	defer func() { _ = recover() }()
	finish(event)
}

func safeInstrumentationNow(clock func() time.Time, fallback time.Time) (now time.Time) {
	now = fallback
	defer func() { _ = recover() }()
	return clock()
}
