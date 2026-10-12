// Package authorization evaluates caller-mapped identities, actions, resources
// and facts against explicit policy snapshots. NewSnapshot/NewEngine establish
// coherent low-level evaluation; ACL, RBAC and ABAC provide local models, while
// policy owns portable manifests and optional synchronization. Engine converts
// no-match to deny; standalone models may return NotApplicable.
//
// Authentication, tenant membership, attribute authority, policy administration
// and resource fetching belong to the application. Requests and evaluators are
// borrowed, not deep-copied or sandboxed; collaborators must remain immutable,
// concurrency-safe and cooperative. No watcher or background worker is started
// by the core. Optional adapters introduce their own borrowed backend/SDK seams.
// Diagnostic count caps do not sanitize or bound arbitrary identifier strings.
package authorization

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// ErrNilSnapshot identifies authorization snapshot is nil. Compare with errors.Is, not error text.
var ErrNilSnapshot = errors.New("authorization snapshot is nil")

// ErrBatchLimitExceeded identifies authorization batch limit exceeded. Compare with errors.Is, not error text.
var ErrBatchLimitExceeded = errors.New("authorization batch limit exceeded")

// ErrPolicyLimitExceeded identifies authorization policy limit exceeded. Compare with errors.Is, not error text.
var ErrPolicyLimitExceeded = errors.New("authorization policy limit exceeded")

// ErrPolicyPanic identifies authorization policy panicked. Compare with errors.Is, not error text.
var ErrPolicyPanic = errors.New("authorization policy panicked")

var (
	// ErrRevisionConflict identifies authorization revision conflict. Compare with errors.Is, not error text.
	ErrRevisionConflict = errors.New("authorization revision conflict")
	// ErrRevisionNotMonotonic identifies authorization revision is not monotonic. Compare with errors.Is, not error text.
	ErrRevisionNotMonotonic = errors.New("authorization revision is not monotonic")
)

const (
	defaultMaxBatchSize        = 1000
	defaultMaxPolicies         = 1000
	defaultMaxTraceSize        = 100
	defaultMaxMatchedPolicyIDs = 100
)

// Limits bounds work and diagnostic cardinality for one engine.
type Limits struct {
	// MaxBatchSize admits request count before result allocation; default is 1000.
	MaxBatchSize int
	// MaxPolicies admits policy count; default is 1000, not a total byte budget.
	MaxPolicies int
	// MaxTraceSize caps trace entry count; default is 100.
	MaxTraceSize int
	// MaxMatchedPolicyIDs caps accumulated identifier count; default is 100.
	MaxMatchedPolicyIDs int
}

// EngineOption configures construction synchronously; custom/nil options are trusted and may panic.
type EngineOption func(*Engine)

// WithLimits configures positive limits and leaves zero-valued fields at safe
// defaults; negative as well as zero fields are ignored.
func WithLimits(limits Limits) EngineOption {
	return func(engine *Engine) {
		if limits.MaxBatchSize > 0 {
			engine.limits.MaxBatchSize = limits.MaxBatchSize
		}
		if limits.MaxPolicies > 0 {
			engine.limits.MaxPolicies = limits.MaxPolicies
		}
		if limits.MaxTraceSize > 0 {
			engine.limits.MaxTraceSize = limits.MaxTraceSize
		}
		if limits.MaxMatchedPolicyIDs > 0 {
			engine.limits.MaxMatchedPolicyIDs = limits.MaxMatchedPolicyIDs
		}
	}
}

// WithClock supplies time when a request omits Environment.Time; nil is ignored.
// The borrowed clock runs inline, must be concurrency-safe/prompt and must not
// panic. Clock failures are not inside evaluator panic recovery.
func WithClock(clock func() time.Time) EngineOption {
	return func(engine *Engine) {
		if clock != nil {
			engine.clock = clock
		}
	}
}

// PolicyEvaluationError identifies a failed policy without exposing its
// internal error text. Unwrap retains programmatic error inspection.
type PolicyEvaluationError struct {
	// PolicyID is the exact non-secret policy diagnostic identity.
	PolicyID PolicyID
	// Err is a borrowed error cause; deliberate unwrapping/fixture use can expose its text/type.
	Err error
}

// Error prints the trusted policy ID, not the evaluator cause text.
func (evaluationError *PolicyEvaluationError) Error() string {
	return fmt.Sprintf("policy %q evaluation failed", evaluationError.PolicyID)
}

// Unwrap exposes the original evaluator cause; protect deliberate inspection/logging.
func (evaluationError *PolicyEvaluationError) Unwrap() error {
	return evaluationError.Err
}

// Engine evaluates each request/batch against one captured snapshot and permits
// concurrent Decide/ReplaceSnapshot calls. Evaluators, clocks and input graphs
// must support that reuse; only publication/state replacement is synchronized.
// Construct with NewEngine; the zero Engine is unusable. No goroutine, timer,
// source refresh or evaluator shutdown is owned.
type Engine struct {
	snapshot  atomic.Pointer[Snapshot]
	limits    Limits
	clock     func() time.Time
	replaceMu sync.Mutex
}

// NewEngine borrows a non-nil snapshot, applies options synchronously and checks
// the selected policy count cap. A non-nil but unvalidated zero Snapshot is not
// rejected here. Nil/custom options can panic and must not retain mutable Engine
// access for later changes. Default limits are 1000 requests/policies and
// 100 trace/matched IDs; count caps do not bound strings or collaborator work.
func NewEngine(snapshot *Snapshot, options ...EngineOption) (*Engine, error) {
	if snapshot == nil {
		return nil, ErrNilSnapshot
	}

	engine := &Engine{
		clock: time.Now,
		limits: Limits{
			MaxBatchSize:        defaultMaxBatchSize,
			MaxPolicies:         defaultMaxPolicies,
			MaxTraceSize:        defaultMaxTraceSize,
			MaxMatchedPolicyIDs: defaultMaxMatchedPolicyIDs,
		},
	}

	for _, option := range options {
		option(engine)
	}
	if len(snapshot.policies) > engine.limits.MaxPolicies {
		return nil, ErrPolicyLimitExceeded
	}
	engine.snapshot.Store(snapshot)

	return engine, nil
}

// Decide validates required request strings, captures one snapshot, then evaluates
// active policies until the combining algorithm is decisive. No-match becomes deny.
// Activation time uses supplied Environment.Time or one clock sample. Errors/panics
// in evaluators deny, but raw error causes remain inspectable. Context checks occur
// before each policy, not after a final successful callback; callbacks are cooperative.
// Request maps/groups are borrowed; ctx and receiver must be usable/non-nil.
func (engine *Engine) Decide(ctx context.Context, request Request) (Decision, error) {
	return engine.decide(ctx, request, engine.snapshot.Load())
}

// Revision returns the revision of the snapshot currently used for new
// decisions.
func (engine *Engine) Revision() Revision {
	return engine.snapshot.Load().revision
}

// ReplaceSnapshot atomically installs a newer snapshot when the caller's
// expected revision still matches the active view. The local replacement mutex
// serializes the revision check/store; existing calls finish on the old snapshot.
// This does not persist policy, invalidate other processes or close old evaluators.
func (engine *Engine) ReplaceSnapshot(next *Snapshot, expected Revision) error {
	if next == nil {
		return ErrNilSnapshot
	}
	if len(next.policies) > engine.limits.MaxPolicies {
		return ErrPolicyLimitExceeded
	}

	// Pair the expectation check with publication: a separate load/store would
	// allow two writers to both accept the same revision (see concurrency tests).
	engine.replaceMu.Lock()
	defer engine.replaceMu.Unlock()

	current := engine.snapshot.Load()
	if current.revision != expected {
		return ErrRevisionConflict
	}

	if next.revision <= current.revision {
		return ErrRevisionNotMonotonic
	}

	engine.snapshot.Store(next)

	return nil
}

// DecideBatch evaluates in input order against one captured snapshot. Oversize
// input returns nil before allocation/evaluation. Otherwise every request gets a
// result and failures are joined; later requests still run, including after
// cancellation (their owned checks may deny). Request graphs remain borrowed,
// callback effects are not transactional, and an empty batch performs no ctx check.
func (engine *Engine) DecideBatch(
	ctx context.Context,
	requests []Request,
) ([]Decision, error) {
	if len(requests) > engine.limits.MaxBatchSize {
		return nil, ErrBatchLimitExceeded
	}

	snapshot := engine.snapshot.Load()
	decisions := make([]Decision, len(requests))
	errorsByRequest := make([]error, 0)

	for index, request := range requests {
		decision, err := engine.decide(ctx, request, snapshot)
		decisions[index] = decision
		if err != nil {
			errorsByRequest = append(errorsByRequest, err)
		}
	}

	return decisions, errors.Join(errorsByRequest...)
}

func (engine *Engine) decide(
	ctx context.Context,
	request Request,
	snapshot *Snapshot,
) (Decision, error) {
	if err := request.Validate(); err != nil {
		return Decision{
			Outcome:  Deny,
			Reason:   ReasonInvalidRequest,
			Revision: snapshot.revision,
		}, err
	}
	if err := ctx.Err(); err != nil {
		return Decision{
			Outcome:  Deny,
			Reason:   ReasonContextCanceled,
			Revision: snapshot.revision,
		}, err
	}

	decisions := make([]Decision, 0, len(snapshot.policies))
	matchedPolicyIDs := make([]PolicyID, 0, len(snapshot.policies))
	matchedPolicyIDsTruncated := false
	traceCapacity := min(len(snapshot.policies), engine.limits.MaxTraceSize)
	trace := make([]TraceEntry, 0, traceCapacity)
	traceTruncated := false
	evaluationTime := request.Environment.Time
	if evaluationTime.IsZero() {
		evaluationTime = engine.clock()
	}

	for _, policy := range snapshot.policies {
		if err := ctx.Err(); err != nil {
			return Decision{
				Outcome:  Deny,
				Reason:   ReasonContextCanceled,
				Revision: snapshot.revision,
			}, err
		}

		decision := Decision{Outcome: NotApplicable, Reason: ReasonPolicyInactive}
		if policy.activeAt(evaluationTime) {
			var err error
			decision, err = evaluatePolicy(ctx, policy.evaluator, request)
			if err != nil {
				return failureDecision(snapshot), &PolicyEvaluationError{
					PolicyID: policy.id,
					Err:      err,
				}
			}
		}

		if decision.Outcome > Deny {
			return failureDecision(snapshot), ErrInvalidOutcome
		}

		decisions = append(decisions, decision)
		if len(trace) < engine.limits.MaxTraceSize {
			trace = append(trace, TraceEntry{
				PolicyID: policy.id,
				Outcome:  decision.Outcome,
				Reason:   decision.Reason,
			})
		} else {
			traceTruncated = true
		}

		if decision.Outcome != NotApplicable {
			matched := decision.MatchedPolicyIDs
			if len(matched) == 0 {
				matched = []PolicyID{policy.id}
			}
			remaining := engine.limits.MaxMatchedPolicyIDs - len(matchedPolicyIDs)
			if len(matched) > remaining {
				matchedPolicyIDs = append(matchedPolicyIDs, matched[:max(remaining, 0)]...)
				matchedPolicyIDsTruncated = true
			} else {
				matchedPolicyIDs = append(matchedPolicyIDs, matched...)
			}
			matchedPolicyIDsTruncated = matchedPolicyIDsTruncated || decision.MatchedPolicyIDsTruncated
		}

		if isDecisive(snapshot.algorithm, decision.Outcome) {
			break
		}
	}

	decision, err := Combine(snapshot.algorithm, decisions)
	if err != nil {
		return failureDecision(snapshot), err
	}

	if decision.Outcome == NotApplicable {
		decision.Outcome = Deny
		decision.Reason = ReasonDefaultDeny
	}

	decision.MatchedPolicyIDs = matchedPolicyIDs
	decision.MatchedPolicyIDsTruncated = matchedPolicyIDsTruncated
	decision.Revision = snapshot.revision
	decision.Trace = trace
	decision.TraceTruncated = traceTruncated

	return decision, nil
}

func evaluatePolicy(
	ctx context.Context,
	evaluator Evaluator,
	request Request,
) (decision Decision, err error) {
	defer func() {
		if recover() != nil {
			decision = Decision{}
			err = ErrPolicyPanic
		}
	}()
	return evaluator.Evaluate(ctx, request)
}

func failureDecision(snapshot *Snapshot) Decision {
	return Decision{
		Outcome:  Deny,
		Reason:   ReasonEvaluationError,
		Revision: snapshot.revision,
	}
}

func isDecisive(algorithm CombiningAlgorithm, outcome Outcome) bool {
	return (algorithm == DenyOverrides && outcome == Deny) ||
		(algorithm == AllowOverrides && outcome == Allow) ||
		((algorithm == FirstApplicable || algorithm == PriorityOrder) &&
			outcome != NotApplicable)
}
