package authorization

import "errors"

var (
	// ErrInvalidCombiningAlgorithm indicates an unsupported combining algorithm.
	ErrInvalidCombiningAlgorithm = errors.New("invalid combining algorithm")
	// ErrInvalidOutcome indicates a decision with an unsupported outcome.
	ErrInvalidOutcome = errors.New("invalid decision outcome")
)

// Outcome is the result of evaluating an authorization policy.
type Outcome uint8

const (
	// NotApplicable means no applicable policy; Engine converts the final result to default deny.
	NotApplicable Outcome = iota
	// Allow is an explicit grant; adapters forward only this valid outcome.
	Allow
	// Deny is an explicit refusal.
	Deny
)

// String returns a stable outcome label, or unknown for an invalid value.
func (outcome Outcome) String() string {
	switch outcome {
	case NotApplicable:
		return "not-applicable"
	case Allow:
		return "allow"
	case Deny:
		return "deny"
	default:
		return "unknown"
	}
}

// Decision is the result of one or more policy evaluations.
type Decision struct {
	// Outcome is Allow, Deny or NotApplicable; Engine validates and default-denies.
	Outcome Outcome
	// Reason is caller/model-defined diagnostic text; it must not contain secrets.
	Reason ReasonCode
	// MatchedPolicyIDs preserves match order; count caps do not bound identifier bytes.
	MatchedPolicyIDs []PolicyID
	// MatchedPolicyIDsTruncated signals incomplete identifier diagnostics, not changed outcome.
	MatchedPolicyIDsTruncated bool
	// Revision identifies the declared policy/view generation; it is not an authenticity signature.
	Revision Revision
	// Trace contains evaluation-order metadata without dedicated request-value fields.
	Trace []TraceEntry
	// TraceTruncated signals incomplete trace diagnostics.
	TraceTruncated bool
}

// TraceEntry records one policy result without request or attribute values.
type TraceEntry struct {
	// PolicyID is the exact non-secret policy diagnostic identity.
	PolicyID PolicyID
	// Outcome is Allow, Deny or NotApplicable; Engine validates and default-denies.
	Outcome Outcome
	// Reason is caller/model-defined diagnostic text; it must not contain secrets.
	Reason ReasonCode
}

// ReasonCode is diagnostic text, not a closed enum; keep it non-secret.
type ReasonCode string

const (
	// ReasonDefaultDeny marks an engine result with no applicable grant.
	ReasonDefaultDeny ReasonCode = "default-deny"
	// ReasonInvalidRequest marks failed Engine request validation.
	ReasonInvalidRequest ReasonCode = "invalid-request"
	// ReasonEvaluationError marks failed or invalid evaluator output.
	ReasonEvaluationError ReasonCode = "evaluation-error"
	// ReasonContextCanceled marks cancellation observed by Engine.
	ReasonContextCanceled ReasonCode = "context-canceled"
	// ReasonPolicyInactive marks a policy skipped outside its activation window.
	ReasonPolicyInactive ReasonCode = "policy-inactive"
	// ReasonPolicyStale marks rejected repository-freshness admission.
	ReasonPolicyStale ReasonCode = "policy-stale"
)

// PolicyID is an exact policy diagnostic label; keep it non-secret.
type PolicyID string

// Revision is a caller-assigned uint64 generation; no overflow, authenticity or backend-range validation is implicit.
type Revision uint64

// CombiningAlgorithm determines how multiple policy decisions are resolved.
type CombiningAlgorithm uint8

const (
	// DenyOverrides prefers any explicit deny over allows.
	DenyOverrides CombiningAlgorithm = iota
	// AllowOverrides prefers any explicit allow over denies.
	AllowOverrides
	// FirstApplicable selects the first non-NotApplicable input in definition order.
	FirstApplicable
	// PriorityOrder selects the first applicable policy after Snapshot sorts descending priority then ID.
	PriorityOrder
)

// String returns the stable name of a combining algorithm.
func (algorithm CombiningAlgorithm) String() string {
	switch algorithm {
	case DenyOverrides:
		return "deny-overrides"
	case AllowOverrides:
		return "allow-overrides"
	case FirstApplicable:
		return "first-applicable"
	case PriorityOrder:
		return "priority-order"
	default:
		return "unknown"
	}
}

// Combine validates all supplied outcomes, then selects the decisive/last
// applicable Decision. Deny/AllowOverrides prefer their named outcome; ordered
// algorithms take the first applicable input. PriorityOrder does not sort here;
// NewSnapshot owns priority ordering. Empty/all-inapplicable input stays
// NotApplicable; only Engine applies default-deny. The selected decision's slices
// are shared, not merged/copied, and no context/resource admission is performed.
func Combine(algorithm CombiningAlgorithm, decisions []Decision) (Decision, error) {
	if algorithm > PriorityOrder {
		return Decision{}, ErrInvalidCombiningAlgorithm
	}

	for _, decision := range decisions {
		if decision.Outcome > Deny {
			return Decision{}, ErrInvalidOutcome
		}
	}

	result := Decision{Outcome: NotApplicable}

	for _, decision := range decisions {
		if (algorithm == FirstApplicable || algorithm == PriorityOrder) &&
			decision.Outcome != NotApplicable {
			return decision, nil
		}

		if algorithm == DenyOverrides && decision.Outcome == Deny {
			return decision, nil
		}

		if algorithm == AllowOverrides && decision.Outcome == Allow {
			return decision, nil
		}

		if decision.Outcome != NotApplicable {
			result = decision
		}
	}

	return result, nil
}
