package authorization

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"time"
)

var (
	// ErrInvalidPolicy identifies invalid policy. Compare with errors.Is, not error text.
	ErrInvalidPolicy = errors.New("invalid policy")
	// ErrDuplicatePolicy identifies duplicate policy. Compare with errors.Is, not error text.
	ErrDuplicatePolicy = errors.New("duplicate policy")
	// ErrInvalidActivationWindow identifies invalid policy activation window. Compare with errors.Is, not error text.
	ErrInvalidActivationWindow = errors.New("invalid policy activation window")
	// ErrInvalidRevision identifies invalid policy revision. Compare with errors.Is, not error text.
	ErrInvalidRevision = errors.New("invalid policy revision")
)

// Evaluator is the bounded, I/O-free decision interface implemented by policy
// models such as ACL, RBAC, and ABAC. This is a collaborator obligation, not an
// I/O/CPU sandbox: implementations must cooperate with ctx, avoid input mutation
// and support concurrent calls when shared. Engine catches evaluation panics
// but cannot undo side effects or preempt blocking work.
type Evaluator interface {
	// Evaluate returns a valid outcome or an error, using immutable borrowed
	// request data. Decision identifiers/reasons must be non-secret application text.
	Evaluate(context.Context, Request) (Decision, error)
}

// PolicyDefinition binds a stable policy identity to its evaluator.
type PolicyDefinition struct {
	// ID is an exact application-defined label; keep diagnostic identifiers non-secret.
	ID PolicyID
	// Revision identifies the declared policy/view generation; it is not an authenticity signature.
	Revision Revision
	// Priority orders higher values first where the selected model supports ordering.
	Priority int
	// ActiveFrom starts the inclusive activation window; absent/zero means unbounded.
	ActiveFrom time.Time
	// ActiveUntil ends the exclusive activation window; absent/zero means unbounded.
	ActiveUntil time.Time
	// Metadata contains editable application labels, not authenticated/private storage.
	Metadata map[string]string
	// Evaluator is borrowed and must be immutable/concurrency-safe/cooperative when shared.
	Evaluator Evaluator
}

type policyEntry struct {
	id          PolicyID
	revision    Revision
	priority    int
	activeFrom  time.Time
	activeUntil time.Time
	metadata    map[string]string
	evaluator   Evaluator
}

func (policy policyEntry) activeAt(at time.Time) bool {
	return (policy.activeFrom.IsZero() || !at.Before(policy.activeFrom)) &&
		(policy.activeUntil.IsZero() || at.Before(policy.activeUntil))
}

// PolicyInfo is inspectable copied metadata for one snapshotted policy.
// It is not sanitized; callers must keep labels and metadata non-secret.
type PolicyInfo struct {
	// ID is an exact application-defined label; keep diagnostic identifiers non-secret.
	ID PolicyID
	// Revision identifies the declared policy/view generation; it is not an authenticity signature.
	Revision Revision
	// Priority orders higher values first where the selected model supports ordering.
	Priority int
	// ActiveFrom starts the inclusive activation window; absent/zero means unbounded.
	ActiveFrom time.Time
	// ActiveUntil ends the exclusive activation window; absent/zero means unbounded.
	ActiveUntil time.Time
	// Metadata contains editable application labels, not authenticated/private storage.
	Metadata map[string]string
}

// Snapshot fixes policy order/activation metadata for a coherent decision.
// Metadata maps are copied, but Evaluator instances are borrowed and must be
// immutable/concurrency-safe. Structural immutability is not deep evaluator
// isolation or authentication. Construct with NewSnapshot; the zero/nil view
// is not a validated revisioned snapshot.
type Snapshot struct {
	revision  Revision
	algorithm CombiningAlgorithm
	policies  []policyEntry
}

// NewSnapshot requires nonzero revision, a supported algorithm and unique
// nonempty IDs/literal-non-nil evaluators. Typed-nil evaluators are not detected.
// Zero per-policy revisions inherit the snapshot revision; other revisions need
// not equal it. Activation is [ActiveFrom, ActiveUntil), with zero ends unbounded.
// PriorityOrder sorts descending priority then lexical ID; other algorithms
// preserve definition order. Metadata maps are copied; evaluators are borrowed.
// Policy count/string/callback admission belongs to callers and Engine limits.
func NewSnapshot(
	revision Revision,
	algorithm CombiningAlgorithm,
	definitions ...PolicyDefinition,
) (*Snapshot, error) {
	if revision == 0 {
		return nil, ErrInvalidRevision
	}
	if _, err := Combine(algorithm, nil); err != nil {
		return nil, err
	}

	policies := make([]policyEntry, len(definitions))
	policyIDs := make(map[PolicyID]struct{}, len(definitions))
	for index, definition := range definitions {
		if definition.ID == "" || definition.Evaluator == nil {
			return nil, fmt.Errorf("policy %d: %w", index, ErrInvalidPolicy)
		}

		if _, exists := policyIDs[definition.ID]; exists {
			return nil, fmt.Errorf("policy %q: %w", definition.ID, ErrDuplicatePolicy)
		}
		if !definition.ActiveFrom.IsZero() && !definition.ActiveUntil.IsZero() &&
			!definition.ActiveUntil.After(definition.ActiveFrom) {
			return nil, fmt.Errorf("policy %q: %w", definition.ID, ErrInvalidActivationWindow)
		}

		policyIDs[definition.ID] = struct{}{}
		policies[index] = policyEntry{
			id:          definition.ID,
			revision:    definition.Revision,
			priority:    definition.Priority,
			activeFrom:  definition.ActiveFrom,
			activeUntil: definition.ActiveUntil,
			metadata:    cloneMetadata(definition.Metadata),
			evaluator:   definition.Evaluator,
		}
		if policies[index].revision == 0 {
			policies[index].revision = revision
		}
	}

	if algorithm == PriorityOrder {
		slices.SortFunc(policies, func(left, right policyEntry) int {
			if priority := cmp.Compare(right.priority, left.priority); priority != 0 {
				return priority
			}

			return cmp.Compare(left.id, right.id)
		})
	}

	return &Snapshot{
		revision:  revision,
		algorithm: algorithm,
		policies:  policies,
	}, nil
}

// Revision returns the immutable snapshot revision.
func (snapshot *Snapshot) Revision() Revision {
	return snapshot.revision
}

// Algorithm returns the snapshot's validated combining algorithm.
func (snapshot *Snapshot) Algorithm() CombiningAlgorithm {
	return snapshot.algorithm
}

// Policies returns a defensive copy of inspectable policy metadata.
func (snapshot *Snapshot) Policies() []PolicyInfo {
	policies := make([]PolicyInfo, len(snapshot.policies))
	for index, policy := range snapshot.policies {
		policies[index] = PolicyInfo{
			ID:          policy.id,
			Revision:    policy.revision,
			Priority:    policy.priority,
			ActiveFrom:  policy.activeFrom,
			ActiveUntil: policy.activeUntil,
			Metadata:    cloneMetadata(policy.metadata),
		}
	}

	return policies
}

func cloneMetadata(metadata map[string]string) map[string]string {
	if metadata == nil {
		return nil
	}

	clone := make(map[string]string, len(metadata))
	for key, value := range metadata {
		clone[key] = value
	}

	return clone
}
