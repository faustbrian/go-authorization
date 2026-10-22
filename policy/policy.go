// Package policy owns the application authorization.policy/v1 manifest profile,
// explicit decoder compilation, inspectable diffs, dry-runs and cooperative reload.
// Decode admits envelope bytes but does not authenticate publishers or verify all
// model semantics. Compiler borrows registered decoders/evaluators; snapshot
// publication is local and does not transact with repository/invalidation I/O.
// Synchronizer owns polling only while Run executes under the caller's context.
// Revisions/metadata are trusted source declarations; no whole-process parser,
// callback, string-byte or distributed freshness guarantee is implied.
package policy

import (
	"context"
	"errors"
	"maps"
	"slices"

	authorization "github.com/faustbrian/go-authorization/v4"
)

// ErrNilSnapshot identifies policy snapshot is nil. Compare with errors.Is, not error text.
var ErrNilSnapshot = errors.New("policy snapshot is nil")

// SnapshotDiff compares inspectable policy metadata and algorithms, not evaluator
// code or proof of semantic equivalence.
type SnapshotDiff struct {
	// FromRevision identifies the source view for inspection/comparison.
	FromRevision authorization.Revision
	// ToRevision identifies the candidate view; no publication is performed by the report.
	ToRevision authorization.Revision
	// AlgorithmChanged compares combining algorithms, not evaluator implementation.
	AlgorithmChanged bool
	// Added contains sorted newly introduced policy IDs.
	Added []authorization.PolicyID
	// Removed contains sorted removed policy IDs.
	Removed []authorization.PolicyID
	// Changed contains sorted IDs with changed inspectable metadata/revision/activation/priority.
	Changed []authorization.PolicyID
}

// Diff rejects nil views and returns sorted added/removed/metadata-changed
// IDs. Evaluator implementation and input ordering changes are not independently
// inspected; publishers must assign meaningful policy revisions.
func Diff(current, candidate *authorization.Snapshot) (SnapshotDiff, error) {
	if current == nil {
		return SnapshotDiff{}, ErrNilSnapshot
	}
	if candidate == nil {
		return SnapshotDiff{}, ErrNilSnapshot
	}

	diff := SnapshotDiff{
		FromRevision:     current.Revision(),
		ToRevision:       candidate.Revision(),
		AlgorithmChanged: current.Algorithm() != candidate.Algorithm(),
	}
	currentPolicies := indexPolicies(current.Policies())
	candidatePolicies := indexPolicies(candidate.Policies())

	for id, currentPolicy := range currentPolicies {
		candidatePolicy, exists := candidatePolicies[id]
		if !exists {
			diff.Removed = append(diff.Removed, id)
		} else if !policyInfoEqual(currentPolicy, candidatePolicy) {
			diff.Changed = append(diff.Changed, id)
		}
	}
	for id := range candidatePolicies {
		if _, exists := currentPolicies[id]; !exists {
			diff.Added = append(diff.Added, id)
		}
	}

	sortPolicyIDs(diff.Added)
	sortPolicyIDs(diff.Removed)
	sortPolicyIDs(diff.Changed)
	return diff, nil
}

// DecisionComparison compares outcome/reason/matched IDs/truncation for one input;
// revision and trace differences alone do not set Changed.
type DecisionComparison struct {
	// Index is the corresponding original request index.
	Index int
	// Current is the current-view decision including its owned result diagnostics.
	Current authorization.Decision
	// Candidate is the candidate-view decision, not an installed result.
	Candidate authorization.Decision
	// Changed reports an outcome/reason/matched-ID or truncation difference; revision/trace alone are ignored.
	Changed bool
}

// DryRunReport contains ordered decisions without installing the candidate.
type DryRunReport struct {
	// FromRevision identifies the source view for inspection/comparison.
	FromRevision authorization.Revision
	// ToRevision identifies the candidate view; no publication is performed by the report.
	ToRevision authorization.Revision
	// Decisions contains per-request comparisons in original order.
	Decisions []DecisionComparison
}

// DryRun creates default-limited engines and evaluates current then candidate
// sequentially, returning joined errors and available comparisons. Callback/clock
// side effects are not rolled back, and omitted request time may sample different
// clocks. Changed excludes revisions/traces; this is selected-request evidence,
// not equivalence, authentication or publication qualification.
func DryRun(
	ctx context.Context,
	current *authorization.Snapshot,
	candidate *authorization.Snapshot,
	requests []authorization.Request,
) (DryRunReport, error) {
	if current == nil {
		return DryRunReport{}, ErrNilSnapshot
	}
	if candidate == nil {
		return DryRunReport{}, ErrNilSnapshot
	}

	currentEngine, err := authorization.NewEngine(current)
	if err != nil {
		return DryRunReport{}, err
	}
	candidateEngine, err := authorization.NewEngine(candidate)
	if err != nil {
		return DryRunReport{}, err
	}
	currentDecisions, currentErr := currentEngine.DecideBatch(ctx, requests)
	candidateDecisions, candidateErr := candidateEngine.DecideBatch(ctx, requests)

	report := DryRunReport{
		FromRevision: current.Revision(),
		ToRevision:   candidate.Revision(),
	}
	evaluationErr := errors.Join(currentErr, candidateErr)
	if len(currentDecisions) != len(requests) {
		return report, evaluationErr
	}
	report.Decisions = make([]DecisionComparison, len(requests))
	for index := range requests {
		report.Decisions[index] = DecisionComparison{
			Index:     index,
			Current:   currentDecisions[index],
			Candidate: candidateDecisions[index],
			Changed:   decisionsDiffer(currentDecisions[index], candidateDecisions[index]),
		}
	}

	return report, evaluationErr
}

func indexPolicies(policies []authorization.PolicyInfo) map[authorization.PolicyID]authorization.PolicyInfo {
	indexed := make(map[authorization.PolicyID]authorization.PolicyInfo, len(policies))
	for _, policy := range policies {
		indexed[policy.ID] = policy
	}
	return indexed
}

func policyInfoEqual(left, right authorization.PolicyInfo) bool {
	return left.Revision == right.Revision &&
		left.Priority == right.Priority && left.ActiveFrom.Equal(right.ActiveFrom) &&
		left.ActiveUntil.Equal(right.ActiveUntil) && maps.Equal(left.Metadata, right.Metadata)
}

func decisionsDiffer(left, right authorization.Decision) bool {
	if left.Outcome != right.Outcome {
		return true
	}
	if left.Reason != right.Reason {
		return true
	}
	if !slices.Equal(left.MatchedPolicyIDs, right.MatchedPolicyIDs) {
		return true
	}
	return left.MatchedPolicyIDsTruncated != right.MatchedPolicyIDsTruncated
}

func sortPolicyIDs(ids []authorization.PolicyID) {
	slices.Sort(ids)
}
