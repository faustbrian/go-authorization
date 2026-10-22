// Package acl indexes explicit subject/group grants and denials by action and
// resource type. New constructs a reusable read-only view; Evaluate matches exact
// identifiers and optional type-wide IDs, with explicit deny winning among matches.
// Standalone no-match is NotApplicable, not final authorization. Global inheritance
// is opt-in. Groups/tenant/identity are trusted mapped facts, not authenticated here.
// Entry containers are indexed but unused nested Subject attributes are borrowed.
// Calls own no I/O/goroutine; request containers must remain immutable. Document v1
// is the application JSON format, not complete external ACL-standard conformance.
package acl

import (
	"context"
	"errors"
	"fmt"
	"slices"

	authorization "github.com/faustbrian/go-authorization/v4"
)

var (
	// ErrInvalidEntry identifies invalid ACL entry. Compare with errors.Is, not error text.
	ErrInvalidEntry = errors.New("invalid ACL entry")
	// ErrDuplicateEntry identifies duplicate ACL entry. Compare with errors.Is, not error text.
	ErrDuplicateEntry = errors.New("duplicate ACL entry")
	// ErrEntryLimitExceeded identifies ACL entry limit exceeded. Compare with errors.Is, not error text.
	ErrEntryLimitExceeded = errors.New("ACL entry limit exceeded")
	// ErrGroupLimitExceeded identifies ACL group limit exceeded. Compare with errors.Is, not error text.
	ErrGroupLimitExceeded = errors.New("ACL group limit exceeded")
	// ErrMatchLimitExceeded identifies ACL match limit exceeded. Compare with errors.Is, not error text.
	ErrMatchLimitExceeded = errors.New("ACL match limit exceeded")
	// ErrBatchLimitExceeded identifies ACL batch limit exceeded. Compare with errors.Is, not error text.
	ErrBatchLimitExceeded = errors.New("ACL batch limit exceeded")
	// ErrUnboundedResourceSet identifies ACL resource set is unbounded. Compare with errors.Is, not error text.
	ErrUnboundedResourceSet = errors.New("ACL resource set is unbounded")
)

// EntryID preserves PolicyID identity for ACL entry diagnostics.
type EntryID = authorization.PolicyID

const (
	// ReasonAllow marks a model grant.
	ReasonAllow authorization.ReasonCode = "acl-allow"
	// ReasonExplicitDeny marks a matching model denial.
	ReasonExplicitDeny authorization.ReasonCode = "acl-explicit-deny"
	// ReasonLimitExceeded marks model work rejected by a configured count/cost limit.
	ReasonLimitExceeded authorization.ReasonCode = "acl-limit-exceeded"
)

const (
	defaultMaxEntries   = 10_000
	defaultMaxGroups    = 100
	defaultMaxMatches   = 100
	defaultMaxBatchSize = 1000
)

// Limits bounds ACL construction and per-request evaluation work.
type Limits struct {
	// MaxEntries admits ACL entries at construction; default is 10000.
	MaxEntries int `json:"max_entries,omitempty"`
	// MaxGroups caps admitted membership count; zero/default policy selects 100.
	MaxGroups int `json:"max_groups,omitempty"`
	// MaxMatches caps collected matching entries/permissions/rules; default is 100.
	MaxMatches int `json:"max_matches,omitempty"`
	// MaxBatchSize admits request count before result allocation; default is 1000.
	MaxBatchSize int `json:"max_batch_size,omitempty"`
}

// Entry grants or denies one subject an action on a resource type or instance.
type Entry struct {
	// ID is an exact application-defined label; keep diagnostic identifiers non-secret.
	ID EntryID
	// Subject supplies trusted kind/ID and optional group/fact state; it is not authenticated here.
	Subject authorization.Subject
	// Action is matched byte-for-byte; no wildcard, normalization or permission discovery is implied.
	Action authorization.Action
	// ResourceType is matched exactly; no wildcard or external lookup is implied.
	ResourceType authorization.ResourceType
	// ResourceID is exact when nonempty; empty makes the grant/rule type-wide.
	ResourceID authorization.ResourceID
	// Tenant is exact scope; empty means global, not inferred tenant membership.
	Tenant authorization.TenantID
	// Effect must select an explicit allow or deny; model construction rejects other outcomes.
	Effect authorization.Outcome
}

type entryKey struct {
	subjectKind  authorization.SubjectKind
	subjectID    authorization.SubjectID
	action       authorization.Action
	resourceType authorization.ResourceType
}

// Evaluator resolves immutable ACL entries without external I/O.
type Evaluator struct {
	entries       map[entryKey][]Entry
	inheritGlobal bool
	limits        Limits
}

// Option configures construction synchronously. Nil/custom options may panic;
// do not retain evaluator mutation access after New publishes its view.
type Option func(*Evaluator)

// WithGlobalInheritance makes global entries apply to tenant-scoped requests.
// Without this option, global and tenant scopes are isolated.
func WithGlobalInheritance() Option {
	return func(evaluator *Evaluator) {
		evaluator.inheritGlobal = true
	}
}

// WithLimits configures positive bounds while retaining safe defaults for
// zero-valued fields.
func WithLimits(limits Limits) Option {
	return func(evaluator *Evaluator) {
		if limits.MaxEntries > 0 {
			evaluator.limits.MaxEntries = limits.MaxEntries
		}
		if limits.MaxGroups > 0 {
			evaluator.limits.MaxGroups = limits.MaxGroups
		}
		if limits.MaxMatches > 0 {
			evaluator.limits.MaxMatches = limits.MaxMatches
		}
		if limits.MaxBatchSize > 0 {
			evaluator.limits.MaxBatchSize = limits.MaxBatchSize
		}
	}
}

// New checks entry count, unique IDs, required identity/action/type strings and
// allow/deny effects before publishing indexes. Entry values are copied, but
// nested Subject groups/attribute maps are not deeply isolated (they are unused
// for matching). Nil/custom options may panic; positive limits replace defaults
// and non-positive fields are ignored. No context/string-byte budget is applied.
func New(entries []Entry, options ...Option) (*Evaluator, error) {
	evaluator := &Evaluator{
		limits: Limits{
			MaxEntries:   defaultMaxEntries,
			MaxGroups:    defaultMaxGroups,
			MaxMatches:   defaultMaxMatches,
			MaxBatchSize: defaultMaxBatchSize,
		},
	}
	for _, option := range options {
		option(evaluator)
	}
	if len(entries) > evaluator.limits.MaxEntries {
		return nil, ErrEntryLimitExceeded
	}

	indexed := make(map[entryKey][]Entry, len(entries))
	entryIDs := make(map[EntryID]struct{}, len(entries))
	for index, entry := range entries {
		if entry.ID == "" || entry.Subject.Kind == "" || entry.Subject.ID == "" ||
			entry.Action == "" || entry.ResourceType == "" ||
			(entry.Effect != authorization.Allow && entry.Effect != authorization.Deny) {
			return nil, fmt.Errorf("entry %d: %w", index, ErrInvalidEntry)
		}

		if _, exists := entryIDs[entry.ID]; exists {
			return nil, fmt.Errorf("entry %q: %w", entry.ID, ErrDuplicateEntry)
		}
		entryIDs[entry.ID] = struct{}{}

		key := entryKey{
			subjectKind:  entry.Subject.Kind,
			subjectID:    entry.Subject.ID,
			action:       entry.Action,
			resourceType: entry.ResourceType,
		}
		indexed[key] = append(indexed[key], entry)
	}

	evaluator.entries = indexed

	return evaluator, nil
}

// Evaluate matches the subject and deduplicated trusted groups in request order.
// Actions/types/tenant are exact; empty entry ResourceID is type-wide. All matches
// are collected up to MaxMatches and any deny overrides allows. Limit/cancel errors
// deny and discard partial diagnostics; no match is NotApplicable. It does not
// call Request.Validate and checks ctx between principals, not every entry.
func (evaluator *Evaluator) Evaluate(
	ctx context.Context,
	request authorization.Request,
) (authorization.Decision, error) {
	if err := ctx.Err(); err != nil {
		return authorization.Decision{
			Outcome: authorization.Deny,
			Reason:  authorization.ReasonContextCanceled,
		}, err
	}
	if len(request.Subject.Groups) > evaluator.limits.MaxGroups {
		return limitDecision(), ErrGroupLimitExceeded
	}

	principals := make([]authorization.Subject, 0, len(request.Subject.Groups)+1)
	principals = append(principals, request.Subject)
	for _, groupID := range request.Subject.Groups {
		principals = append(principals, authorization.Subject{
			Kind: authorization.SubjectGroup,
			ID:   groupID,
		})
	}

	decision := authorization.Decision{Outcome: authorization.NotApplicable}
	seenPrincipals := make(map[entryKey]struct{}, len(principals))
	for _, principal := range principals {
		if err := ctx.Err(); err != nil {
			return authorization.Decision{
				Outcome: authorization.Deny,
				Reason:  authorization.ReasonContextCanceled,
			}, err
		}

		key := entryKey{
			subjectKind:  principal.Kind,
			subjectID:    principal.ID,
			action:       request.Action,
			resourceType: request.Resource.Type,
		}
		if _, seen := seenPrincipals[key]; !seen {
			seenPrincipals[key] = struct{}{}

			for _, entry := range evaluator.entries[key] {
				if !evaluator.matchesTenant(entry.Tenant, request.Tenant) ||
					(entry.ResourceID != "" && entry.ResourceID != request.Resource.ID) {
					continue
				}
				if len(decision.MatchedPolicyIDs) >= evaluator.limits.MaxMatches {
					return limitDecision(), ErrMatchLimitExceeded
				}

				decision.MatchedPolicyIDs = append(decision.MatchedPolicyIDs, entry.ID)
				if entry.Effect == authorization.Deny {
					decision.Outcome = authorization.Deny
					decision.Reason = ReasonExplicitDeny
				} else if decision.Outcome == authorization.NotApplicable {
					decision.Outcome = authorization.Allow
					decision.Reason = ReasonAllow
				}
			}
		}
	}

	return decision, nil
}

// EvaluateBatch evaluates all requests against the same ACL view and returns
// each decision with joined per-request errors. Oversized input returns nil;
// cancellation is delegated to Evaluate and does not short-circuit the batch.
func (evaluator *Evaluator) EvaluateBatch(
	ctx context.Context,
	requests []authorization.Request,
) ([]authorization.Decision, error) {
	if len(requests) > evaluator.limits.MaxBatchSize {
		return nil, ErrBatchLimitExceeded
	}

	decisions := make([]authorization.Decision, len(requests))
	evaluationErrors := make([]error, 0)
	for index, request := range requests {
		decision, err := evaluator.Evaluate(ctx, request)
		decisions[index] = decision
		if err != nil {
			evaluationErrors = append(evaluationErrors, err)
		}
	}

	return decisions, errors.Join(evaluationErrors...)
}

// ListResourceIDs returns only explicitly enumerable instance grants. A
// resource-type allow is reported as unbounded instead of triggering a storage
// scan; a type-wide deny returns an empty set immediately. Results are sorted,
// duplicate principals are ignored and exact matched-entry caps apply. No request
// authentication/validation is performed; context is checked between principals.
func (evaluator *Evaluator) ListResourceIDs(
	ctx context.Context,
	subject authorization.Subject,
	action authorization.Action,
	resourceType authorization.ResourceType,
	tenant authorization.TenantID,
) ([]authorization.ResourceID, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(subject.Groups) > evaluator.limits.MaxGroups {
		return nil, ErrGroupLimitExceeded
	}

	resourceEffects := make(map[authorization.ResourceID]authorization.Outcome)
	typeWideAllow := false
	matches := 0
	for _, key := range principalKeys(subject, action, resourceType) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		for _, entry := range evaluator.entries[key] {
			if evaluator.matchesTenant(entry.Tenant, tenant) {
				if matches >= evaluator.limits.MaxMatches {
					return nil, ErrMatchLimitExceeded
				}
				matches++

				if entry.ResourceID == "" {
					if entry.Effect == authorization.Deny {
						return []authorization.ResourceID{}, nil
					}
					typeWideAllow = true
				} else if entry.Effect == authorization.Deny ||
					resourceEffects[entry.ResourceID] == authorization.NotApplicable {
					resourceEffects[entry.ResourceID] = entry.Effect
				}
			}
		}
	}

	if typeWideAllow {
		return nil, ErrUnboundedResourceSet
	}

	resourceIDs := make([]authorization.ResourceID, 0, len(resourceEffects))
	for resourceID, effect := range resourceEffects {
		if effect == authorization.Allow {
			resourceIDs = append(resourceIDs, resourceID)
		}
	}
	slices.Sort(resourceIDs)

	return resourceIDs, nil
}

func principalKeys(
	subject authorization.Subject,
	action authorization.Action,
	resourceType authorization.ResourceType,
) []entryKey {
	keys := make([]entryKey, 0, len(subject.Groups)+1)
	seen := make(map[entryKey]struct{})
	principals := make([]authorization.Subject, 0, len(subject.Groups)+1)
	principals = append(principals, subject)
	for _, groupID := range subject.Groups {
		principals = append(principals, authorization.Subject{
			Kind: authorization.SubjectGroup,
			ID:   groupID,
		})
	}

	for _, principal := range principals {
		key := entryKey{
			subjectKind:  principal.Kind,
			subjectID:    principal.ID,
			action:       action,
			resourceType: resourceType,
		}
		if _, exists := seen[key]; !exists {
			seen[key] = struct{}{}
			keys = append(keys, key)
		}
	}

	return keys
}

func limitDecision() authorization.Decision {
	return authorization.Decision{
		Outcome: authorization.Deny,
		Reason:  ReasonLimitExceeded,
	}
}

func (evaluator *Evaluator) matchesTenant(
	entryTenant authorization.TenantID,
	requestTenant authorization.TenantID,
) bool {
	if entryTenant == requestTenant {
		return true
	}
	if requestTenant == "" {
		return false
	}
	if entryTenant != "" {
		return false
	}
	return evaluator.inheritGlobal
}
