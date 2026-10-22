// Package abac evaluates a closed typed expression model over caller-owned facts.
// New binds inline/versioned named conditions and sorts rules by priority then ID.
// Exact tenant/action/resource scope is required; explicit deny wins among matches,
// and standalone no-match is NotApplicable. Authentication, attribute truth and
// external I/O are not owned. Built-in constructors copy expression slices and
// use immutable Values; the request maps are borrowed during each call.
// Costs count visited expression nodes, not string bytes, CPU time or allocation.
// Condition is closed to direct external implementations, not an execution sandbox
// for embedded/trusted collaborators. Model JSON is the application v1 profile.
package abac

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"

	authorization "github.com/faustbrian/go-authorization/v4"
)

var (
	// ErrInvalidRule identifies invalid ABAC rule. Compare with errors.Is, not error text.
	ErrInvalidRule = errors.New("invalid ABAC rule")
	// ErrInvalidCondition identifies invalid ABAC condition. Compare with errors.Is, not error text.
	ErrInvalidCondition = errors.New("invalid ABAC condition")
	// ErrCostExceeded identifies ABAC evaluation cost exceeded. Compare with errors.Is, not error text.
	ErrCostExceeded = errors.New("ABAC evaluation cost exceeded")
	// ErrDepthExceeded identifies ABAC condition depth exceeded. Compare with errors.Is, not error text.
	ErrDepthExceeded = errors.New("ABAC condition depth exceeded")
	// ErrRuleLimitExceeded identifies ABAC rule limit exceeded. Compare with errors.Is, not error text.
	ErrRuleLimitExceeded = errors.New("ABAC rule limit exceeded")
	// ErrSetLimitExceeded identifies ABAC set limit exceeded. Compare with errors.Is, not error text.
	ErrSetLimitExceeded = errors.New("ABAC set limit exceeded")
	// ErrMatchLimitExceeded identifies ABAC match limit exceeded. Compare with errors.Is, not error text.
	ErrMatchLimitExceeded = errors.New("ABAC match limit exceeded")
	// ErrBatchLimitExceeded identifies ABAC batch limit exceeded. Compare with errors.Is, not error text.
	ErrBatchLimitExceeded = errors.New("ABAC batch limit exceeded")
	// ErrUnknownNamedCondition identifies unknown named ABAC condition. Compare with errors.Is, not error text.
	ErrUnknownNamedCondition = errors.New("unknown named ABAC condition")
	// ErrDuplicateNamedCondition identifies duplicate named ABAC condition. Compare with errors.Is, not error text.
	ErrDuplicateNamedCondition = errors.New("duplicate named ABAC condition")
)

const (
	// ReasonAllow marks a model grant.
	ReasonAllow authorization.ReasonCode = "abac-allow"
	// ReasonExplicitDeny marks a matching model denial.
	ReasonExplicitDeny authorization.ReasonCode = "abac-explicit-deny"
	// ReasonLimitExceeded marks model work rejected by a configured count/cost limit.
	ReasonLimitExceeded authorization.ReasonCode = "abac-limit-exceeded"
)

// Source selects one of the four independent request attribute maps.
type Source uint8

const (
	// Subject selects subject facts.
	Subject Source = iota
	// Resource selects resource facts.
	Resource
	// Request selects request facts.
	Request
	// Environment selects environment facts.
	Environment
)

// Reference names an exact attribute in a selected map; no path traversal
// or external fetch is performed.
type Reference struct {
	// Source selects the request fact map, not an external data provider.
	Source Source
	// Name is the exact application label; do not place secrets in error-visible names.
	Name authorization.AttributeName
}

// Status distinguishes match/no-match, missing, explicit null and kind mismatch.
type Status uint8

const (
	// StatusNoMatch reports a well-typed predicate that is false.
	StatusNoMatch Status = iota
	// StatusMatch reports a true predicate.
	StatusMatch
	// StatusMissing reports an absent or ValueMissing fact.
	StatusMissing
	// StatusNull reports explicit null for an operator that does not match it.
	StatusNull
	// StatusTypeMismatch reports a fact/literal kind mismatch.
	StatusTypeMismatch
)

// Result reports predicate status and accounted node visits, not elapsed
// cost or a final authorization outcome.
type Result struct {
	// Matched reports predicate truth, not a final authorization grant.
	Matched bool
	// Status distinguishes predicate match, missing, null and type mismatch.
	Status Status
	// Cost reports consumed expression-node visits, not string-byte work or wall time.
	Cost int
}

// Condition is the built-in expression contract with package-private methods.
// Constructors defer validation to New/EvaluateCondition; do not treat embedding
// an arbitrary implementation as safe plugin admission.
type Condition interface {
	evaluate(*evaluationState) (Result, error)
	validate() error
}

// Rule matches exact tenant/action/type and optional instance before
// evaluating either Condition or a versioned named condition.
type Rule struct {
	// ID is an exact application-defined label; keep diagnostic identifiers non-secret.
	ID authorization.PolicyID
	// Priority orders higher values first where the selected model supports ordering.
	Priority int
	// Tenant is exact scope; empty means global, not inferred tenant membership.
	Tenant authorization.TenantID
	// Action is matched byte-for-byte; no wildcard, normalization or permission discovery is implied.
	Action authorization.Action
	// ResourceType is matched exactly; no wildcard or external lookup is implied.
	ResourceType authorization.ResourceType
	// ResourceID is exact when nonempty; empty makes the grant/rule type-wide.
	ResourceID authorization.ResourceID
	// Effect must select an explicit allow or deny; model construction rejects other outcomes.
	Effect authorization.Outcome
	// Condition is the selected expression; use built-in constructors and avoid nil/embedded unsafe state.
	Condition Condition
	// ConditionName selects an exact named condition instead of an inline Condition.
	ConditionName string
	// ConditionVersion must be nonzero with ConditionName, otherwise zero.
	ConditionVersion uint64
}

// NamedCondition binds a nonempty name/nonzero version to a validated
// reusable expression; unused definitions are also validated.
type NamedCondition struct {
	// Name is the exact application label; do not place secrets in error-visible names.
	Name string
	// Version is a nonzero exact named-condition identity, independent of model format version.
	Version uint64
	// Condition is the selected expression; use built-in constructors and avoid nil/embedded unsafe state.
	Condition Condition
}

// Limits bounds selected rule/name/depth/cost/set/match/batch counts.
// Cost counts expression visits; string operations and literal construction are
// not byte/time budgets, and non-positive overrides retain defaults.
type Limits struct {
	// MaxRules admits rule count; default is 1000.
	MaxRules int `json:"max_rules,omitempty"`
	// MaxDepth admits expression depth; default is 32.
	MaxDepth int `json:"max_depth,omitempty"`
	// MaxCost caps node visits per evaluation; default is 1000, not CPU/string-time admission.
	MaxCost int `json:"max_cost,omitempty"`
	// MaxMatches caps collected matching entries/permissions/rules; default is 100.
	MaxMatches int `json:"max_matches,omitempty"`
	// MaxSetSize admits selected literal/runtime collection cardinality; default is 1000, not total bytes.
	MaxSetSize int `json:"max_set_size,omitempty"`
	// MaxBatchSize admits request count before result allocation; default is 1000.
	MaxBatchSize int `json:"max_batch_size,omitempty"`
	// MaxNamedConditions admits named definition count; default is 1000.
	MaxNamedConditions int `json:"max_named_conditions,omitempty"`
}

const (
	defaultMaxRules           = 1000
	defaultMaxDepth           = 32
	defaultMaxCost            = 1000
	defaultMaxMatches         = 100
	defaultMaxSetSize         = 1000
	defaultMaxBatchSize       = 1000
	defaultMaxNamedConditions = 1000
)

// Option configures construction synchronously. Nil/custom options may panic;
// do not retain evaluator mutation access after New publishes its view.
type Option func(*Evaluator)

// WithLimits applies only positive fields; zero and negative fields retain defaults.
// Limits admit selected counts, not total string bytes, wall time or collaborator memory.
func WithLimits(limits Limits) Option {
	return func(evaluator *Evaluator) {
		if limits.MaxRules > 0 {
			evaluator.limits.MaxRules = limits.MaxRules
		}
		if limits.MaxDepth > 0 {
			evaluator.limits.MaxDepth = limits.MaxDepth
		}
		if limits.MaxCost > 0 {
			evaluator.limits.MaxCost = limits.MaxCost
		}
		if limits.MaxMatches > 0 {
			evaluator.limits.MaxMatches = limits.MaxMatches
		}
		if limits.MaxSetSize > 0 {
			evaluator.limits.MaxSetSize = limits.MaxSetSize
		}
		if limits.MaxBatchSize > 0 {
			evaluator.limits.MaxBatchSize = limits.MaxBatchSize
		}
		if limits.MaxNamedConditions > 0 {
			evaluator.limits.MaxNamedConditions = limits.MaxNamedConditions
		}
	}
}

// Evaluator holds a sorted constructed rule view with no I/O/lifecycle.
// Request attribute maps must remain immutable during concurrent evaluation.
type Evaluator struct {
	rules  []Rule
	limits Limits
}

// New validates exact identities/effects, unique rule IDs, named-condition
// bindings and expression depth/literal cardinality, then copies/sorts rules.
// MaxCost is evaluation admission, not a total constructor-node budget. Typed-nil
// embedded conditions/custom options can panic at uncovered construction seams.
func New(
	rules []Rule,
	namedConditions []NamedCondition,
	options ...Option,
) (*Evaluator, error) {
	evaluator := &Evaluator{
		limits: normalizedLimits(Limits{}),
	}
	for _, option := range options {
		option(evaluator)
	}
	if len(rules) > evaluator.limits.MaxRules {
		return nil, ErrRuleLimitExceeded
	}
	if len(namedConditions) > evaluator.limits.MaxNamedConditions {
		return nil, ErrRuleLimitExceeded
	}

	type namedKey struct {
		name    string
		version uint64
	}
	named := make(map[namedKey]Condition, len(namedConditions))
	for index, definition := range namedConditions {
		if definition.Name == "" || definition.Version == 0 || definition.Condition == nil {
			return nil, fmt.Errorf("named condition %d: %w", index, ErrInvalidCondition)
		}
		key := namedKey{name: definition.Name, version: definition.Version}
		if _, exists := named[key]; exists {
			return nil, fmt.Errorf("named condition %q version %d: %w", definition.Name, definition.Version, ErrDuplicateNamedCondition)
		}
		if err := validateConditionLimits(definition.Condition, evaluator.limits); err != nil {
			return nil, fmt.Errorf("named condition %q version %d: %w", definition.Name, definition.Version, err)
		}
		named[key] = definition.Condition
	}

	ruleIDs := make(map[authorization.PolicyID]struct{}, len(rules))
	evaluator.rules = append([]Rule(nil), rules...)
	for index, rule := range evaluator.rules {
		if rule.ConditionName != "" {
			if rule.Condition != nil || rule.ConditionVersion == 0 {
				return nil, fmt.Errorf("rule %d: %w", index, ErrInvalidRule)
			}
			condition, exists := named[namedKey{name: rule.ConditionName, version: rule.ConditionVersion}]
			if !exists {
				return nil, fmt.Errorf("rule %q: %w", rule.ID, ErrUnknownNamedCondition)
			}
			rule.Condition = condition
			evaluator.rules[index] = rule
		} else if rule.ConditionVersion != 0 {
			return nil, fmt.Errorf("rule %d: %w", index, ErrInvalidRule)
		}
		if rule.ID == "" || rule.Action == "" || rule.ResourceType == "" ||
			(rule.Effect != authorization.Allow && rule.Effect != authorization.Deny) ||
			rule.Condition == nil {
			return nil, fmt.Errorf("rule %d: %w", index, ErrInvalidRule)
		}
		if _, exists := ruleIDs[rule.ID]; exists {
			return nil, fmt.Errorf("rule %q: %w", rule.ID, ErrInvalidRule)
		}
		if err := validateConditionLimits(rule.Condition, evaluator.limits); err != nil {
			return nil, fmt.Errorf("rule %q: %w", rule.ID, err)
		}
		ruleIDs[rule.ID] = struct{}{}
	}
	slices.SortFunc(evaluator.rules, func(left, right Rule) int {
		if priority := cmp.Compare(right.Priority, left.Priority); priority != 0 {
			return priority
		}
		return cmp.Compare(left.ID, right.ID)
	})

	return evaluator, nil
}

// Evaluate matches scopes and evaluates conditions in sorted order; explicit
// deny wins among all matches and no-match is NotApplicable. One cost counter is
// shared across matching rules. Request.Validate is not called; ctx is checked
// at consumed nodes; a request with no matching scope can return NotApplicable
// even when canceled.
func (evaluator *Evaluator) Evaluate(
	ctx context.Context,
	request authorization.Request,
) (authorization.Decision, error) {
	state := &evaluationState{
		ctx: ctx, request: request,
		maxCost: evaluator.limits.MaxCost, maxSetSize: evaluator.limits.MaxSetSize,
	}
	decision := authorization.Decision{Outcome: authorization.NotApplicable}

	for _, rule := range evaluator.rules {
		if rule.Tenant != request.Tenant || rule.Action != request.Action ||
			rule.ResourceType != request.Resource.Type ||
			(rule.ResourceID != "" && rule.ResourceID != request.Resource.ID) {
			continue
		}

		result, err := rule.Condition.evaluate(state)
		if err != nil {
			reason := ReasonLimitExceeded
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				reason = authorization.ReasonContextCanceled
			}
			return authorization.Decision{Outcome: authorization.Deny, Reason: reason}, err
		}
		if result.Matched {
			if len(decision.MatchedPolicyIDs) >= evaluator.limits.MaxMatches {
				return authorization.Decision{
					Outcome: authorization.Deny,
					Reason:  ReasonLimitExceeded,
				}, ErrMatchLimitExceeded
			}

			decision.MatchedPolicyIDs = append(decision.MatchedPolicyIDs, rule.ID)
			if rule.Effect == authorization.Deny {
				decision.Outcome = authorization.Deny
				decision.Reason = ReasonExplicitDeny
			} else if decision.Outcome == authorization.NotApplicable {
				decision.Outcome = authorization.Allow
				decision.Reason = ReasonAllow
			}
		}
	}

	return decision, nil
}

// EvaluateBatch checks MaxBatchSize before allocation, then returns one ordered result
// per request and joined errors. It continues after failures/cancellation; an empty
// batch performs no per-request ctx check. No cross-request transaction is provided.
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

func validateConditionLimits(condition Condition, limits Limits) error {
	type frame struct {
		condition Condition
		depth     int
	}
	stack := []frame{{condition: condition, depth: 1}}
	cardinality := 0
	for len(stack) > 0 {
		last := len(stack) - 1
		current := stack[last]
		stack = stack[:last]
		if current.depth > limits.MaxDepth {
			return ErrDepthExceeded
		}
		if err := current.condition.validate(); err != nil {
			return err
		}

		children := conditionChildren(current.condition)
		for index := len(children) - 1; index >= 0; index-- {
			stack = append(stack, frame{condition: children[index], depth: current.depth + 1})
		}

		localCardinality := conditionLocalCardinality(current.condition)
		if localCardinality > limits.MaxSetSize-cardinality {
			return ErrSetLimitExceeded
		}
		cardinality = cardinality + localCardinality
	}
	return nil
}

func conditionChildren(condition Condition) []Condition {
	switch typed := condition.(type) {
	case allCondition:
		return typed.conditions
	case anyCondition:
		return typed.conditions
	case notCondition:
		if typed.condition != nil {
			return []Condition{typed.condition}
		}
	}
	return nil
}

func conditionLocalCardinality(condition Condition) int {
	switch typed := condition.(type) {
	case inCondition:
		return len(typed.values)
	case equalCondition:
		values, ok := typed.want.StringSet()
		if ok {
			return len(values)
		}
	}
	return 0
}

func normalizedLimits(limits Limits) Limits {
	normalized := Limits{
		MaxRules:           defaultMaxRules,
		MaxDepth:           defaultMaxDepth,
		MaxCost:            defaultMaxCost,
		MaxMatches:         defaultMaxMatches,
		MaxSetSize:         defaultMaxSetSize,
		MaxBatchSize:       defaultMaxBatchSize,
		MaxNamedConditions: defaultMaxNamedConditions,
	}
	evaluator := &Evaluator{limits: normalized}
	WithLimits(limits)(evaluator)
	return evaluator.limits
}

// EvaluateCondition validates depth/literal set policy, then evaluates with a
// fresh per-call node budget. Cost is reported from the state even on failure;
// nil conditions fail. No request authentication or complete request validation occurs.
func EvaluateCondition(
	ctx context.Context,
	condition Condition,
	request authorization.Request,
	limits Limits,
) (Result, error) {
	if condition == nil {
		return Result{}, ErrInvalidCondition
	}
	limits = normalizedLimits(limits)
	if err := validateConditionLimits(condition, limits); err != nil {
		return Result{}, err
	}
	state := &evaluationState{
		ctx: ctx, request: request,
		maxCost: limits.MaxCost, maxSetSize: limits.MaxSetSize,
	}
	result, err := condition.evaluate(state)
	result.Cost = state.cost
	return result, err
}

type evaluationState struct {
	ctx        context.Context
	request    authorization.Request
	cost       int
	maxCost    int
	maxSetSize int
}

func (state *evaluationState) consume() error {
	if err := state.ctx.Err(); err != nil {
		return err
	}
	if state.cost >= state.maxCost {
		return ErrCostExceeded
	}
	state.cost++
	return nil
}

func (state *evaluationState) attribute(reference Reference) (authorization.Value, bool) {
	var attributes authorization.Attributes
	switch reference.Source {
	case Subject:
		attributes = state.request.Subject.Attributes
	case Resource:
		attributes = state.request.Resource.Attributes
	case Request:
		attributes = state.request.Attributes
	case Environment:
		attributes = state.request.Environment.Attributes
	}

	value, exists := attributes[reference.Name]
	return value, exists
}

type equalCondition struct {
	reference Reference
	want      authorization.Value
}

// Equal compares exact kinds and structural Values; explicit null can
// match null, while missing values and mismatched kinds keep distinct statuses.
func Equal(reference Reference, want authorization.Value) Condition {
	return equalCondition{reference: reference, want: want}
}

func (condition equalCondition) evaluate(state *evaluationState) (Result, error) {
	if err := state.consume(); err != nil {
		return Result{}, err
	}

	got, exists := state.attribute(condition.reference)
	if isMissingValue(got, exists) {
		return Result{Status: StatusMissing}, nil
	}
	if err := state.validateValue(got); err != nil {
		return Result{}, err
	}
	if got.Kind() == authorization.ValueNull {
		if condition.want.Kind() == authorization.ValueNull {
			return Result{Matched: true, Status: StatusMatch}, nil
		}
		return Result{Status: StatusNull}, nil
	}
	if got.Kind() != condition.want.Kind() {
		return Result{Status: StatusTypeMismatch}, nil
	}
	if got.Equal(condition.want) {
		return Result{Matched: true, Status: StatusMatch}, nil
	}
	return Result{Status: StatusNoMatch}, nil
}

func (state *evaluationState) validateValue(value authorization.Value) error {
	if length, collection := value.CollectionLength(); collection && length > state.maxSetSize {
		return ErrSetLimitExceeded
	}
	return nil
}

func (condition equalCondition) validate() error {
	if err := validateReference(condition.reference); err != nil {
		return err
	}
	if condition.want.Kind() == authorization.ValueMissing {
		return ErrInvalidCondition
	}
	return nil
}

type allCondition struct {
	conditions []Condition
}

// All copies child order and short-circuits on the first false/error.
// Empty or nil children fail later validation, not this constructor.
func All(conditions ...Condition) Condition {
	return allCondition{conditions: append([]Condition(nil), conditions...)}
}

func (condition allCondition) evaluate(state *evaluationState) (Result, error) {
	if err := state.consume(); err != nil {
		return Result{}, err
	}
	for _, child := range condition.conditions {
		result, err := child.evaluate(state)
		if err != nil || !result.Matched {
			return result, err
		}
	}
	return Result{Matched: true, Status: StatusMatch}, nil
}

func (condition allCondition) validate() error {
	return validateChildren(condition.conditions)
}
