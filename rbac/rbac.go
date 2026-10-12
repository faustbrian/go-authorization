// Package rbac resolves exact-scope subject/group assignments through a validated
// acyclic role graph. New copies parent/group slices and builds a reusable view;
// Evaluate applies exact action/resource matches and explicit deny over allow.
// Permissions are ordered by descending priority then ID, not first-match wins.
// No-match remains NotApplicable for the root engine to combine/default-deny.
// Tenant inheritance is opt-in; authentication/group membership stays caller-owned.
// Manager provides separate in-memory administration, not distributed persistence.
// Request and unused Subject attributes remain borrowed; no I/O worker is owned.
// Model documents use the application version-1 JSON profile.
package rbac

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"

	authorization "github.com/faustbrian/go-authorization/v3"
)

var (
	// ErrRoleCycle identifies RBAC role inheritance cycle. Compare with errors.Is, not error text.
	ErrRoleCycle = errors.New("RBAC role inheritance cycle")
	// ErrInheritanceDepthExceeded identifies RBAC inheritance depth exceeded. Compare with errors.Is, not error text.
	ErrInheritanceDepthExceeded = errors.New("RBAC inheritance depth exceeded")
	// ErrUnknownParentRole identifies RBAC parent role does not exist. Compare with errors.Is, not error text.
	ErrUnknownParentRole = errors.New("RBAC parent role does not exist")
	// ErrCrossTenantInheritance identifies RBAC inheritance crosses tenants. Compare with errors.Is, not error text.
	ErrCrossTenantInheritance = errors.New("RBAC inheritance crosses tenants")
	// ErrInvalidRole identifies invalid RBAC role. Compare with errors.Is, not error text.
	ErrInvalidRole = errors.New("invalid RBAC role")
	// ErrDuplicateRole identifies duplicate RBAC role. Compare with errors.Is, not error text.
	ErrDuplicateRole = errors.New("duplicate RBAC role")
	// ErrInvalidPermission identifies invalid RBAC permission. Compare with errors.Is, not error text.
	ErrInvalidPermission = errors.New("invalid RBAC permission")
	// ErrDuplicatePermission identifies duplicate RBAC permission. Compare with errors.Is, not error text.
	ErrDuplicatePermission = errors.New("duplicate RBAC permission")
	// ErrInvalidAssignment identifies invalid RBAC assignment. Compare with errors.Is, not error text.
	ErrInvalidAssignment = errors.New("invalid RBAC assignment")
	// ErrDuplicateAssignment identifies duplicate RBAC assignment. Compare with errors.Is, not error text.
	ErrDuplicateAssignment = errors.New("duplicate RBAC assignment")
	// ErrUnknownRole identifies RBAC role does not exist. Compare with errors.Is, not error text.
	ErrUnknownRole = errors.New("RBAC role does not exist")
	// ErrRoleTenantMismatch identifies RBAC role tenant mismatch. Compare with errors.Is, not error text.
	ErrRoleTenantMismatch = errors.New("RBAC role tenant mismatch")
	// ErrRoleLimitExceeded identifies RBAC role limit exceeded. Compare with errors.Is, not error text.
	ErrRoleLimitExceeded = errors.New("RBAC role limit exceeded")
	// ErrPermissionLimitExceeded identifies RBAC permission limit exceeded. Compare with errors.Is, not error text.
	ErrPermissionLimitExceeded = errors.New("RBAC permission limit exceeded")
	// ErrAssignmentLimitExceeded identifies RBAC assignment limit exceeded. Compare with errors.Is, not error text.
	ErrAssignmentLimitExceeded = errors.New("RBAC assignment limit exceeded")
	// ErrGroupLimitExceeded identifies RBAC group limit exceeded. Compare with errors.Is, not error text.
	ErrGroupLimitExceeded = errors.New("RBAC group limit exceeded")
	// ErrMatchLimitExceeded identifies RBAC match limit exceeded. Compare with errors.Is, not error text.
	ErrMatchLimitExceeded = errors.New("RBAC match limit exceeded")
	// ErrBatchLimitExceeded identifies RBAC batch limit exceeded. Compare with errors.Is, not error text.
	ErrBatchLimitExceeded = errors.New("RBAC batch limit exceeded")
)

const (
	defaultMaxInheritanceDepth = 32
	defaultMaxRoles            = 1000
	defaultMaxPermissions      = 10_000
	defaultMaxAssignments      = 10_000
	defaultMaxGroups           = 100
	defaultMaxMatches          = 100
	defaultMaxBatchSize        = 1000
)

const (
	// ReasonAllow marks a model grant.
	ReasonAllow authorization.ReasonCode = "rbac-allow"
	// ReasonExplicitDeny marks a matching model denial.
	ReasonExplicitDeny authorization.ReasonCode = "rbac-explicit-deny"
	// ReasonLimitExceeded marks model work rejected by a configured count/cost limit.
	ReasonLimitExceeded authorization.ReasonCode = "rbac-limit-exceeded"
)

// Limits admits role/permission/assignment/group/match/batch counts and graph
// depth; positive overrides are trusted policy, not a whole-process memory budget.
type Limits struct {
	// MaxInheritanceDepth admits validated role-graph depth; default is 32.
	MaxInheritanceDepth int `json:"max_inheritance_depth,omitempty"`
	// MaxRoles admits role count; default is 1000.
	MaxRoles int `json:"max_roles,omitempty"`
	// MaxPermissions admits permission count; default is 10000.
	MaxPermissions int `json:"max_permissions,omitempty"`
	// MaxAssignments admits assignment count; default is 10000.
	MaxAssignments int `json:"max_assignments,omitempty"`
	// MaxGroups caps admitted membership count; zero/default policy selects 100.
	MaxGroups int `json:"max_groups,omitempty"`
	// MaxMatches caps collected matching entries/permissions/rules; default is 100.
	MaxMatches int `json:"max_matches,omitempty"`
	// MaxBatchSize admits request count before result allocation; default is 1000.
	MaxBatchSize int `json:"max_batch_size,omitempty"`
}

// Option configures construction synchronously. Nil/custom options may panic;
// do not retain evaluator mutation access after New publishes its view.
type Option func(*Evaluator)

// WithLimits applies only positive fields; zero and negative fields retain defaults.
// Limits admit selected counts, not total string bytes, wall time or collaborator memory.
func WithLimits(limits Limits) Option {
	return func(evaluator *Evaluator) {
		if limits.MaxInheritanceDepth > 0 {
			evaluator.limits.MaxInheritanceDepth = limits.MaxInheritanceDepth
		}
		if limits.MaxRoles > 0 {
			evaluator.limits.MaxRoles = limits.MaxRoles
		}
		if limits.MaxPermissions > 0 {
			evaluator.limits.MaxPermissions = limits.MaxPermissions
		}
		if limits.MaxAssignments > 0 {
			evaluator.limits.MaxAssignments = limits.MaxAssignments
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

// WithGlobalInheritance permits global assignments for non-global requests;
// inheritance never crosses distinct nonempty tenant scopes.
func WithGlobalInheritance() Option {
	return func(evaluator *Evaluator) {
		evaluator.inheritGlobal = true
	}
}

// RoleID is an exact application role label, not authenticated membership.
type RoleID string

// Role defines same-tenant inheritance through copied parent IDs.
type Role struct {
	// ID is an exact application-defined label; keep diagnostic identifiers non-secret.
	ID RoleID
	// Tenant is exact scope; empty means global, not inferred tenant membership.
	Tenant authorization.TenantID
	// Parents lists same-tenant inherited roles; New copies and validates the acyclic graph.
	Parents []RoleID
}

// Permission grants/denies one exact action/type and optional resource instance;
// its tenant must match the referenced role.
type Permission struct {
	// ID is an exact application-defined label; keep diagnostic identifiers non-secret.
	ID authorization.PolicyID
	// RoleID names an existing same-tenant role; constructors validate that relation.
	RoleID RoleID
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
	// Priority orders higher values first where the selected model supports ordering.
	Priority int
}

// Assignment binds an exact subject kind/ID to a same-tenant role;
// Subject attributes/groups do not expand assignment identity.
type Assignment struct {
	// ID is an exact application-defined label; keep diagnostic identifiers non-secret.
	ID authorization.PolicyID
	// Subject supplies trusted kind/ID and optional group/fact state; it is not authenticated here.
	Subject authorization.Subject
	// RoleID names an existing same-tenant role; constructors validate that relation.
	RoleID RoleID
	// Tenant is exact scope; empty means global, not inferred tenant membership.
	Tenant authorization.TenantID
}

type subjectKey struct {
	kind authorization.SubjectKind
	id   authorization.SubjectID
}

// Evaluator is a reusable constructed role view with no background lifecycle.
// Use New; requests/maps and unused assignment Subject attributes remain borrowed.
type Evaluator struct {
	roles         map[RoleID]Role
	permissions   map[RoleID][]Permission
	assignments   map[subjectKey][]Assignment
	limits        Limits
	inheritGlobal bool
}

// New checks count/identity/tenant/role-reference constraints and acyclic
// inheritance before publishing a view. Parent and assignment-group slices are
// copied; unused Subject attributes remain borrowed. Initial maps are allocated
// before count rejection; graph cycle detection precedes inheritance-depth admission.
// Nil/custom options may panic; caller strings and constructor work need trusted budgets.
func New(
	roles []Role,
	permissions []Permission,
	assignments []Assignment,
	options ...Option,
) (*Evaluator, error) {
	evaluator := &Evaluator{
		roles:       make(map[RoleID]Role, len(roles)),
		permissions: make(map[RoleID][]Permission, len(permissions)),
		assignments: make(map[subjectKey][]Assignment, len(assignments)),
		limits: Limits{
			MaxInheritanceDepth: defaultMaxInheritanceDepth,
			MaxRoles:            defaultMaxRoles,
			MaxPermissions:      defaultMaxPermissions,
			MaxAssignments:      defaultMaxAssignments,
			MaxGroups:           defaultMaxGroups,
			MaxMatches:          defaultMaxMatches,
			MaxBatchSize:        defaultMaxBatchSize,
		},
	}
	for _, option := range options {
		option(evaluator)
	}
	if len(roles) > evaluator.limits.MaxRoles {
		return nil, ErrRoleLimitExceeded
	}
	if len(permissions) > evaluator.limits.MaxPermissions {
		return nil, ErrPermissionLimitExceeded
	}
	if len(assignments) > evaluator.limits.MaxAssignments {
		return nil, ErrAssignmentLimitExceeded
	}

	for index, role := range roles {
		if role.ID == "" {
			return nil, fmt.Errorf("role %d: %w", index, ErrInvalidRole)
		}
		if _, exists := evaluator.roles[role.ID]; exists {
			return nil, fmt.Errorf("role %q: %w", role.ID, ErrDuplicateRole)
		}
		role.Parents = append([]RoleID(nil), role.Parents...)
		evaluator.roles[role.ID] = role
	}
	if err := evaluator.validateInheritance(); err != nil {
		return nil, err
	}
	permissionIDs := make(map[authorization.PolicyID]struct{}, len(permissions))
	for index, permission := range permissions {
		if !validPermission(permission) {
			return nil, fmt.Errorf("permission %d: %w", index, ErrInvalidPermission)
		}
		if _, exists := permissionIDs[permission.ID]; exists {
			return nil, fmt.Errorf("permission %q: %w", permission.ID, ErrDuplicatePermission)
		}
		role, exists := evaluator.roles[permission.RoleID]
		if !exists {
			return nil, fmt.Errorf("permission %q role %q: %w", permission.ID, permission.RoleID, ErrUnknownRole)
		}
		if role.Tenant != permission.Tenant {
			return nil, fmt.Errorf("permission %q: %w", permission.ID, ErrRoleTenantMismatch)
		}
		permissionIDs[permission.ID] = struct{}{}
		evaluator.permissions[permission.RoleID] = append(
			evaluator.permissions[permission.RoleID],
			permission,
		)
	}
	assignmentIDs := make(map[authorization.PolicyID]struct{}, len(assignments))
	for index, assignment := range assignments {
		if !validAssignment(assignment) {
			return nil, fmt.Errorf("assignment %d: %w", index, ErrInvalidAssignment)
		}
		if _, exists := assignmentIDs[assignment.ID]; exists {
			return nil, fmt.Errorf("assignment %q: %w", assignment.ID, ErrDuplicateAssignment)
		}
		role, exists := evaluator.roles[assignment.RoleID]
		if !exists {
			return nil, fmt.Errorf("assignment %q role %q: %w", assignment.ID, assignment.RoleID, ErrUnknownRole)
		}
		if role.Tenant != assignment.Tenant {
			return nil, fmt.Errorf("assignment %q: %w", assignment.ID, ErrRoleTenantMismatch)
		}
		assignment.Subject.Groups = append([]authorization.SubjectID(nil), assignment.Subject.Groups...)
		assignmentIDs[assignment.ID] = struct{}{}
		key := subjectKey{kind: assignment.Subject.Kind, id: assignment.Subject.ID}
		evaluator.assignments[key] = append(evaluator.assignments[key], assignment)
	}

	return evaluator, nil
}

// Evaluate obtains effective permissions, matches exact action/type and optional
// instance ID, and collects at most MaxMatches with deny overriding allow. It does
// not call Request.Validate. Context is checked in EffectivePermissions at entry,
// not at every recursive role/permission step; no-match is NotApplicable.
func (evaluator *Evaluator) Evaluate(
	ctx context.Context,
	request authorization.Request,
) (authorization.Decision, error) {
	decision := authorization.Decision{Outcome: authorization.NotApplicable}
	permissions, err := evaluator.EffectivePermissions(ctx, request.Subject, request.Tenant)
	if err != nil {
		reason := ReasonLimitExceeded
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			reason = authorization.ReasonContextCanceled
		}
		return authorization.Decision{Outcome: authorization.Deny, Reason: reason}, err
	}

	for _, permission := range permissions {
		if !permissionMatchesRequest(permission, request) {
			continue
		}
		if len(decision.MatchedPolicyIDs) >= evaluator.limits.MaxMatches {
			return authorization.Decision{
				Outcome: authorization.Deny,
				Reason:  ReasonLimitExceeded,
			}, ErrMatchLimitExceeded
		}

		decision.MatchedPolicyIDs = append(decision.MatchedPolicyIDs, permission.ID)
		if permission.Effect == authorization.Deny {
			decision.Outcome = authorization.Deny
			decision.Reason = ReasonExplicitDeny
		} else if decision.Outcome == authorization.NotApplicable {
			decision.Outcome = authorization.Allow
			decision.Reason = ReasonAllow
		}
	}

	return decision, nil
}

// EffectivePermissions returns a fresh priority-descending/ID-sorted permission
// slice from exact-scope subject/groups and their role closures. Duplicate roles
// are collapsed, not equal permissions across distinct roles. MaxGroups applies;
// MaxMatches is enforced later by Evaluate, not as this collection size budget.
// Groups/tenant membership are trusted facts, and context checks occur at entry.
func (evaluator *Evaluator) EffectivePermissions(
	ctx context.Context,
	subject authorization.Subject,
	tenant authorization.TenantID,
) ([]Permission, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(subject.Groups) > evaluator.limits.MaxGroups {
		return nil, ErrGroupLimitExceeded
	}

	principals := []authorization.Subject{subject}
	for _, groupID := range subject.Groups {
		principals = append(principals, authorization.Subject{
			Kind: authorization.SubjectGroup,
			ID:   groupID,
		})
	}

	roleIDs := make(map[RoleID]struct{})
	for _, principal := range principals {
		key := subjectKey{kind: principal.Kind, id: principal.ID}
		for _, assignment := range evaluator.assignments[key] {
			if evaluator.matchesTenant(assignment.Tenant, tenant) {
				evaluator.addRoleClosure(assignment.RoleID, roleIDs)
			}
		}
	}

	permissions := make([]Permission, 0)
	for roleID := range roleIDs {
		permissions = append(permissions, evaluator.permissions[roleID]...)
	}
	slices.SortFunc(permissions, func(left, right Permission) int {
		return cmp.Or(
			cmp.Compare(right.Priority, left.Priority),
			cmp.Compare(left.ID, right.ID),
		)
	})

	return permissions, nil
}

func validPermission(permission Permission) bool {
	if slices.Contains([]string{
		string(permission.ID), string(permission.RoleID), string(permission.Action),
		string(permission.ResourceType),
	}, "") {
		return false
	}
	switch permission.Effect {
	case authorization.Allow, authorization.Deny:
		return true
	default:
		return false
	}
}

func validAssignment(assignment Assignment) bool {
	return !slices.Contains([]string{
		string(assignment.ID), string(assignment.Subject.Kind),
		string(assignment.Subject.ID), string(assignment.RoleID),
	}, "")
}

func permissionMatchesRequest(permission Permission, request authorization.Request) bool {
	if permission.Action != request.Action {
		return false
	}
	if permission.ResourceType != request.Resource.Type {
		return false
	}
	if permission.ResourceID == "" {
		return true
	}
	return permission.ResourceID == request.Resource.ID
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

func (evaluator *Evaluator) matchesTenant(
	policyTenant authorization.TenantID,
	requestTenant authorization.TenantID,
) bool {
	if policyTenant == requestTenant {
		return true
	}

	return evaluator.inheritGlobal && policyTenant == "" && requestTenant != ""
}

func (evaluator *Evaluator) addRoleClosure(roleID RoleID, roles map[RoleID]struct{}) {
	if _, seen := roles[roleID]; seen {
		return
	}
	roles[roleID] = struct{}{}
	for _, parentID := range evaluator.roles[roleID].Parents {
		evaluator.addRoleClosure(parentID, roles)
	}
}

func (evaluator *Evaluator) validateInheritance() error {
	for _, role := range evaluator.roles {
		for _, parentID := range role.Parents {
			parent, exists := evaluator.roles[parentID]
			if !exists {
				return fmt.Errorf("role %q parent %q: %w", role.ID, parentID, ErrUnknownParentRole)
			}
			if parent.Tenant != role.Tenant {
				return fmt.Errorf("role %q parent %q: %w", role.ID, parentID, ErrCrossTenantInheritance)
			}
		}
	}

	states := make(map[RoleID]uint8, len(evaluator.roles))
	var visit func(RoleID) error
	visit = func(roleID RoleID) error {
		if states[roleID] == 1 {
			return ErrRoleCycle
		}
		if states[roleID] == 2 {
			return nil
		}
		states[roleID] = 1
		for _, parentID := range evaluator.roles[roleID].Parents {
			if err := visit(parentID); err != nil {
				return err
			}
		}
		states[roleID] = 2
		return nil
	}
	for roleID := range evaluator.roles {
		if err := visit(roleID); err != nil {
			return err
		}
	}

	depths := make(map[RoleID]int, len(evaluator.roles))
	var depth func(RoleID) int
	depth = func(roleID RoleID) int {
		if known, exists := depths[roleID]; exists {
			return known
		}
		maximum := 0
		for _, parentID := range evaluator.roles[roleID].Parents {
			maximum = max(maximum, 1+depth(parentID))
		}
		depths[roleID] = maximum
		return maximum
	}
	for roleID := range evaluator.roles {
		if depth(roleID) > evaluator.limits.MaxInheritanceDepth {
			return fmt.Errorf("role %q: %w", roleID, ErrInheritanceDepthExceeded)
		}
	}

	return nil
}
