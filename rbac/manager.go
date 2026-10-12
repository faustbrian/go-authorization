package rbac

import (
	"sync"

	authorization "github.com/faustbrian/go-authorization/v3"
)

// Manager provides synchronized in-memory assignment administration. Each
// Evaluator call builds a new structural view. Options run again under manager
// locks and must not block/reenter the manager. Unused nested Subject attribute
// maps are not deep-copied. No distributed storage, clock or goroutine is owned.
type Manager struct {
	mu          sync.RWMutex
	roles       []Role
	permissions []Permission
	assignments []Assignment
	options     []Option
	revision    authorization.Revision
}

// NewManager validates/copies roles, permissions, assignments and options.
// Subject attribute maps remain borrowed; options are rerun during later
// validation under manager locks and must not reenter/block.
func NewManager(
	roles []Role,
	permissions []Permission,
	assignments []Assignment,
	options ...Option,
) (*Manager, error) {
	if _, err := New(roles, permissions, assignments, options...); err != nil {
		return nil, err
	}

	return &Manager{
		roles:       cloneRoles(roles),
		permissions: append([]Permission(nil), permissions...),
		assignments: cloneAssignments(assignments),
		options:     append([]Option(nil), options...),
		revision:    1,
	}, nil
}

// Assign validates and atomically adds a subject-role assignment.
func (manager *Manager) Assign(assignment Assignment) error {
	manager.mu.Lock()
	defer manager.mu.Unlock()

	candidate := append(cloneAssignments(manager.assignments), cloneAssignment(assignment))
	if _, err := New(manager.roles, manager.permissions, candidate, manager.options...); err != nil {
		return err
	}

	manager.assignments = candidate
	manager.revision++
	return nil
}

// RevokeAssignment removes an assignment by stable ID.
func (manager *Manager) RevokeAssignment(id authorization.PolicyID) bool {
	manager.mu.Lock()
	defer manager.mu.Unlock()

	for index, assignment := range manager.assignments {
		if assignment.ID != id {
			continue
		}

		manager.assignments = append(
			manager.assignments[:index],
			manager.assignments[index+1:]...,
		)
		manager.revision++
		return true
	}

	return false
}

// Assignments returns exact-scope assignment copies, including copied Groups.
// Nested Subject.Attributes maps remain shared (and are not used for matching).
func (manager *Manager) Assignments(
	subject authorization.Subject,
	tenant authorization.TenantID,
) []Assignment {
	manager.mu.RLock()
	defer manager.mu.RUnlock()

	assignments := make([]Assignment, 0)
	for _, assignment := range manager.assignments {
		if assignment.Subject.Kind == subject.Kind &&
			assignment.Subject.ID == subject.ID && assignment.Tenant == tenant {
			assignments = append(assignments, cloneAssignment(assignment))
		}
	}

	return assignments
}

// Evaluator rebuilds the current view under the read lock, rerunning borrowed
// options. Returned models fix matching state; unused subject attributes remain
// borrowed. Options must not reenter the manager or block.
func (manager *Manager) Evaluator() (*Evaluator, error) {
	manager.mu.RLock()
	defer manager.mu.RUnlock()

	return New(manager.roles, manager.permissions, manager.assignments, manager.options...)
}

// Revision returns the in-memory counter (initially 1), incremented after accepted
// assignment mutations. It is not a persisted/global token and has no wrap guard.
func (manager *Manager) Revision() authorization.Revision {
	manager.mu.RLock()
	defer manager.mu.RUnlock()

	return manager.revision
}

func cloneRoles(roles []Role) []Role {
	clone := make([]Role, len(roles))
	for index, role := range roles {
		role.Parents = append([]RoleID(nil), role.Parents...)
		clone[index] = role
	}
	return clone
}

func cloneAssignments(assignments []Assignment) []Assignment {
	clone := make([]Assignment, len(assignments))
	for index, assignment := range assignments {
		clone[index] = cloneAssignment(assignment)
	}
	return clone
}

func cloneAssignment(assignment Assignment) Assignment {
	assignment.Subject.Groups = append(
		[]authorization.SubjectID(nil),
		assignment.Subject.Groups...,
	)
	return assignment
}
