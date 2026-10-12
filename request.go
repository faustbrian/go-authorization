package authorization

import (
	"errors"
	"fmt"
	"time"
)

// ErrInvalidRequest identifies invalid authorization request. Compare with errors.Is, not error text.
var ErrInvalidRequest = errors.New("invalid authorization request")

// ValidationError records a failed input path. Validate supplies known field
// names, not input values; a manually supplied Field remains unredacted.
type ValidationError struct {
	// Field is the failed-input path printed by Error; keep manually supplied text non-secret.
	Field string
}

// Error formats Field with ErrInvalidRequest; it does not redact custom Field text.
func (validationError *ValidationError) Error() string {
	return fmt.Sprintf("%s: %v", validationError.Field, ErrInvalidRequest)
}

// Unwrap exposes ErrInvalidRequest for errors.Is.
func (validationError *ValidationError) Unwrap() error {
	return ErrInvalidRequest
}

// SubjectKind identifies the application-defined kind of principal.
type SubjectKind string

const (
	// SubjectUser labels a user principal without verifying its identity.
	SubjectUser SubjectKind = "user"
	// SubjectServiceAccount labels a service-account principal without verifying its identity.
	SubjectServiceAccount SubjectKind = "service-account"
	// SubjectAPIKey labels an API-key principal, not the secret key bytes.
	SubjectAPIKey SubjectKind = "api-key"
	// SubjectGroup labels a group principal; request groups still require trusted membership.
	SubjectGroup SubjectKind = "group"
)

// SubjectID is an exact caller-defined principal label, not a credential.
type SubjectID string

// Action is an exact operation label; no wildcard expansion is implied.
type Action string

// ResourceType is an exact application resource category.
type ResourceType string

// ResourceID is an exact instance label; empty denotes type-wide scope.
type ResourceID string

// TenantID is an exact scope label; empty denotes global scope, not membership verification.
type TenantID string

// AttributeName is an exact fact-map key, not a nested path.
type AttributeName string

// Attributes is caller-owned fact state; keep it stable during evaluation and authenticate its sources.
type Attributes map[AttributeName]Value

// Subject identifies the principal making an authorization request.
type Subject struct {
	// Kind is the caller-selected representation/category, not an authentication assertion.
	Kind SubjectKind
	// ID is an exact application-defined label; keep diagnostic identifiers non-secret.
	ID SubjectID
	// Groups is trusted mapped membership; request slices are borrowed during evaluation.
	Groups []SubjectID
	// Attributes is the caller-owned fact map; sensitivity/authority is not inferred.
	Attributes Attributes
}

// Resource identifies either a resource type or a concrete resource instance.
// An empty ID intentionally represents the entire resource type.
type Resource struct {
	// Type is the exact application resource-type label, not an external schema lookup.
	Type ResourceType
	// ID is an exact application-defined label; keep diagnostic identifiers non-secret.
	ID ResourceID
	// Attributes is the caller-owned fact map; sensitivity/authority is not inferred.
	Attributes Attributes
}

// Environment contains deterministic request-scoped evaluation inputs.
type Environment struct {
	// Time is caller-supplied evaluation time; zero lets Engine sample its clock.
	Time time.Time
	// Attributes is the caller-owned fact map; sensitivity/authority is not inferred.
	Attributes Attributes
}

// Request contains the stable, typed inputs shared by every policy model. An
// empty tenant denotes an explicitly global request scope. Maps/groups are
// borrowed and must not be mutated during evaluation, including by custom
// evaluators. No authentication or automatic tenant binding is performed.
type Request struct {
	// Subject supplies trusted kind/ID and optional group/fact state; it is not authenticated here.
	Subject Subject
	// Action is matched byte-for-byte; no wildcard, normalization or permission discovery is implied.
	Action Action
	// Resource carries exact type/optional instance ID and borrowed application facts.
	Resource Resource
	// Tenant is exact scope; empty means global, not inferred tenant membership.
	Tenant TenantID
	// Environment supplies caller-mapped time/facts; Engine does not authenticate them.
	Environment Environment
	// Attributes is the caller-owned fact map; sensitivity/authority is not inferred.
	Attributes Attributes
}

// Validate rejects empty subject kind/ID, action, resource type and group IDs.
// It does not authenticate identity, validate known kind enums, trim strings,
// admit map/group/identifier bytes or verify tenant/resource/attribute authority.
// Resource.ID and Tenant may be empty for type-wide/global scope. Models used
// directly need their own admission; Engine calls Validate before evaluation.
func (request Request) Validate() error {
	for _, field := range []struct {
		name  string
		value string
	}{
		{name: "subject.kind", value: string(request.Subject.Kind)},
		{name: "subject.id", value: string(request.Subject.ID)},
		{name: "action", value: string(request.Action)},
		{name: "resource.type", value: string(request.Resource.Type)},
	} {
		if field.value == "" {
			return &ValidationError{Field: field.name}
		}
	}

	for index, groupID := range request.Subject.Groups {
		if groupID == "" {
			return &ValidationError{Field: fmt.Sprintf("subject.groups[%d]", index)}
		}
	}

	return nil
}
