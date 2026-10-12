package rbac

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	authorization "github.com/faustbrian/go-authorization/v3"
)

// DocumentVersion is version 1 of this application model JSON profile.
const DocumentVersion uint64 = 1
const maxEncodedDocumentBytes = 1 << 20

const (
	// EffectAllow is the serialized explicit allow label.
	EffectAllow = "allow"
	// EffectDeny is the serialized explicit deny label.
	EffectDeny = "deny"
)

var (
	// ErrInvalidDocument identifies invalid RBAC document. Compare with errors.Is, not error text.
	ErrInvalidDocument = errors.New("invalid RBAC document")
	// ErrUnsupportedDocumentVersion identifies unsupported RBAC document version. Compare with errors.Is, not error text.
	ErrUnsupportedDocumentVersion = errors.New("unsupported RBAC document version")
	// ErrDocumentLimitExceeded identifies RBAC document size limit exceeded. Compare with errors.Is, not error text.
	ErrDocumentLimitExceeded = errors.New("RBAC document size limit exceeded")
)

// RoleDocument is editable same-tenant role inheritance input.
type RoleDocument struct {
	// ID is an exact application-defined label; keep diagnostic identifiers non-secret.
	ID RoleID `json:"id"`
	// Tenant is exact scope; empty means global, not inferred tenant membership.
	Tenant authorization.TenantID `json:"tenant,omitempty"`
	// Parents lists same-tenant inherited roles; New copies and validates the acyclic graph.
	Parents []RoleID `json:"parents,omitempty"`
}

// PermissionDocument is editable exact role/action/resource permission input.
type PermissionDocument struct {
	// ID is an exact application-defined label; keep diagnostic identifiers non-secret.
	ID authorization.PolicyID `json:"id"`
	// RoleID names an existing same-tenant role; constructors validate that relation.
	RoleID RoleID `json:"role_id"`
	// Tenant is exact scope; empty means global, not inferred tenant membership.
	Tenant authorization.TenantID `json:"tenant,omitempty"`
	// Action is matched byte-for-byte; no wildcard, normalization or permission discovery is implied.
	Action authorization.Action `json:"action"`
	// ResourceType is matched exactly; no wildcard or external lookup is implied.
	ResourceType authorization.ResourceType `json:"resource_type"`
	// ResourceID is exact when nonempty; empty makes the grant/rule type-wide.
	ResourceID authorization.ResourceID `json:"resource_id,omitempty"`
	// Effect must select an explicit allow or deny; model construction rejects other outcomes.
	Effect string `json:"effect"`
	// Priority orders higher values first where the selected model supports ordering.
	Priority int `json:"priority,omitempty"`
}

// AssignmentDocument is editable exact subject/role scope input.
type AssignmentDocument struct {
	// ID is an exact application-defined label; keep diagnostic identifiers non-secret.
	ID authorization.PolicyID `json:"id"`
	// SubjectKind is the exact principal-kind label, not enforced authentication policy.
	SubjectKind authorization.SubjectKind `json:"subject_kind"`
	// SubjectID is the exact principal identity; application authentication must establish it.
	SubjectID authorization.SubjectID `json:"subject_id"`
	// RoleID names an existing same-tenant role; constructors validate that relation.
	RoleID RoleID `json:"role_id"`
	// Tenant is exact scope; empty means global, not inferred tenant membership.
	Tenant authorization.TenantID `json:"tenant,omitempty"`
}

// Document is the editable application version-1 JSON model, not an
// authenticated artifact. Build validates the selected model after caller-owned
// construction/JSON materialization; inactive fields can be present but unused.
type Document struct {
	// Version is the application model version; Build requires DocumentVersion (1).
	Version uint64 `json:"version"`
	// GlobalInheritance explicitly enables global assignments/grants for tenant requests.
	GlobalInheritance bool `json:"global_inheritance,omitempty"`
	// Limits supplies positive count/inheritance-depth overrides; other values retain defaults.
	Limits Limits `json:"limits,omitempty"`
	// Roles supplies editable role definitions; Build/New copies parent slices.
	Roles []RoleDocument `json:"roles"`
	// Permissions supplies editable role permission definitions.
	Permissions []PermissionDocument `json:"permissions"`
	// Assignments supplies editable exact-subject role bindings; attributes are not assignment identity.
	Assignments []AssignmentDocument `json:"assignments"`
}

// Build constructs and validates a fresh model evaluator for DocumentVersion.
// It does not impose the encoded-byte cap or authenticate provenance. Caller-owned
// document containers must stay immutable during construction.
func (document Document) Build() (*Evaluator, error) {
	if document.Version != DocumentVersion {
		return nil, ErrUnsupportedDocumentVersion
	}
	roles := make([]Role, len(document.Roles))
	for index, role := range document.Roles {
		roles[index] = Role(role)
	}
	permissions := make([]Permission, len(document.Permissions))
	for index, permission := range document.Permissions {
		effect, err := parseDocumentEffect(permission.Effect)
		if err != nil {
			return nil, fmt.Errorf("permission %d: %w", index, err)
		}
		permissions[index] = Permission{
			ID: permission.ID, RoleID: permission.RoleID, Tenant: permission.Tenant,
			Action: permission.Action, ResourceType: permission.ResourceType,
			ResourceID: permission.ResourceID, Effect: effect,
			Priority: permission.Priority,
		}
	}
	assignments := make([]Assignment, len(document.Assignments))
	for index, assignment := range document.Assignments {
		assignments[index] = Assignment{
			ID: assignment.ID,
			Subject: authorization.Subject{
				Kind: assignment.SubjectKind,
				ID:   assignment.SubjectID,
			},
			RoleID: assignment.RoleID,
			Tenant: assignment.Tenant,
		}
	}
	options := []Option{WithLimits(document.Limits)}
	if document.GlobalInheritance {
		options = append(options, WithGlobalInheritance())
	}
	return New(roles, permissions, assignments, options...)
}

// DecodeDocument rejects input above 1 MiB before JSON decoding, unknown
// fields and trailing values, then builds the model. Duplicate JSON member names
// follow encoding/json last-wins semantics; duplicate model IDs are rejected.
// Parser diagnostics can include offending characters/field names. No context or
// pre-parser model-depth/count cap is supplied; decoded trees allocate before Build.
func DecodeDocument(encoded []byte) (*Evaluator, error) {
	if len(encoded) > maxEncodedDocumentBytes {
		return nil, ErrDocumentLimitExceeded
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var document Document
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidDocument, err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, ErrInvalidDocument
	}
	return document.Build()
}

// EncodeDocument build-validates, then marshals indented JSON and checks
// the 1 MiB result cap after allocation. It returns no successful oversize output;
// field/string memory and caller document ownership remain outside that cap.
func EncodeDocument(document Document) ([]byte, error) {
	if _, err := document.Build(); err != nil {
		return nil, err
	}
	encoded, err := json.MarshalIndent(document, "", "  ")
	if len(encoded) > maxEncodedDocumentBytes {
		return nil, ErrDocumentLimitExceeded
	}
	return encoded, err
}

// Decoder is the stateless policy.Decoder binding for this version-1 model.
type Decoder struct{}

// Decode delegates to DecodeDocument; no independent lifecycle or context is added.
func (Decoder) Decode(document json.RawMessage) (authorization.Evaluator, error) {
	return DecodeDocument(document)
}

func parseDocumentEffect(effect string) (authorization.Outcome, error) {
	switch effect {
	case EffectAllow:
		return authorization.Allow, nil
	case EffectDeny:
		return authorization.Deny, nil
	default:
		return authorization.NotApplicable, ErrInvalidDocument
	}
}
