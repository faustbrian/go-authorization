package acl

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
	// ErrInvalidDocument identifies invalid ACL document. Compare with errors.Is, not error text.
	ErrInvalidDocument = errors.New("invalid ACL document")
	// ErrUnsupportedDocumentVersion identifies unsupported ACL document version. Compare with errors.Is, not error text.
	ErrUnsupportedDocumentVersion = errors.New("unsupported ACL document version")
	// ErrDocumentLimitExceeded identifies ACL document size limit exceeded. Compare with errors.Is, not error text.
	ErrDocumentLimitExceeded = errors.New("ACL document size limit exceeded")
)

// EntryDocument is the editable version-1 exact subject/action/resource grant.
type EntryDocument struct {
	// ID is an exact application-defined label; keep diagnostic identifiers non-secret.
	ID EntryID `json:"id"`
	// SubjectKind is the exact principal-kind label, not enforced authentication policy.
	SubjectKind authorization.SubjectKind `json:"subject_kind"`
	// SubjectID is the exact principal identity; application authentication must establish it.
	SubjectID authorization.SubjectID `json:"subject_id"`
	// Action is matched byte-for-byte; no wildcard, normalization or permission discovery is implied.
	Action authorization.Action `json:"action"`
	// ResourceType is matched exactly; no wildcard or external lookup is implied.
	ResourceType authorization.ResourceType `json:"resource_type"`
	// ResourceID is exact when nonempty; empty makes the grant/rule type-wide.
	ResourceID authorization.ResourceID `json:"resource_id,omitempty"`
	// Tenant is exact scope; empty means global, not inferred tenant membership.
	Tenant authorization.TenantID `json:"tenant,omitempty"`
	// Effect must select an explicit allow or deny; model construction rejects other outcomes.
	Effect string `json:"effect"`
}

// Document is the editable application version-1 JSON model, not an
// authenticated artifact. Build validates the selected model after caller-owned
// construction/JSON materialization; inactive fields can be present but unused.
type Document struct {
	// Version is the application model version; Build requires DocumentVersion (1).
	Version uint64 `json:"version"`
	// GlobalInheritance explicitly enables global assignments/grants for tenant requests.
	GlobalInheritance bool `json:"global_inheritance,omitempty"`
	// Limits supplies positive entry/group/match/batch count overrides; other values retain defaults.
	Limits Limits `json:"limits,omitempty"`
	// Entries is the editable ordered ACL document input, copied/indexed by Build/New.
	Entries []EntryDocument `json:"entries"`
}

// Build constructs and validates a fresh model evaluator for DocumentVersion.
// It does not impose the encoded-byte cap or authenticate provenance. Caller-owned
// document containers must stay immutable during construction.
func (document Document) Build() (*Evaluator, error) {
	if document.Version != DocumentVersion {
		return nil, ErrUnsupportedDocumentVersion
	}
	entries := make([]Entry, len(document.Entries))
	for index, entry := range document.Entries {
		effect, err := parseEffect(entry.Effect)
		if err != nil {
			return nil, fmt.Errorf("entry %d: %w", index, err)
		}
		entries[index] = Entry{
			ID: entry.ID,
			Subject: authorization.Subject{
				Kind: entry.SubjectKind,
				ID:   entry.SubjectID,
			},
			Action:       entry.Action,
			ResourceType: entry.ResourceType,
			ResourceID:   entry.ResourceID,
			Tenant:       entry.Tenant,
			Effect:       effect,
		}
	}
	options := []Option{WithLimits(document.Limits)}
	if document.GlobalInheritance {
		options = append(options, WithGlobalInheritance())
	}
	return New(entries, options...)
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

func parseEffect(effect string) (authorization.Outcome, error) {
	switch effect {
	case EffectAllow:
		return authorization.Allow, nil
	case EffectDeny:
		return authorization.Deny, nil
	default:
		return authorization.NotApplicable, ErrInvalidDocument
	}
}
