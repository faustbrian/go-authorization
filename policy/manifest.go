package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	authorization "github.com/faustbrian/go-authorization/v4"
)

var (
	// ErrInvalidManifest identifies invalid policy manifest. Compare with errors.Is, not error text.
	ErrInvalidManifest = errors.New("invalid policy manifest")
	// ErrDuplicateRecord identifies duplicate policy record. Compare with errors.Is, not error text.
	ErrDuplicateRecord = errors.New("duplicate policy record")
	// ErrManifestLimitExceeded identifies policy manifest size limit exceeded. Compare with errors.Is, not error text.
	ErrManifestLimitExceeded = errors.New("policy manifest size limit exceeded")
)

const maxEncodedManifestBytes = 16 << 20

// Format identifies the editable application envelope version, not a signature.
type Format string

// FormatV1 identifies the authorization.policy/v1 application envelope.
const FormatV1 Format = "authorization.policy/v1"

// Algorithm is the serialized combining label accepted by Manifest.Validate.
type Algorithm string

const (
	// AlgorithmDenyOverrides serializes deny-overrides.
	AlgorithmDenyOverrides Algorithm = "deny-overrides"
	// AlgorithmAllowOverrides serializes allow-overrides.
	AlgorithmAllowOverrides Algorithm = "allow-overrides"
	// AlgorithmFirstApplicable serializes definition-order first-applicable.
	AlgorithmFirstApplicable Algorithm = "first-applicable"
	// AlgorithmPriorityOrder serializes priority-order.
	AlgorithmPriorityOrder Algorithm = "priority-order"
)

// Model names one decoder registry entry; composite has no implicit builtin decoder.
type Model string

const (
	// ModelACL selects the explicitly registered ACL decoder.
	ModelACL Model = "acl"
	// ModelRBAC selects the explicitly registered RBAC decoder.
	ModelRBAC Model = "rbac"
	// ModelABAC selects the explicitly registered ABAC decoder.
	ModelABAC Model = "abac"
	// ModelComposite requires an explicitly registered application decoder; no implicit composite decoder is installed.
	ModelComposite Model = "composite"
)

// Record contains editable metadata and a raw JSON object; model semantics belong
// to its registered Decoder. RawMessage/maps/time pointers are caller-owned.
type Record struct {
	// ID is an exact application-defined label; keep diagnostic identifiers non-secret.
	ID authorization.PolicyID `json:"id"`
	// Revision identifies the declared policy/view generation; it is not an authenticity signature.
	Revision authorization.Revision `json:"revision"`
	// Model names the registered document decoder; composite requires an explicit custom decoder.
	Model Model `json:"model"`
	// Priority orders higher values first where the selected model supports ordering.
	Priority int `json:"priority,omitempty"`
	// ActiveFrom starts the inclusive activation window; absent/zero means unbounded.
	ActiveFrom *time.Time `json:"active_from,omitempty"`
	// ActiveUntil ends the exclusive activation window; absent/zero means unbounded.
	ActiveUntil *time.Time `json:"active_until,omitempty"`
	// Metadata contains editable application labels, not authenticated/private storage.
	Metadata map[string]string `json:"metadata,omitempty"`
	// Document is caller-owned raw JSON object data, not validated model semantics or an authenticated artifact.
	Document json.RawMessage `json:"document"`
}

// Manifest contains one caller-owned revisioned policy candidate. No deep immutability,
// authenticity or whole-process allocation policy is implied by this data type.
type Manifest struct {
	// Format must be the application authorization.policy/v1 envelope identifier.
	Format Format `json:"format"`
	// Revision identifies the declared policy/view generation; it is not an authenticity signature.
	Revision authorization.Revision `json:"revision"`
	// Algorithm selects one supported combining policy; it does not authenticate a manifest.
	Algorithm Algorithm `json:"algorithm"`
	// Policies is caller-owned ordered record state; Compile copies definitions and borrows decoded evaluators.
	Policies []Record `json:"policies"`
}

// Validate checks envelope version/revision/algorithm, unique nonempty
// IDs, valid models/object JSON and activation windows. It does not validate
// model semantics, reject duplicate JSON member names or enforce byte/policy caps.
// Caller-owned documents/maps must remain unchanged during traversal.
func (manifest Manifest) Validate() error {
	if manifest.Format != FormatV1 || manifest.Revision == 0 ||
		!manifest.Algorithm.valid() {
		return ErrInvalidManifest
	}

	policyIDs := make(map[authorization.PolicyID]struct{}, len(manifest.Policies))
	for index, record := range manifest.Policies {
		if record.ID == "" || record.Revision == 0 || !record.Model.valid() ||
			!validDocument(record.Document) {
			return fmt.Errorf("policy %d: %w", index, ErrInvalidManifest)
		}
		if _, exists := policyIDs[record.ID]; exists {
			return fmt.Errorf("policy %q: %w", record.ID, ErrDuplicateRecord)
		}
		if record.ActiveFrom != nil && record.ActiveUntil != nil &&
			!record.ActiveUntil.After(*record.ActiveFrom) {
			return fmt.Errorf("policy %q activation: %w", record.ID, ErrInvalidManifest)
		}
		policyIDs[record.ID] = struct{}{}
	}

	return nil
}

// Encode validates then emits indented JSON with one final newline.
// The 16 MiB cap includes that newline and is checked after marshal allocation;
// it is not a constructor/serialization heap cap or canonical signing encoding.
func Encode(manifest Manifest) ([]byte, error) {
	if err := manifest.Validate(); err != nil {
		return nil, err
	}

	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode manifest: %w", err)
	}
	if len(encoded)+1 > maxEncodedManifestBytes {
		return nil, ErrManifestLimitExceeded
	}
	return append(encoded, '\n'), nil
}

// Decode admits at most 16 MiB before JSON materialization, rejects
// unknown fields/trailing values and validates the envelope. Duplicate member
// names follow encoding/json last-wins; error details may expose offending input
// characters/field names. No context or cryptographic publisher validation is added.
func Decode(encoded []byte) (Manifest, error) {
	if len(encoded) > maxEncodedManifestBytes {
		return Manifest{}, ErrManifestLimitExceeded
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var manifest Manifest
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, fmt.Errorf("decode manifest: %w: %v", ErrInvalidManifest, err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Manifest{}, fmt.Errorf("decode manifest trailing data: %w", ErrInvalidManifest)
	}
	if err := manifest.Validate(); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func (algorithm Algorithm) valid() bool {
	return algorithm == AlgorithmDenyOverrides ||
		algorithm == AlgorithmAllowOverrides ||
		algorithm == AlgorithmFirstApplicable ||
		algorithm == AlgorithmPriorityOrder
}

func (model Model) valid() bool {
	return model == ModelACL || model == ModelRBAC ||
		model == ModelABAC || model == ModelComposite
}

func validDocument(document json.RawMessage) bool {
	trimmed := bytes.TrimSpace(document)
	if len(trimmed) < 2 {
		return false
	}
	if trimmed[0] != '{' {
		return false
	}
	return json.Valid(trimmed)
}

// Repository is the storage-neutral optimistic-concurrency contract for
// portable policy manifests. Implementations must cooperate with context and
// preserve atomic expected-revision updates without relying on advisory caches.
// Returned manifest containers must remain stable while callers validate/compile
// them; implementations own persistence/trust/durability and their I/O limits.
type Repository interface {
	// Load returns authoritative current state or an error, not cached authorization.
	Load(context.Context) (Manifest, error)
	// Update uses the expected revision (zero for initialization) and a newer
	// validated candidate. Errors may need reconciliation if commit state is unknown.
	Update(context.Context, authorization.Revision, Manifest) (Manifest, error)
}
