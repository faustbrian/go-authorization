package policy

import (
	"encoding/json"
	"errors"
	"fmt"

	authorization "github.com/faustbrian/go-authorization/v3"
)

const (
	defaultMaxDocumentBytes      = 1 << 20
	defaultMaxPolicies           = 1000
	defaultMaxTotalDocumentBytes = 16 << 20
)

var (
	// ErrNilDecoder identifies policy decoder is nil. Compare with errors.Is, not error text.
	ErrNilDecoder = errors.New("policy decoder is nil")
	// ErrMissingDecoder identifies policy decoder is not registered. Compare with errors.Is, not error text.
	ErrMissingDecoder = errors.New("policy decoder is not registered")
	// ErrNilEvaluator identifies policy decoder returned a nil evaluator. Compare with errors.Is, not error text.
	ErrNilEvaluator = errors.New("policy decoder returned a nil evaluator")
	// ErrDocumentLimitExceeded identifies policy document size limit exceeded. Compare with errors.Is, not error text.
	ErrDocumentLimitExceeded = errors.New("policy document size limit exceeded")
	// ErrPolicyLimitExceeded identifies policy compiler policy limit exceeded. Compare with errors.Is, not error text.
	ErrPolicyLimitExceeded = errors.New("policy compiler policy limit exceeded")
	// ErrTotalDocumentLimitExceeded identifies policy compiler total document size limit exceeded. Compare with errors.Is, not error text.
	ErrTotalDocumentLimitExceeded = errors.New("policy compiler total document size limit exceeded")
)

// Decoder validates model semantics and returns a reusable evaluator. Input
// RawMessage is borrowed; do not mutate it, and bound model parsing/construction
// before allocation where possible. No context/panic/I/O sandbox is supplied;
// shared decoders/evaluators must be immutable and concurrency-safe.
type Decoder interface {
	// Decode returns a non-nil reusable evaluator or an error; protect raw cause diagnostics.
	Decode(json.RawMessage) (authorization.Evaluator, error)
}

// DecoderFunc adapts trusted synchronous decoding code; nil functions panic on use.
type DecoderFunc func(json.RawMessage) (authorization.Evaluator, error)

// Decode calls the borrowed function directly without context or panic recovery.
func (decode DecoderFunc) Decode(
	document json.RawMessage,
) (authorization.Evaluator, error) {
	return decode(document)
}

// CompilerLimits admits selected count/document sizes after envelope
// validation, not total callback/parser allocations. Non-positive fields retain defaults.
type CompilerLimits struct {
	// MaxDocumentBytes caps each compiled record after envelope validation; default is 1 MiB.
	MaxDocumentBytes int
	// MaxPolicies admits policy count; default is 1000, not a total byte budget.
	MaxPolicies int
	// MaxTotalDocumentBytes caps compiled record-byte total; default is 16 MiB.
	MaxTotalDocumentBytes int
}

// CompilerOption runs synchronously at construction; nil/custom options
// may panic and must not retain mutable compiler access.
type CompilerOption func(*Compiler)

// WithCompilerLimits applies positive limits only, retaining defaults for
// zero/negative values. Callers select representable finite budgets.
func WithCompilerLimits(limits CompilerLimits) CompilerOption {
	return func(compiler *Compiler) {
		if limits.MaxDocumentBytes > 0 {
			compiler.limits.MaxDocumentBytes = limits.MaxDocumentBytes
		}
		if limits.MaxPolicies > 0 {
			compiler.limits.MaxPolicies = limits.MaxPolicies
		}
		if limits.MaxTotalDocumentBytes > 0 {
			compiler.limits.MaxTotalDocumentBytes = limits.MaxTotalDocumentBytes
		}
	}
}

// Compiler activates portable manifests through an explicit model decoder
// registry. The registry is copied at construction and is safe for concurrent
// Compile calls when its decoders are safe for concurrent use.
type Compiler struct {
	decoders map[Model]Decoder
	limits   CompilerLimits
}

// NewCompiler copies registry keys but borrows decoder instances. Literal
// nil decoders are rejected; typed-nil decoders and nil options are not guarded.
// Registry model names need not be one of Manifest.Validate accepted models.
func NewCompiler(
	decoders map[Model]Decoder,
	options ...CompilerOption,
) (*Compiler, error) {
	compiler := &Compiler{
		decoders: make(map[Model]Decoder, len(decoders)),
		limits: CompilerLimits{
			MaxDocumentBytes:      defaultMaxDocumentBytes,
			MaxPolicies:           defaultMaxPolicies,
			MaxTotalDocumentBytes: defaultMaxTotalDocumentBytes,
		},
	}
	for model, decoder := range decoders {
		if decoder == nil {
			return nil, fmt.Errorf("model %q: %w", model, ErrNilDecoder)
		}
		compiler.decoders[model] = decoder
	}
	for _, option := range options {
		option(compiler)
	}
	return compiler, nil
}

// Compile envelope-validates before count/per-record/aggregate byte admission,
// then invokes decoders in order and builds one snapshot. Partial decoder side
// effects may have occurred if a later record fails. Raw JSON is borrowed and
// callbacks are contextless/not panic-contained; typed-nil evaluators are not
// rejected here. Admission is not a pre-envelope-parser or whole-process heap cap.
func (compiler *Compiler) Compile(
	manifest Manifest,
) (*authorization.Snapshot, error) {
	if err := manifest.Validate(); err != nil {
		return nil, err
	}
	if len(manifest.Policies) > compiler.limits.MaxPolicies {
		return nil, ErrPolicyLimitExceeded
	}

	definitions := make([]authorization.PolicyDefinition, len(manifest.Policies))
	totalDocumentBytes := 0
	for index, record := range manifest.Policies {
		if len(record.Document) > compiler.limits.MaxDocumentBytes {
			return nil, fmt.Errorf("policy %q: %w", record.ID, ErrDocumentLimitExceeded)
		}
		if len(record.Document) > compiler.limits.MaxTotalDocumentBytes-totalDocumentBytes {
			return nil, ErrTotalDocumentLimitExceeded
		}
		totalDocumentBytes = totalDocumentBytes + len(record.Document)
		decoder, exists := compiler.decoders[record.Model]
		if !exists {
			return nil, fmt.Errorf("policy %q model %q: %w", record.ID, record.Model, ErrMissingDecoder)
		}
		evaluator, err := decoder.Decode(record.Document)
		if err != nil {
			return nil, fmt.Errorf("policy %q model %q: %w", record.ID, record.Model, err)
		}
		if evaluator == nil {
			return nil, fmt.Errorf("policy %q model %q: %w", record.ID, record.Model, ErrNilEvaluator)
		}

		definition := authorization.PolicyDefinition{
			ID:        record.ID,
			Revision:  record.Revision,
			Priority:  record.Priority,
			Metadata:  record.Metadata,
			Evaluator: evaluator,
		}
		if record.ActiveFrom != nil {
			definition.ActiveFrom = *record.ActiveFrom
		}
		if record.ActiveUntil != nil {
			definition.ActiveUntil = *record.ActiveUntil
		}
		definitions[index] = definition
	}

	algorithms := map[Algorithm]authorization.CombiningAlgorithm{
		AlgorithmDenyOverrides:   authorization.DenyOverrides,
		AlgorithmAllowOverrides:  authorization.AllowOverrides,
		AlgorithmFirstApplicable: authorization.FirstApplicable,
		AlgorithmPriorityOrder:   authorization.PriorityOrder,
	}
	return authorization.NewSnapshot(
		manifest.Revision,
		algorithms[manifest.Algorithm],
		definitions...,
	)
}
