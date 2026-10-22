package abac

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"time"

	authorization "github.com/faustbrian/go-authorization/v4"
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

const (
	// SourceSubject is the serialized subject attribute-map label.
	SourceSubject = "subject"
	// SourceResource is the serialized resource attribute-map label.
	SourceResource = "resource"
	// SourceRequest is the serialized request attribute-map label.
	SourceRequest = "request"
	// SourceEnvironment is the serialized environment attribute-map label.
	SourceEnvironment = "environment"
)

const (
	// OperatorEqual selects the serialized built-in equality operator; see the corresponding typed constructor.
	OperatorEqual = "equal"
	// OperatorExists selects the serialized built-in existence operator; see the corresponding typed constructor.
	OperatorExists = "exists"
	// OperatorIsNull selects the serialized built-in null operator; see the corresponding typed constructor.
	OperatorIsNull = "is_null"
	// OperatorAll selects the serialized built-in all operator; see the corresponding typed constructor.
	OperatorAll = "all"
	// OperatorAny selects the serialized built-in any operator; see the corresponding typed constructor.
	OperatorAny = "any"
	// OperatorNot selects the serialized built-in negation operator; see the corresponding typed constructor.
	OperatorNot = "not"
	// OperatorGreaterThan selects the serialized built-in greater-than operator; see the corresponding typed constructor.
	OperatorGreaterThan = "greater_than"
	// OperatorLessThan selects the serialized built-in less-than operator; see the corresponding typed constructor.
	OperatorLessThan = "less_than"
	// OperatorIn selects the serialized built-in membership operator; see the corresponding typed constructor.
	OperatorIn = "in"
	// OperatorSetContains selects the serialized built-in set-membership operator; see the corresponding typed constructor.
	OperatorSetContains = "set_contains"
	// OperatorHasPrefix selects the serialized built-in prefix operator; see the corresponding typed constructor.
	OperatorHasPrefix = "has_prefix"
	// OperatorHasSuffix selects the serialized built-in suffix operator; see the corresponding typed constructor.
	OperatorHasSuffix = "has_suffix"
	// OperatorStringContains selects the serialized built-in substring operator; see the corresponding typed constructor.
	OperatorStringContains = "string_contains"
	// OperatorIPIn selects the serialized built-in CIDR-membership operator; see the corresponding typed constructor.
	OperatorIPIn = "ip_in"
)

const (
	// ValueNull is the serialized null value-kind label.
	ValueNull = "null"
	// ValueString is the serialized string value-kind label.
	ValueString = "string"
	// ValueBool is the serialized bool value-kind label.
	ValueBool = "bool"
	// ValueInt is the serialized int value-kind label.
	ValueInt = "int"
	// ValueFloat is the serialized float value-kind label.
	ValueFloat = "float"
	// ValueTime is the serialized time value-kind label.
	ValueTime = "time"
	// ValueIP is the serialized ip value-kind label.
	ValueIP = "ip"
	// ValueStringSet is the serialized string_set value-kind label.
	ValueStringSet = "string_set"
)

var (
	// ErrInvalidDocument identifies invalid ABAC document. Compare with errors.Is, not error text.
	ErrInvalidDocument = errors.New("invalid ABAC document")
	// ErrUnsupportedDocumentVersion identifies unsupported ABAC document version. Compare with errors.Is, not error text.
	ErrUnsupportedDocumentVersion = errors.New("unsupported ABAC document version")
	// ErrDocumentLimitExceeded identifies ABAC document size limit exceeded. Compare with errors.Is, not error text.
	ErrDocumentLimitExceeded = errors.New("ABAC document size limit exceeded")
)

// ValueDocument is a tagged literal; only the selected Kind field is consumed.
type ValueDocument struct {
	// Kind selects one supported serialized literal representation; unrelated fields are unused.
	Kind string `json:"kind"`
	// String supplies the string literal when Kind selects string; it is retained plaintext.
	String string `json:"string,omitempty"`
	// Bool supplies the boolean literal when Kind selects bool.
	Bool bool `json:"bool,omitempty"`
	// Int supplies the signed int64 literal when Kind selects int.
	Int int64 `json:"int,omitempty"`
	// Float supplies the finite floating literal when Kind selects float.
	Float float64 `json:"float,omitempty"`
	// Time is parsed as RFC3339Nano then normalized to UTC when Kind selects time.
	Time string `json:"time,omitempty"`
	// IP supplies the parseable address literal when Kind selects ip.
	IP string `json:"ip,omitempty"`
	// StringSet supplies copied/sorted/deduplicated literals when Kind selects string_set.
	StringSet []string `json:"string_set,omitempty"`
}

func (document ValueDocument) build() (authorization.Value, error) {
	switch document.Kind {
	case ValueNull:
		return authorization.NullValue(), nil
	case ValueString:
		return authorization.StringValue(document.String), nil
	case ValueBool:
		return authorization.BoolValue(document.Bool), nil
	case ValueInt:
		return authorization.IntValue(document.Int), nil
	case ValueFloat:
		return authorization.FloatValue(document.Float)
	case ValueTime:
		value, err := time.Parse(time.RFC3339Nano, document.Time)
		if err != nil {
			return authorization.Value{}, ErrInvalidDocument
		}
		return authorization.TimeValue(value), nil
	case ValueIP:
		value, err := netip.ParseAddr(document.IP)
		if err != nil {
			return authorization.Value{}, ErrInvalidDocument
		}
		return authorization.IPValue(value), nil
	case ValueStringSet:
		return authorization.StringSetValue(document.StringSet), nil
	default:
		return authorization.Value{}, ErrInvalidDocument
	}
}

// ConditionDocument is editable recursive expression data; Build visits only
// operator-selected children before constructing validated Conditions.
type ConditionDocument struct {
	// Operator selects one supported expression operation; unrelated fields may remain unused.
	Operator string `json:"operator"`
	// Source selects the request fact map, not an external data provider.
	Source string `json:"source,omitempty"`
	// Attribute names an exact map key for a leaf operation.
	Attribute authorization.AttributeName `json:"attribute,omitempty"`
	// Value supplies the comparison literal for equal/greater/less operations.
	Value *ValueDocument `json:"value,omitempty"`
	// Values supplies the same-kind membership candidates for in.
	Values []ValueDocument `json:"values,omitempty"`
	// Conditions supplies ordered children for all/any; Build validates visited children.
	Conditions []ConditionDocument `json:"conditions,omitempty"`
	// Condition supplies the single child for not; other operators do not consume it.
	Condition *ConditionDocument `json:"condition,omitempty"`
	// Text supplies the string operand for set/string operations, not executable input.
	Text string `json:"text,omitempty"`
	// Prefix is the CIDR operand for ip_in, normalized by IPIn.
	Prefix string `json:"prefix,omitempty"`
}

func (document ConditionDocument) build() (Condition, error) {
	switch document.Operator {
	case OperatorAll, OperatorAny:
		conditions := make([]Condition, len(document.Conditions))
		for index, child := range document.Conditions {
			condition, err := child.build()
			if err != nil {
				return nil, err
			}
			conditions[index] = condition
		}
		if document.Operator == OperatorAll {
			return All(conditions...), nil
		}
		return Any(conditions...), nil
	case OperatorNot:
		if document.Condition == nil {
			return nil, ErrInvalidDocument
		}
		condition, err := document.Condition.build()
		if err != nil {
			return nil, err
		}
		return Not(condition), nil
	}

	reference, err := document.reference()
	if err != nil {
		return nil, err
	}
	switch document.Operator {
	case OperatorExists:
		return Exists(reference), nil
	case OperatorIsNull:
		return IsNull(reference), nil
	case OperatorEqual, OperatorGreaterThan, OperatorLessThan:
		if document.Value == nil {
			return nil, ErrInvalidDocument
		}
		value, err := document.Value.build()
		if err != nil {
			return nil, err
		}
		if document.Operator == OperatorEqual {
			return Equal(reference, value), nil
		}
		if document.Operator == OperatorGreaterThan {
			return GreaterThan(reference, value), nil
		}
		return LessThan(reference, value), nil
	case OperatorIn:
		values := make([]authorization.Value, len(document.Values))
		for index, valueDocument := range document.Values {
			value, err := valueDocument.build()
			if err != nil {
				return nil, err
			}
			values[index] = value
		}
		return In(reference, values...), nil
	case OperatorSetContains:
		return SetContains(reference, document.Text), nil
	case OperatorHasPrefix:
		return HasPrefix(reference, document.Text), nil
	case OperatorHasSuffix:
		return HasSuffix(reference, document.Text), nil
	case OperatorStringContains:
		return StringContains(reference, document.Text), nil
	case OperatorIPIn:
		prefix, err := netip.ParsePrefix(document.Prefix)
		if err != nil {
			return nil, ErrInvalidDocument
		}
		return IPIn(reference, prefix), nil
	default:
		return nil, ErrInvalidDocument
	}
}

func (document ConditionDocument) reference() (Reference, error) {
	var source Source
	switch document.Source {
	case SourceSubject:
		source = Subject
	case SourceResource:
		source = Resource
	case SourceRequest:
		source = Request
	case SourceEnvironment:
		source = Environment
	default:
		return Reference{}, ErrInvalidDocument
	}
	if document.Attribute == "" {
		return Reference{}, ErrInvalidDocument
	}
	return Reference{Source: source, Name: document.Attribute}, nil
}

// RuleDocument is editable scoped rule input with either inline or versioned
// named-condition selection, not authenticated facts.
type RuleDocument struct {
	// ID is an exact application-defined label; keep diagnostic identifiers non-secret.
	ID authorization.PolicyID `json:"id"`
	// Priority orders higher values first where the selected model supports ordering.
	Priority int `json:"priority,omitempty"`
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
	// Condition supplies editable inline expression data; Build validates the selected tree.
	Condition *ConditionDocument `json:"condition,omitempty"`
	// ConditionName selects an exact named condition instead of an inline Condition.
	ConditionName string `json:"condition_name,omitempty"`
	// ConditionVersion must be nonzero with ConditionName, otherwise zero.
	ConditionVersion uint64 `json:"condition_version,omitempty"`
}

// NamedConditionDocument binds editable expression data to a nonzero name/version.
type NamedConditionDocument struct {
	// Name is the exact application label; do not place secrets in error-visible names.
	Name string `json:"name"`
	// Version is a nonzero named-condition version, independent of DocumentVersion.
	Version uint64 `json:"version"`
	// Condition supplies editable inline expression data; Build validates the selected tree.
	Condition ConditionDocument `json:"condition"`
}

// Document is the editable application version-1 JSON model, not an
// authenticated artifact. Build validates the selected model after caller-owned
// construction/JSON materialization; inactive fields can be present but unused.
type Document struct {
	// Version is the application model version; Build requires DocumentVersion (1).
	Version uint64 `json:"version"`
	// Limits supplies positive count/depth/cost overrides; non-positive fields retain model defaults.
	Limits Limits `json:"limits,omitempty"`
	// Rules supplies editable rule definitions; Build/New validates and sorts them.
	Rules []RuleDocument `json:"rules"`
	// NamedConditions supplies editable named/versioned expression definitions.
	NamedConditions []NamedConditionDocument `json:"named_conditions"`
}

// Build constructs and validates a fresh model evaluator for DocumentVersion.
// It does not impose the encoded-byte cap or authenticate provenance. Caller-owned
// document containers must stay immutable during construction.
func (document Document) Build() (*Evaluator, error) {
	if document.Version != DocumentVersion {
		return nil, ErrUnsupportedDocumentVersion
	}
	limits := normalizedLimits(document.Limits)
	for index := range document.NamedConditions {
		if err := validateConditionDocumentLimits(&document.NamedConditions[index].Condition, limits); err != nil {
			return nil, fmt.Errorf("named condition %d: %w", index, err)
		}
	}
	for index := range document.Rules {
		if document.Rules[index].Condition != nil {
			if err := validateConditionDocumentLimits(document.Rules[index].Condition, limits); err != nil {
				return nil, fmt.Errorf("rule %d: %w", index, err)
			}
		}
	}
	named := make([]NamedCondition, len(document.NamedConditions))
	for index, definition := range document.NamedConditions {
		condition, err := definition.Condition.build()
		if err != nil {
			return nil, fmt.Errorf("named condition %d: %w", index, err)
		}
		named[index] = NamedCondition{
			Name: definition.Name, Version: definition.Version,
			Condition: condition,
		}
	}
	rules := make([]Rule, len(document.Rules))
	for index, ruleDocument := range document.Rules {
		effect, err := parseDocumentEffect(ruleDocument.Effect)
		if err != nil {
			return nil, fmt.Errorf("rule %d: %w", index, err)
		}
		var condition Condition
		if ruleDocument.Condition != nil {
			condition, err = ruleDocument.Condition.build()
			if err != nil {
				return nil, fmt.Errorf("rule %d: %w", index, err)
			}
		}
		rules[index] = Rule{
			ID: ruleDocument.ID, Priority: ruleDocument.Priority,
			Tenant: ruleDocument.Tenant, Action: ruleDocument.Action,
			ResourceType: ruleDocument.ResourceType,
			ResourceID:   ruleDocument.ResourceID, Effect: effect,
			Condition: condition, ConditionName: ruleDocument.ConditionName,
			ConditionVersion: ruleDocument.ConditionVersion,
		}
	}
	return New(rules, named, WithLimits(document.Limits))
}

func validateConditionDocumentLimits(root *ConditionDocument, limits Limits) error {
	type frame struct {
		condition *ConditionDocument
		depth     int
	}
	stack := []frame{{condition: root, depth: 1}}
	for len(stack) > 0 {
		last := len(stack) - 1
		current := stack[last]
		stack = stack[:last]
		if current.depth > limits.MaxDepth {
			return ErrDepthExceeded
		}

		children := make([]*ConditionDocument, 0)
		switch current.condition.Operator {
		case OperatorAll, OperatorAny:
			for index := range current.condition.Conditions {
				children = append(children, &current.condition.Conditions[index])
			}
		case OperatorNot:
			if current.condition.Condition != nil {
				children = append(children, current.condition.Condition)
			}
		}
		for index := len(children) - 1; index >= 0; index-- {
			stack = append(stack, frame{condition: children[index], depth: current.depth + 1})
		}
	}
	return nil
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
