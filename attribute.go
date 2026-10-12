package authorization

import (
	"errors"
	"math"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"time"
)

// ErrInvalidFloat identifies attribute float must be finite. Compare with errors.Is, not error text.
var ErrInvalidFloat = errors.New("attribute float must be finite")

// ValueKind is the closed set of supported attribute representations.
type ValueKind uint8

const (
	// ValueMissing is the zero/missing representation, distinct from null.
	ValueMissing ValueKind = iota
	// ValueNull is explicit null.
	ValueNull
	// ValueString is exact text.
	ValueString
	// ValueBool is a boolean.
	ValueBool
	// ValueInt is a signed 64-bit integer.
	ValueInt
	// ValueFloat is a finite float64.
	ValueFloat
	// ValueTime is a UTC instant without monotonic data.
	ValueTime
	// ValueIP is an unmapped netip address, possibly invalid.
	ValueIP
	// ValueStringSet is an immutable sorted deduplicated string set.
	ValueStringSet
)

// Value is an immutable typed attribute value. Its zero value represents an
// invalid or missing value and is distinct from explicit null.
type Value struct {
	kind      ValueKind
	stringVal string
	boolVal   bool
	intVal    int64
	floatVal  float64
	timeVal   time.Time
	ipVal     netip.Addr
	setVal    []string
}

// NullValue returns explicit null, distinct from the zero missing Value.
func NullValue() Value {
	return Value{kind: ValueNull}
}

// StringValue retains text without copying, normalization or byte admission.
func StringValue(value string) Value {
	return Value{kind: ValueString, stringVal: value}
}

// BoolValue wraps a boolean without coercion.
func BoolValue(value bool) Value {
	return Value{kind: ValueBool, boolVal: value}
}

// IntValue wraps a signed 64-bit integer without coercion.
func IntValue(value int64) Value {
	return Value{kind: ValueInt, intVal: value}
}

// FloatValue rejects NaN/infinities with ErrInvalidFloat; finite values are retained.
func FloatValue(value float64) (Value, error) {
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return Value{}, ErrInvalidFloat
	}

	return Value{kind: ValueFloat, floatVal: value}, nil
}

// MustFloatValue returns FloatValue or panics with ErrInvalidFloat; use only for trusted constants.
func MustFloatValue(value float64) Value {
	attribute, err := FloatValue(value)
	if err != nil {
		panic(err)
	}

	return attribute
}

// TimeValue drops monotonic data and normalizes the instant to UTC.
func TimeValue(value time.Time) Value {
	return Value{kind: ValueTime, timeVal: value.Round(0).UTC()}
}

// IPValue normalizes IPv4-mapped addresses with Unmap; invalid addresses remain invalid.
func IPValue(value netip.Addr) Value {
	return Value{kind: ValueIP, ipVal: value.Unmap()}
}

// StringSetValue copies, sorts lexically and deduplicates values before returning immutable set state; no input/cardinality/byte cap is enforced.
func StringSetValue(values []string) Value {
	set := append([]string(nil), values...)
	sort.Strings(set)
	unique := set[:0]
	for _, value := range set {
		if len(unique) == 0 || unique[len(unique)-1] != value {
			unique = append(unique, value)
		}
	}

	return Value{kind: ValueStringSet, setVal: unique}
}

// Kind reports the representation; zero is ValueMissing.
func (value Value) Kind() ValueKind {
	return value.kind
}

// String returns stored text and whether the value is a string.
func (value Value) String() (string, bool) {
	return value.stringVal, value.kind == ValueString
}

// Bool returns the stored boolean and whether that representation is present.
func (value Value) Bool() (bool, bool) {
	return value.boolVal, value.kind == ValueBool
}

// Int returns the stored int64 and whether that representation is present.
func (value Value) Int() (int64, bool) {
	return value.intVal, value.kind == ValueInt
}

// Float returns the stored finite float and whether that representation is present.
func (value Value) Float() (float64, bool) {
	return value.floatVal, value.kind == ValueFloat
}

// Time returns the stored UTC instant and whether that representation is present.
func (value Value) Time() (time.Time, bool) {
	return value.timeVal, value.kind == ValueTime
}

// IP returns the stored unmapped address and whether that representation is present.
func (value Value) IP() (netip.Addr, bool) {
	return value.ipVal, value.kind == ValueIP
}

// StringSet returns a copied sorted/deduplicated slice, or (nil, false) for a non-set.
func (value Value) StringSet() ([]string, bool) {
	if value.kind != ValueStringSet {
		return nil, false
	}

	return append([]string(nil), value.setVal...), true
}

// CollectionLength reports the cardinality of collection values.
func (value Value) CollectionLength() (int, bool) {
	if value.kind != ValueStringSet {
		return 0, false
	}

	return len(value.setVal), true
}

// Equal reports structural equality without type coercion.
func (value Value) Equal(other Value) bool {
	if value.kind != other.kind {
		return false
	}

	switch value.kind {
	case ValueMissing, ValueNull:
		return true
	case ValueString:
		return value.stringVal == other.stringVal
	case ValueBool:
		return value.boolVal == other.boolVal
	case ValueInt:
		return value.intVal == other.intVal
	case ValueFloat:
		return value.floatVal == other.floatVal
	case ValueTime:
		return value.timeVal.Equal(other.timeVal)
	case ValueIP:
		return value.ipVal == other.ipVal
	case ValueStringSet:
		return slices.Equal(value.setVal, other.setVal)
	default:
		return false
	}
}

// Compare orders strings, integers, finite floats and times of the same kind.
// Other/cross-kind pairs return (0, false); no numeric/string coercion occurs.
func (value Value) Compare(other Value) (int, bool) {
	if value.kind != other.kind {
		return 0, false
	}

	switch value.kind {
	case ValueString:
		return strings.Compare(value.stringVal, other.stringVal), true
	case ValueInt:
		return compareOrdered(value.intVal, other.intVal), true
	case ValueFloat:
		return compareOrdered(value.floatVal, other.floatVal), true
	case ValueTime:
		return value.timeVal.Compare(other.timeVal), true
	default:
		return 0, false
	}
}

func compareOrdered[T ~int64 | ~float64](left, right T) int {
	if left < right {
		return -1
	}
	if left > right {
		return 1
	}
	return 0
}
