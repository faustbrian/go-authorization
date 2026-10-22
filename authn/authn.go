// Package authn maps immutable authenticated principals into authorization
// subjects without making authentication depend on authorization. Subject maps
// trusted stable Principal methods; it verifies neither signatures/credentials
// nor tenant membership. It owns no I/O/lifecycle and accepts no context.
// Claims, mapping configuration and principal callbacks must remain immutable;
// literals are copied/normalized into Values, not protected-memory storage.
package authn

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"strconv"
	"time"

	authorization "github.com/faustbrian/go-authorization/v4"
)

const defaultMaxGroups = 100

var (
	// ErrNilPrincipal identifies authorization authentication principal is nil. Compare with errors.Is, not error text.
	ErrNilPrincipal = errors.New("authorization authentication principal is nil")
	// ErrAnonymousPrincipal identifies authorization authentication principal is anonymous. Compare with errors.Is, not error text.
	ErrAnonymousPrincipal = errors.New("authorization authentication principal is anonymous")
	// ErrInvalidPrincipal identifies authorization authentication principal is invalid. Compare with errors.Is, not error text.
	ErrInvalidPrincipal = errors.New("authorization authentication principal is invalid")
	// ErrInvalidConfig identifies authorization authentication mapping config is invalid. Compare with errors.Is, not error text.
	ErrInvalidConfig = errors.New("authorization authentication mapping config is invalid")
	// ErrMissingClaim identifies authorization authentication claim is missing. Compare with errors.Is, not error text.
	ErrMissingClaim = errors.New("authorization authentication claim is missing")
	// ErrUnsupportedClaim identifies authorization authentication claim type is unsupported. Compare with errors.Is, not error text.
	ErrUnsupportedClaim = errors.New("authorization authentication claim type is unsupported")
	// ErrInvalidGroups identifies authorization authentication groups are invalid. Compare with errors.Is, not error text.
	ErrInvalidGroups = errors.New("authorization authentication groups are invalid")
	// ErrGroupLimitExceeded identifies authorization authentication group limit exceeded. Compare with errors.Is, not error text.
	ErrGroupLimitExceeded = errors.New("authorization authentication group limit exceeded")
)

// Principal is implemented by authentication Principal values and keeps
// this adapter independent of authentication's package lifecycle.
type Principal interface {
	// IsAnonymous distinguishes anonymous input; it is not a verification operation here.
	IsAnonymous() bool
	// Subject returns a stable nonempty authenticated identity supplied by the application.
	Subject() string
	// Claims returns a stable graph during mapping; claim authority/byte bounds belong to the caller.
	Claims() map[string]any
}

// Config selects exact required claims and output subject kind. Only
// group count is admitted here; map/string/literal conversion allocations are not byte-capped.
type Config struct {
	// Kind is the caller-selected representation/category, not an authentication assertion.
	Kind authorization.SubjectKind
	// AttributeClaims maps exact output attributes to required claim names; input maps must remain stable.
	AttributeClaims map[authorization.AttributeName]string
	// GroupsClaim is an optional required string-collection claim when nonempty.
	GroupsClaim string
	// MaxGroups caps admitted membership count; zero/default policy selects 100.
	MaxGroups int
}

// Subject rejects literal nil, anonymous/empty identity and invalid mapping,
// then constructs a new subject. Typed-nil principals/callback panics are not
// contained. All configured claims must exist; unsupported types fail with zero
// subject. Groups are copied before count rejection and their order is preserved.
// json.Number tries int64, then finite float64 (large integers may round).
// It does not populate/verify Request.Tenant or enforce authentication policy.
func Subject(principal Principal, config Config) (authorization.Subject, error) {
	if principal == nil {
		return authorization.Subject{}, ErrNilPrincipal
	}
	if principal.IsAnonymous() {
		return authorization.Subject{}, ErrAnonymousPrincipal
	}
	if principal.Subject() == "" {
		return authorization.Subject{}, ErrInvalidPrincipal
	}
	if config.Kind == "" || config.MaxGroups < 0 {
		return authorization.Subject{}, ErrInvalidConfig
	}
	if config.MaxGroups == 0 {
		config.MaxGroups = defaultMaxGroups
	}
	for attribute, claim := range config.AttributeClaims {
		if attribute == "" || claim == "" {
			return authorization.Subject{}, ErrInvalidConfig
		}
	}

	claims := principal.Claims()
	attributes := make(authorization.Attributes, len(config.AttributeClaims))
	for attribute, claim := range config.AttributeClaims {
		raw, exists := claims[claim]
		if !exists {
			return authorization.Subject{}, fmt.Errorf("claim %q: %w", claim, ErrMissingClaim)
		}
		value, err := claimValue(raw)
		if err != nil {
			return authorization.Subject{}, fmt.Errorf("claim %q: %w", claim, err)
		}
		attributes[attribute] = value
	}

	groups := []authorization.SubjectID(nil)
	if config.GroupsClaim != "" {
		raw, exists := claims[config.GroupsClaim]
		if !exists {
			return authorization.Subject{}, fmt.Errorf("claim %q: %w", config.GroupsClaim, ErrMissingClaim)
		}
		values, ok := stringCollection(raw)
		if !ok {
			return authorization.Subject{}, ErrInvalidGroups
		}
		if len(values) > config.MaxGroups {
			return authorization.Subject{}, ErrGroupLimitExceeded
		}
		groups = make([]authorization.SubjectID, len(values))
		for index, value := range values {
			if value == "" {
				return authorization.Subject{}, ErrInvalidGroups
			}
			groups[index] = authorization.SubjectID(value)
		}
	}

	return authorization.Subject{
		Kind: config.Kind, ID: authorization.SubjectID(principal.Subject()),
		Groups: groups, Attributes: attributes,
	}, nil
}

func stringCollection(raw any) ([]string, bool) {
	switch values := raw.(type) {
	case []string:
		return append([]string(nil), values...), true
	case []any:
		strings := make([]string, len(values))
		for index, value := range values {
			stringValue, ok := value.(string)
			if !ok {
				return nil, false
			}
			strings[index] = stringValue
		}

		return strings, true
	default:
		return nil, false
	}
}

func claimValue(raw any) (authorization.Value, error) {
	switch value := raw.(type) {
	case nil:
		return authorization.NullValue(), nil
	case string:
		return authorization.StringValue(value), nil
	case bool:
		return authorization.BoolValue(value), nil
	case int:
		return authorization.IntValue(int64(value)), nil
	case int8:
		return authorization.IntValue(int64(value)), nil
	case int16:
		return authorization.IntValue(int64(value)), nil
	case int32:
		return authorization.IntValue(int64(value)), nil
	case int64:
		return authorization.IntValue(value), nil
	case uint:
		return unsignedValue(uint64(value))
	case uint8:
		return authorization.IntValue(int64(value)), nil
	case uint16:
		return authorization.IntValue(int64(value)), nil
	case uint32:
		return authorization.IntValue(int64(value)), nil
	case uint64:
		return unsignedValue(value)
	case float32:
		return authorization.FloatValue(float64(value))
	case float64:
		return authorization.FloatValue(value)
	case json.Number:
		if integer, err := strconv.ParseInt(value.String(), 10, 64); err == nil {
			return authorization.IntValue(integer), nil
		}
		floating, err := strconv.ParseFloat(value.String(), 64)
		if err != nil {
			return authorization.Value{}, ErrUnsupportedClaim
		}
		return authorization.FloatValue(floating)
	case time.Time:
		return authorization.TimeValue(value), nil
	case netip.Addr:
		return authorization.IPValue(value), nil
	case []string:
		return authorization.StringSetValue(value), nil
	case []any:
		strings, ok := stringCollection(value)
		if !ok {
			return authorization.Value{}, ErrUnsupportedClaim
		}
		return authorization.StringSetValue(strings), nil
	default:
		return authorization.Value{}, ErrUnsupportedClaim
	}
}

func unsignedValue(value uint64) (authorization.Value, error) {
	if value > math.MaxInt64 {
		return authorization.Value{}, ErrUnsupportedClaim
	}
	return authorization.IntValue(int64(value)), nil
}
