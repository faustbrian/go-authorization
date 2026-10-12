// Package authhttp provides the legacy net/http authorization adapter.
//
// Deprecated: use github.com/faustbrian/go-authorization/v3/adapters/http. This
// package remains supported for the longer of 180 days after successor public
// availability and two subsequently published stable root-module minor
// releases.
//
//lint:file-ignore SA1019 Preserve released alias identities through the compatibility interval.
package authhttp

import (
	"context"
	"net/http"

	authorization "github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-authorization/v3/httpauth" //nolint:staticcheck // Preserve released alias identities through the compatibility interval.
)

// Authorizer is the released httpauth.Authorizer alias; identity is preserved.
type Authorizer = httpauth.Authorizer

// RequestMapper maps trusted HTTP identity/scope/facts synchronously;
// authenticate upstream and do not trust client tenant/ownership claims.
type RequestMapper = httpauth.RequestMapper

// Option configures construction synchronously; nil/custom options may panic.
type Option = httpauth.Option

var (
	// WithDeniedHandler preserves the released option function identity; nil keeps default denial handling.
	WithDeniedHandler = httpauth.WithDeniedHandler
	// WithErrorHandler preserves the released option function identity; nil keeps default failure handling.
	WithErrorHandler = httpauth.WithErrorHandler
)

// NewHandler delegates to the released HTTP facade and direct fail-closed adapter.
func NewHandler(
	authorizer Authorizer,
	mapper RequestMapper,
	next http.Handler,
	options ...Option,
) (http.Handler, error) {
	return httpauth.NewHandler(authorizer, mapper, next, options...)
}

// DecisionFromContext returns a decision by value with shared diagnostic slices.
func DecisionFromContext(ctx context.Context) (authorization.Decision, bool) {
	return httpauth.DecisionFromContext(ctx)
}

// ErrorFromContext returns raw local failure state; callers own redaction before exposure.
func ErrorFromContext(ctx context.Context) (error, bool) {
	return httpauth.ErrorFromContext(ctx)
}
