// Package authhttp provides the legacy net/http authorization adapter.
//
// Deprecated: use github.com/faustbrian/go-authorization/adapters/http. This
// package remains supported for the longer of 180 days after successor public
// availability and two subsequently published stable root-module minor
// releases.
package authhttp

import (
	"context"
	"net/http"

	authorization "github.com/faustbrian/go-authorization"
	"github.com/faustbrian/go-authorization/httpauth" //nolint:staticcheck // Preserve released alias identities through the compatibility interval.
)

type Authorizer = httpauth.Authorizer
type RequestMapper = httpauth.RequestMapper
type Option = httpauth.Option

var (
	WithDeniedHandler = httpauth.WithDeniedHandler
	WithErrorHandler  = httpauth.WithErrorHandler
)

func NewHandler(
	authorizer Authorizer,
	mapper RequestMapper,
	next http.Handler,
	options ...Option,
) (http.Handler, error) {
	return httpauth.NewHandler(authorizer, mapper, next, options...)
}

func DecisionFromContext(ctx context.Context) (authorization.Decision, bool) {
	return httpauth.DecisionFromContext(ctx)
}

func ErrorFromContext(ctx context.Context) (error, bool) {
	return httpauth.ErrorFromContext(ctx)
}
