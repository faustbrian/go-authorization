// Package httpauth provides the legacy fail-closed net/http authorization
// integration.
//
// Deprecated: use github.com/faustbrian/go-authorization/v3/adapters/http. This
// package remains supported for the longer of 180 days after successor public
// availability and two subsequently published stable root-module minor
// releases.
package httpauth

import (
	"context"
	"net/http"

	authorization "github.com/faustbrian/go-authorization/v3"
	adapter "github.com/faustbrian/go-authorization/v3/adapters/http"
)

var (
	// ErrNilAuthorizer preserves the direct adapter error identity for errors.Is.
	ErrNilAuthorizer = adapter.ErrNilAuthorizer
	// ErrNilRequestMapper preserves the direct adapter error identity for errors.Is.
	ErrNilRequestMapper = adapter.ErrNilRequestMapper
	// ErrNilNextHandler preserves the direct adapter error identity for errors.Is.
	ErrNilNextHandler = adapter.ErrNilNextHandler
)

// Authorizer decides from trusted caller-mapped input. Implementations must
// cooperate with ctx and support concurrent reuse; this seam performs no authentication.
type Authorizer interface {
	// Decide returns a valid outcome or error; map errors to failure, never allow.
	Decide(context.Context, authorization.Request) (authorization.Decision, error)
}

// RequestMapper maps trusted HTTP identity/scope/facts synchronously;
// authenticate upstream and do not trust client tenant/ownership claims.
type RequestMapper func(*http.Request) (authorization.Request, error)

// Option configures construction synchronously; nil/custom options may panic.
type Option func(*options)

type options struct {
	denied http.Handler
	failed http.Handler
}

// WithDeniedHandler selects denial handling; nil preserves the default 403 response.
func WithDeniedHandler(handler http.Handler) Option {
	return func(options *options) {
		if handler != nil {
			options.denied = handler
		}
	}
}

// WithErrorHandler selects failure handling; nil preserves the default 500 response.
func WithErrorHandler(handler http.Handler) Option {
	return func(options *options) {
		if handler != nil {
			options.failed = handler
		}
	}
}

// NewHandler maps each HTTP request, evaluates it, and invokes next only for
// explicit allow decisions. Mapper and evaluation failures use the error
// handler; deny and not-applicable outcomes use the denial handler.
func NewHandler(
	authorizer Authorizer,
	mapper RequestMapper,
	next http.Handler,
	handlerOptions ...Option,
) (http.Handler, error) {
	if authorizer == nil {
		return nil, ErrNilAuthorizer
	}
	if mapper == nil {
		return nil, ErrNilRequestMapper
	}
	if next == nil {
		return nil, ErrNilNextHandler
	}
	configured := options{}
	for _, option := range handlerOptions {
		option(&configured)
	}
	options := make([]adapter.Option, 0, 2)
	if configured.denied != nil {
		options = append(options, adapter.WithDeniedHandler(configured.denied))
	}
	if configured.failed != nil {
		options = append(options, adapter.WithErrorHandler(configured.failed))
	}
	return adapter.NewHandler(authorizer, adapter.RequestMapper(mapper), next, options...)
}

// DecisionFromContext returns the attached decision by value; its slices remain shared.
func DecisionFromContext(ctx context.Context) (authorization.Decision, bool) {
	return adapter.DecisionFromContext(ctx)
}

// ErrorFromContext returns raw mapper/evaluator error state for a protected local handler.
func ErrorFromContext(ctx context.Context) (error, bool) {
	return adapter.ErrorFromContext(ctx)
}
