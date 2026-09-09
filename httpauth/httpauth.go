// Package httpauth provides the legacy fail-closed net/http authorization
// integration.
//
// Deprecated: use github.com/faustbrian/go-authorization/adapters/http. This
// package remains supported for the longer of 180 days after successor public
// availability and two subsequently published stable root-module minor
// releases.
package httpauth

import (
	"context"
	"net/http"

	authorization "github.com/faustbrian/go-authorization"
	adapter "github.com/faustbrian/go-authorization/adapters/http"
)

var (
	ErrNilAuthorizer    = adapter.ErrNilAuthorizer
	ErrNilRequestMapper = adapter.ErrNilRequestMapper
	ErrNilNextHandler   = adapter.ErrNilNextHandler
)

type Authorizer interface {
	Decide(context.Context, authorization.Request) (authorization.Decision, error)
}

type RequestMapper func(*http.Request) (authorization.Request, error)

type Option func(*options)

type options struct {
	denied http.Handler
	failed http.Handler
}

func WithDeniedHandler(handler http.Handler) Option {
	return func(options *options) {
		if handler != nil {
			options.denied = handler
		}
	}
}

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

func DecisionFromContext(ctx context.Context) (authorization.Decision, bool) {
	return adapter.DecisionFromContext(ctx)
}

func ErrorFromContext(ctx context.Context) (error, bool) {
	return adapter.ErrorFromContext(ctx)
}
