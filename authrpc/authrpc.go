// Package authrpc provides the legacy fail-closed JSON-RPC authorization
// middleware.
//
// Deprecated: use github.com/faustbrian/go-authorization/v3/adapters/jsonrpc.
// This package remains supported for the longer of 180 days after successor
// public availability and two subsequently published stable root-module minor
// releases.
package authrpc

import (
	"context"
	"encoding/json"

	authorization "github.com/faustbrian/go-authorization/v3"
	adapter "github.com/faustbrian/go-authorization/v3/adapters/jsonrpc"
	jsonrpc "github.com/faustbrian/go-jsonrpc"
)

// CodeForbidden is the application JSON-RPC forbidden code (-32001).
const CodeForbidden = -32001

var (
	// ErrNilAuthorizer preserves the direct adapter error identity for errors.Is.
	ErrNilAuthorizer = adapter.ErrNilAuthorizer
	// ErrNilRequestMapper preserves the direct adapter error identity for errors.Is.
	ErrNilRequestMapper = adapter.ErrNilRequestMapper
)

// Authorizer decides from trusted caller-mapped input. Implementations must
// cooperate with ctx and support concurrent reuse; this seam performs no authentication.
type Authorizer interface {
	// Decide returns a valid outcome or error; map errors to failure, never allow.
	Decide(context.Context, authorization.Request) (authorization.Decision, error)
}

// RequestMapper maps borrowed raw parameters/context to trusted policy facts;
// it must be synchronous, cooperative and safe for concurrent handler reuse.
type RequestMapper func(context.Context, json.RawMessage) (authorization.Request, error)

// DeniedError maps a non-allow decision; custom output owns privacy and byte policy.
type DeniedError func(authorization.Decision) *jsonrpc.Error

// ErrorMapper maps raw local causes; do not expose secrets in JSON-RPC data/messages.
type ErrorMapper func(error) *jsonrpc.Error

// Option configures construction synchronously; nil/custom options may panic.
type Option func(*options)

type options struct {
	denied DeniedError
	failed ErrorMapper
}

// WithDeniedError selects denial mapping; nil retains the bounded forbidden default.
func WithDeniedError(mapper DeniedError) Option {
	return func(options *options) {
		if mapper != nil {
			options.denied = mapper
		}
	}
}

// WithErrorMapper selects failure mapping; nil retains the generic internal-error default.
func WithErrorMapper(mapper ErrorMapper) Option {
	return func(options *options) {
		if mapper != nil {
			options.failed = mapper
		}
	}
}

// NewMiddleware delegates to the direct fail-closed adapter, retaining this facade
// type/options. Literal nil dependencies fail; typed-nil/custom callback panics
// are not handled here. See adapters/jsonrpc for response/context ownership.
func NewMiddleware(
	authorizer Authorizer,
	mapper RequestMapper,
	middlewareOptions ...Option,
) (jsonrpc.Middleware, error) {
	if authorizer == nil {
		return nil, ErrNilAuthorizer
	}
	if mapper == nil {
		return nil, ErrNilRequestMapper
	}
	configured := options{}
	for _, option := range middlewareOptions {
		option(&configured)
	}
	options := make([]adapter.Option, 0, 2)
	if configured.denied != nil {
		options = append(options, adapter.WithDeniedError(adapter.DeniedError(configured.denied)))
	}
	if configured.failed != nil {
		options = append(options, adapter.WithErrorMapper(adapter.ErrorMapper(configured.failed)))
	}
	return adapter.NewMiddleware(authorizer, adapter.RequestMapper(mapper), options...)
}

// DecisionFromContext returns the attached decision by value; its slices remain shared.
func DecisionFromContext(ctx context.Context) (authorization.Decision, bool) {
	return adapter.DecisionFromContext(ctx)
}
