// Package authrpc provides the legacy fail-closed JSON-RPC authorization
// middleware.
//
// Deprecated: use github.com/faustbrian/go-authorization/adapters/jsonrpc.
// This package remains supported for the longer of 180 days after successor
// public availability and two subsequently published stable root-module minor
// releases.
package authrpc

import (
	"context"
	"encoding/json"

	authorization "github.com/faustbrian/go-authorization"
	adapter "github.com/faustbrian/go-authorization/adapters/jsonrpc"
	jsonrpc "github.com/faustbrian/go-jsonrpc"
)

const CodeForbidden = -32001

var (
	ErrNilAuthorizer    = adapter.ErrNilAuthorizer
	ErrNilRequestMapper = adapter.ErrNilRequestMapper
)

type Authorizer interface {
	Decide(context.Context, authorization.Request) (authorization.Decision, error)
}

type RequestMapper func(context.Context, json.RawMessage) (authorization.Request, error)
type DeniedError func(authorization.Decision) *jsonrpc.Error
type ErrorMapper func(error) *jsonrpc.Error
type Option func(*options)

type options struct {
	denied DeniedError
	failed ErrorMapper
}

func WithDeniedError(mapper DeniedError) Option {
	return func(options *options) {
		if mapper != nil {
			options.denied = mapper
		}
	}
}

func WithErrorMapper(mapper ErrorMapper) Option {
	return func(options *options) {
		if mapper != nil {
			options.failed = mapper
		}
	}
}

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

func DecisionFromContext(ctx context.Context) (authorization.Decision, bool) {
	return adapter.DecisionFromContext(ctx)
}
