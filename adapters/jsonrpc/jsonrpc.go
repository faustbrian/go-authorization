// Package authorizationjsonrpc provides fail-closed JSON-RPC authorization
// middleware.
package authorizationjsonrpc

import (
	"context"
	"encoding/json"
	"errors"

	authorization "github.com/faustbrian/go-authorization"
	jsonrpc "github.com/faustbrian/go-jsonrpc"
)

// CodeForbidden is the bounded JSON-RPC server error code for authorization denial.
const CodeForbidden = -32001

var (
	// ErrNilAuthorizer reports that NewMiddleware received no authorizer.
	ErrNilAuthorizer = errors.New("JSON-RPC authorization authorizer is nil")
	// ErrNilRequestMapper reports that NewMiddleware received no request mapper.
	ErrNilRequestMapper = errors.New("JSON-RPC authorization request mapper is nil")
)

// Authorizer decides whether a mapped JSON-RPC request may reach its method handler.
type Authorizer interface {
	Decide(context.Context, authorization.Request) (authorization.Decision, error)
}

// RequestMapper maps JSON-RPC context and raw parameters to an authorization request.
type RequestMapper func(context.Context, json.RawMessage) (authorization.Request, error)

// DeniedError maps a valid non-allow decision to a JSON-RPC error.
type DeniedError func(authorization.Decision) *jsonrpc.Error

// ErrorMapper maps request-mapping and evaluation failures to JSON-RPC errors.
type ErrorMapper func(error) *jsonrpc.Error

// Option configures JSON-RPC authorization failure mapping.
type Option func(*options)

type options struct {
	denied DeniedError
	failed ErrorMapper
}

// WithDeniedError replaces the mapper for valid non-allow decisions.
// A nil mapper leaves the default forbidden response unchanged.
func WithDeniedError(mapper DeniedError) Option {
	return func(options *options) {
		if mapper != nil {
			options.denied = mapper
		}
	}
}

// WithErrorMapper replaces the mapper for mapping, evaluation, and invalid-outcome failures.
// A nil mapper leaves the default internal-error response unchanged.
func WithErrorMapper(mapper ErrorMapper) Option {
	return func(options *options) {
		if mapper != nil {
			options.failed = mapper
		}
	}
}

// NewMiddleware constructs fail-closed JSON-RPC authorization middleware.
// Only Allow reaches the next handler; nil custom-mapper results are contained as internal errors.
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
	configured := options{
		denied: func(authorization.Decision) *jsonrpc.Error {
			return jsonrpc.NewError(CodeForbidden, "Forbidden")
		},
		failed: func(err error) *jsonrpc.Error {
			return jsonrpc.InternalError().WithCause(err)
		},
	}
	for _, option := range middlewareOptions {
		option(&configured)
	}

	return func(next jsonrpc.Handler) jsonrpc.Handler {
		return func(ctx context.Context, params json.RawMessage) (any, error) {
			request, err := mapper(ctx, params)
			if err != nil {
				return nil, mapFailure(configured.failed, err)
			}
			decision, err := authorizer.Decide(ctx, request)
			if err != nil {
				return nil, mapFailure(configured.failed, err)
			}
			if decision.Outcome > authorization.Deny {
				return nil, mapFailure(configured.failed, authorization.ErrInvalidOutcome)
			}
			ctx = context.WithValue(ctx, decisionContextKey{}, decision)
			if decision.Outcome != authorization.Allow {
				denied := configured.denied(decision)
				if denied == nil {
					return nil, jsonrpc.InternalError().WithCause(authorization.ErrInvalidOutcome)
				}
				return nil, denied
			}
			return next(ctx, params)
		}
	}, nil
}

type decisionContextKey struct{}

// DecisionFromContext returns the decision attached for denied or allowed method handling.
func DecisionFromContext(ctx context.Context) (authorization.Decision, bool) {
	decision, ok := ctx.Value(decisionContextKey{}).(authorization.Decision)
	return decision, ok
}

func mapFailure(mapper ErrorMapper, err error) *jsonrpc.Error {
	mapped := mapper(err)
	if mapped == nil {
		return jsonrpc.InternalError().WithCause(err)
	}
	return mapped
}
