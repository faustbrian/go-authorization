// Package authorizationhttp provides fail-closed net/http authorization
// integration.
package authorizationhttp

import (
	"context"
	"errors"
	"net/http"

	authorization "github.com/faustbrian/go-authorization"
)

var (
	// ErrNilAuthorizer reports that NewHandler received no authorizer.
	ErrNilAuthorizer = errors.New("HTTP authorization authorizer is nil")
	// ErrNilRequestMapper reports that NewHandler received no request mapper.
	ErrNilRequestMapper = errors.New("HTTP authorization request mapper is nil")
	// ErrNilNextHandler reports that NewHandler received no downstream handler.
	ErrNilNextHandler = errors.New("HTTP authorization next handler is nil")
)

// Authorizer decides whether a mapped HTTP request may reach its downstream handler.
type Authorizer interface {
	Decide(context.Context, authorization.Request) (authorization.Decision, error)
}

// RequestMapper maps an HTTP request to the transport-neutral authorization request.
type RequestMapper func(*http.Request) (authorization.Request, error)

// Option configures HTTP authorization failure handling.
type Option func(*options)

type options struct {
	denied http.Handler
	failed http.Handler
}

// WithDeniedHandler replaces the handler used for valid non-allow decisions.
// A nil handler leaves the default HTTP 403 response unchanged.
func WithDeniedHandler(handler http.Handler) Option {
	return func(options *options) {
		if handler != nil {
			options.denied = handler
		}
	}
}

// WithErrorHandler replaces the handler used for mapping, evaluation, and invalid-outcome failures.
// A nil handler leaves the default HTTP 500 response unchanged.
func WithErrorHandler(handler http.Handler) Option {
	return func(options *options) {
		if handler != nil {
			options.failed = handler
		}
	}
}

// NewHandler constructs fail-closed authorization middleware around next.
// Only Allow reaches next; denial and failure handlers receive the decision or error in context.
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
	configured := options{
		denied: http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			writer.WriteHeader(http.StatusForbidden)
		}),
		failed: http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			writer.WriteHeader(http.StatusInternalServerError)
		}),
	}
	for _, option := range handlerOptions {
		option(&configured)
	}

	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		authorizationRequest, err := mapper(request)
		if err != nil {
			configured.failed.ServeHTTP(writer, request.WithContext(withError(request.Context(), err)))
			return
		}
		decision, err := authorizer.Decide(request.Context(), authorizationRequest)
		if err != nil {
			configured.failed.ServeHTTP(writer, request.WithContext(withError(request.Context(), err)))
			return
		}
		if decision.Outcome > authorization.Deny {
			configured.failed.ServeHTTP(writer, request.WithContext(withError(request.Context(), authorization.ErrInvalidOutcome)))
			return
		}
		request = request.WithContext(context.WithValue(request.Context(), decisionContextKey{}, decision))
		if decision.Outcome != authorization.Allow {
			configured.denied.ServeHTTP(writer, request)
			return
		}
		next.ServeHTTP(writer, request)
	}), nil
}

type decisionContextKey struct{}
type errorContextKey struct{}

// DecisionFromContext returns the decision attached for denied or allowed downstream handling.
func DecisionFromContext(ctx context.Context) (authorization.Decision, bool) {
	decision, ok := ctx.Value(decisionContextKey{}).(authorization.Decision)
	return decision, ok
}

// ErrorFromContext returns the local failure attached for a configured error handler.
func ErrorFromContext(ctx context.Context) (error, bool) {
	err, ok := ctx.Value(errorContextKey{}).(error)
	return err, ok
}

func withError(ctx context.Context, err error) context.Context {
	return context.WithValue(ctx, errorContextKey{}, err)
}
