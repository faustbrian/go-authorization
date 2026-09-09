package authorizationjsonrpc

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	authorization "github.com/faustbrian/go-authorization"
	jsonrpc "github.com/faustbrian/go-jsonrpc"
)

type authorizerFunc func(context.Context, authorization.Request) (authorization.Decision, error)

func (authorize authorizerFunc) Decide(ctx context.Context, request authorization.Request) (authorization.Decision, error) {
	return authorize(ctx, request)
}

func TestMiddlewareAllowsAndExposesDecision(t *testing.T) {
	t.Parallel()
	middleware, err := NewMiddleware(
		authorizerFunc(func(context.Context, authorization.Request) (authorization.Decision, error) {
			return authorization.Decision{Outcome: authorization.Allow, Revision: 4}, nil
		}),
		func(context.Context, json.RawMessage) (authorization.Request, error) {
			return authorization.Request{}, nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	result, err := middleware(func(ctx context.Context, _ json.RawMessage) (any, error) {
		decision, ok := DecisionFromContext(ctx)
		if !ok || decision.Revision != 4 {
			t.Errorf("decision = %+v, %v", decision, ok)
		}
		return "ok", nil
	})(context.Background(), nil)
	if err != nil || result != "ok" {
		t.Fatalf("result = %v, %v", result, err)
	}
}

func TestMiddlewareFailuresOptionsAndValidation(t *testing.T) {
	t.Parallel()
	mapper := func(context.Context, json.RawMessage) (authorization.Request, error) {
		return authorization.Request{}, nil
	}
	deny := authorizerFunc(func(context.Context, authorization.Request) (authorization.Decision, error) {
		return authorization.Decision{Outcome: authorization.Deny}, nil
	})
	if _, err := NewMiddleware(nil, mapper); !errors.Is(err, ErrNilAuthorizer) {
		t.Errorf("nil authorizer = %v", err)
	}
	if _, err := NewMiddleware(deny, nil); !errors.Is(err, ErrNilRequestMapper) {
		t.Errorf("nil mapper = %v", err)
	}
	want := errors.New("failed")
	cases := []struct {
		name       string
		authorizer Authorizer
		mapper     RequestMapper
		wantCode   int
	}{
		{name: "deny", authorizer: deny, mapper: mapper, wantCode: CodeForbidden},
		{name: "not applicable", authorizer: authorizerFunc(func(context.Context, authorization.Request) (authorization.Decision, error) {
			return authorization.Decision{Outcome: authorization.NotApplicable}, nil
		}), mapper: mapper, wantCode: CodeForbidden},
		{name: "mapper", authorizer: deny, mapper: func(context.Context, json.RawMessage) (authorization.Request, error) {
			return authorization.Request{}, want
		}, wantCode: jsonrpc.CodeInternalError},
		{name: "decision", authorizer: authorizerFunc(func(context.Context, authorization.Request) (authorization.Decision, error) {
			return authorization.Decision{}, want
		}), mapper: mapper, wantCode: jsonrpc.CodeInternalError},
		{name: "outcome", authorizer: authorizerFunc(func(context.Context, authorization.Request) (authorization.Decision, error) {
			return authorization.Decision{Outcome: 99}, nil
		}), mapper: mapper, wantCode: jsonrpc.CodeInternalError},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			middleware, err := NewMiddleware(test.authorizer, test.mapper)
			if err != nil {
				t.Fatal(err)
			}
			_, err = middleware(func(context.Context, json.RawMessage) (any, error) {
				t.Error("next called")
				return nil, nil
			})(context.Background(), nil)
			var rpcError *jsonrpc.Error
			if !errors.As(err, &rpcError) || rpcError.Code != test.wantCode {
				t.Errorf("error = %v, want code %d", err, test.wantCode)
			}
		})
	}
	for _, option := range []Option{WithDeniedError(nil), WithErrorMapper(nil)} {
		middleware, err := NewMiddleware(deny, mapper, option)
		if err != nil || middleware == nil {
			t.Fatalf("nil option = %v, %v", middleware, err)
		}
	}
	customDenied, err := NewMiddleware(deny, mapper, WithDeniedError(func(authorization.Decision) *jsonrpc.Error {
		return jsonrpc.NewError(-32042, "No")
	}))
	if err != nil {
		t.Fatal(err)
	}
	_, err = customDenied(func(context.Context, json.RawMessage) (any, error) { return nil, nil })(context.Background(), nil)
	assertRPCCode(t, err, -32042)
	nilDenied, err := NewMiddleware(deny, mapper, WithDeniedError(func(authorization.Decision) *jsonrpc.Error { return nil }))
	if err != nil {
		t.Fatal(err)
	}
	_, err = nilDenied(func(context.Context, json.RawMessage) (any, error) { return nil, nil })(context.Background(), nil)
	assertRPCCode(t, err, jsonrpc.CodeInternalError)
	for _, mapper := range []ErrorMapper{
		func(error) *jsonrpc.Error { return jsonrpc.NewError(-32043, "Failed") },
		func(error) *jsonrpc.Error { return nil },
	} {
		customFailure, err := NewMiddleware(authorizerFunc(func(context.Context, authorization.Request) (authorization.Decision, error) {
			return authorization.Decision{}, want
		}), mapperFunc(), WithErrorMapper(mapper))
		if err != nil {
			t.Fatal(err)
		}
		_, err = customFailure(func(context.Context, json.RawMessage) (any, error) { return nil, nil })(context.Background(), nil)
		var rpcError *jsonrpc.Error
		if !errors.As(err, &rpcError) || (rpcError.Code != -32043 && rpcError.Code != jsonrpc.CodeInternalError) {
			t.Fatalf("custom failure = %v", err)
		}
	}
	if _, ok := DecisionFromContext(context.Background()); ok {
		t.Error("empty context contains decision")
	}
}

func mapperFunc() RequestMapper {
	return func(context.Context, json.RawMessage) (authorization.Request, error) {
		return authorization.Request{}, nil
	}
}

func assertRPCCode(t *testing.T, err error, want int) {
	t.Helper()
	var rpcError *jsonrpc.Error
	if !errors.As(err, &rpcError) || rpcError.Code != want {
		t.Fatalf("error = %v, want code %d", err, want)
	}
}
