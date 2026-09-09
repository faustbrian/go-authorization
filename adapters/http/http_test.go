package authorizationhttp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	authorization "github.com/faustbrian/go-authorization"
)

type authorizerFunc func(context.Context, authorization.Request) (authorization.Decision, error)

func (authorize authorizerFunc) Decide(ctx context.Context, request authorization.Request) (authorization.Decision, error) {
	return authorize(ctx, request)
}

func TestHandlerAllowsAndExposesDecision(t *testing.T) {
	t.Parallel()
	want := authorization.Decision{Outcome: authorization.Allow, Revision: 7}
	handler, err := NewHandler(
		authorizerFunc(func(context.Context, authorization.Request) (authorization.Decision, error) { return want, nil }),
		func(*http.Request) (authorization.Request, error) { return authorization.Request{Action: "read"}, nil },
		http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			decision, ok := DecisionFromContext(request.Context())
			if !ok || decision.Revision != want.Revision {
				t.Errorf("DecisionFromContext() = (%+v, %v)", decision, ok)
			}
			writer.WriteHeader(http.StatusNoContent)
		}),
	)
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("status = %d", recorder.Code)
	}
}

func TestHandlerDenialsFailuresOptionsAndValidation(t *testing.T) {
	t.Parallel()
	mapper := func(*http.Request) (authorization.Request, error) { return authorization.Request{}, nil }
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("next called") })
	valid := authorizerFunc(func(context.Context, authorization.Request) (authorization.Decision, error) {
		return authorization.Decision{Outcome: authorization.Deny}, nil
	})
	for _, test := range []struct {
		name       string
		authorizer Authorizer
		mapper     RequestMapper
		next       http.Handler
		want       error
	}{
		{name: "authorizer", mapper: mapper, next: next, want: ErrNilAuthorizer},
		{name: "mapper", authorizer: valid, next: next, want: ErrNilRequestMapper},
		{name: "next", authorizer: valid, mapper: mapper, want: ErrNilNextHandler},
	} {
		if _, err := NewHandler(test.authorizer, test.mapper, test.next); !errors.Is(err, test.want) {
			t.Errorf("%s error = %v", test.name, err)
		}
	}
	want := errors.New("failed")
	cases := []struct {
		name       string
		authorizer Authorizer
		mapper     RequestMapper
		wantStatus int
	}{
		{name: "deny", authorizer: valid, mapper: mapper, wantStatus: http.StatusForbidden},
		{name: "not applicable", authorizer: authorizerFunc(func(context.Context, authorization.Request) (authorization.Decision, error) {
			return authorization.Decision{Outcome: authorization.NotApplicable}, nil
		}), mapper: mapper, wantStatus: http.StatusForbidden},
		{name: "mapping failure", authorizer: valid, mapper: func(*http.Request) (authorization.Request, error) {
			return authorization.Request{}, want
		}, wantStatus: http.StatusInternalServerError},
		{name: "decision failure", authorizer: authorizerFunc(func(context.Context, authorization.Request) (authorization.Decision, error) {
			return authorization.Decision{}, want
		}), mapper: mapper, wantStatus: http.StatusInternalServerError},
		{name: "invalid outcome", authorizer: authorizerFunc(func(context.Context, authorization.Request) (authorization.Decision, error) {
			return authorization.Decision{Outcome: 99}, nil
		}), mapper: mapper, wantStatus: http.StatusInternalServerError},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			handler, err := NewHandler(test.authorizer, test.mapper, next)
			if err != nil {
				t.Fatal(err)
			}
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
			if recorder.Code != test.wantStatus {
				t.Errorf("status = %d, want %d", recorder.Code, test.wantStatus)
			}
		})
	}
	denied := http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) { writer.WriteHeader(http.StatusUnauthorized) })
	failed := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if _, ok := ErrorFromContext(request.Context()); !ok {
			t.Error("missing failure")
		}
		writer.WriteHeader(http.StatusServiceUnavailable)
	})
	for _, option := range []Option{WithDeniedHandler(nil), WithErrorHandler(nil)} {
		handler, err := NewHandler(valid, mapper, next, option)
		if err != nil || handler == nil {
			t.Fatalf("nil option = %v, %v", handler, err)
		}
	}
	handler, err := NewHandler(valid, mapper, next, WithDeniedHandler(denied), WithErrorHandler(failed))
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("custom denial status = %d", recorder.Code)
	}
	handler, err = NewHandler(authorizerFunc(func(context.Context, authorization.Request) (authorization.Decision, error) {
		return authorization.Decision{}, want
	}), mapper, next, WithErrorHandler(failed))
	if err != nil {
		t.Fatal(err)
	}
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("custom failure status = %d", recorder.Code)
	}
	if _, ok := DecisionFromContext(context.Background()); ok {
		t.Error("empty context contains decision")
	}
	if _, ok := ErrorFromContext(context.Background()); ok {
		t.Error("empty context contains error")
	}
}
