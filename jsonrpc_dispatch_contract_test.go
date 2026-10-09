//nolint:staticcheck // The deprecated facade remains part of the public contract.
package authorization_test

//lint:file-ignore SA1019 This test exercises the supported legacy RPC facade.

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	authorization "github.com/faustbrian/go-authorization/v3"
	canonical "github.com/faustbrian/go-authorization/v3/adapters/jsonrpc"
	legacy "github.com/faustbrian/go-authorization/v3/authrpc"
	jsonrpc "github.com/faustbrian/go-jsonrpc"
)

type rpcContractAuthorizer func(context.Context, authorization.Request) (authorization.Decision, error)

func (a rpcContractAuthorizer) Decide(ctx context.Context, request authorization.Request) (authorization.Decision, error) {
	return a(ctx, request)
}

func contractMiddleware(t *testing.T, path string, a rpcContractAuthorizer, mapper func(context.Context, json.RawMessage) (authorization.Request, error), denied func(authorization.Decision) *jsonrpc.Error) jsonrpc.Middleware {
	t.Helper()
	var middleware jsonrpc.Middleware
	var err error
	if path == "legacy" {
		middleware, err = legacy.NewMiddleware(a, legacy.RequestMapper(mapper), legacy.WithDeniedError(legacy.DeniedError(denied)))
	} else {
		middleware, err = canonical.NewMiddleware(a, canonical.RequestMapper(mapper), canonical.WithDeniedError(canonical.DeniedError(denied)))
	}
	if err != nil {
		t.Fatal(err)
	}
	return middleware
}

func TestRPCDispatcherBoundsAuthorizationResponses(t *testing.T) {
	const limit = 4 << 20
	for _, path := range []string{"canonical", "legacy"} {
		t.Run(path, func(t *testing.T) {
			for _, mode := range []string{"allowed-result", "custom-denial", "aggregate-after-effects"} {
				t.Run(mode, func(t *testing.T) {
					outcome := authorization.Allow
					if mode == "custom-denial" {
						outcome = authorization.Deny
					}
					a := rpcContractAuthorizer(func(context.Context, authorization.Request) (authorization.Decision, error) {
						return authorization.Decision{Outcome: outcome}, nil
					})
					mapper := func(context.Context, json.RawMessage) (authorization.Request, error) {
						return authorization.Request{}, nil
					}
					large := strings.Repeat("x", limit)
					middleware := contractMiddleware(t, path, a, mapper, func(authorization.Decision) *jsonrpc.Error {
						return jsonrpc.NewError(-32042, "custom denial").WithData(large)
					})
					calls := 0
					registry := jsonrpc.NewRegistry()
					result := large
					if mode == "aggregate-after-effects" {
						result = strings.Repeat("x", limit/2+64)
					}
					if err := registry.Register("protected", func(context.Context, json.RawMessage) (any, error) { calls++; return result, nil }); err != nil {
						t.Fatal(err)
					}
					dispatcher := jsonrpc.NewDispatcher(registry, jsonrpc.WithMiddleware(middleware))
					request := []byte(`{"jsonrpc":"2.0","id":1,"method":"protected"}`)
					wantCalls := 1
					wantID := "1"
					if mode == "custom-denial" {
						wantCalls = 0
					}
					if mode == "aggregate-after-effects" {
						request = []byte(`[{"jsonrpc":"2.0","id":1,"method":"protected"},{"jsonrpc":"2.0","id":2,"method":"protected"}]`)
						wantCalls = 2
						wantID = "null"
					}
					wire, reply := dispatcher.Dispatch(t.Context(), request)
					if !reply || len(wire) > limit {
						t.Fatalf("reply=%v, encoded bytes=%d, want bounded reply", reply, len(wire))
					}
					if calls != wantCalls {
						t.Fatalf("protected effects=%d, want %d", calls, wantCalls)
					}
					var envelope map[string]json.RawMessage
					if mode == "aggregate-after-effects" {
						var batch []map[string]json.RawMessage
						if err := json.Unmarshal(wire, &batch); err != nil || len(batch) != 1 {
							t.Fatalf("bounded batch count=%d, error=%v", len(batch), err)
						}
						envelope = batch[0]
					} else if err := json.Unmarshal(wire, &envelope); err != nil {
						t.Fatal(err)
					}
					if string(envelope["id"]) != wantID || string(envelope["jsonrpc"]) != `"2.0"` {
						t.Fatalf("response identity=%s, version=%s", envelope["id"], envelope["jsonrpc"])
					}
					if _, ok := envelope["result"]; ok {
						t.Fatal("overflow returned a result")
					}
					var failure struct {
						Code    int             `json:"code"`
						Message string          `json:"message"`
						Data    json.RawMessage `json:"data"`
					}
					if err := json.Unmarshal(envelope["error"], &failure); err != nil {
						t.Fatal(err)
					}
					if failure.Code != -32603 || failure.Message != "Internal error" || len(failure.Data) != 0 {
						t.Fatalf("bounded error=%+v", failure)
					}
				})
			}
		})
	}
}

func TestRPCDispatcherPreservesFailClosedWireContracts(t *testing.T) {
	cause := errors.New("private authorization cause")
	tests := []struct {
		name              string
		outcome           authorization.Outcome
		mapperFailure     bool
		evaluationFailure bool
		denied            func(authorization.Decision) *jsonrpc.Error
		wantCode          int
		wantMessage       string
	}{
		{name: "allow", outcome: authorization.Allow},
		{name: "deny", outcome: authorization.Deny, wantCode: -32001, wantMessage: "Forbidden"},
		{name: "not-applicable", outcome: authorization.NotApplicable, wantCode: -32001, wantMessage: "Forbidden"},
		{name: "mapper-failure", mapperFailure: true, wantCode: -32603, wantMessage: "Internal error"},
		{name: "evaluation-failure", evaluationFailure: true, wantCode: -32603, wantMessage: "Internal error"},
		{name: "invalid-outcome", outcome: 99, wantCode: -32603, wantMessage: "Internal error"},
		{name: "nil-custom-denial", outcome: authorization.Deny, denied: func(authorization.Decision) *jsonrpc.Error { return nil }, wantCode: -32603, wantMessage: "Internal error"},
		{name: "custom-denial", outcome: authorization.Deny, denied: func(authorization.Decision) *jsonrpc.Error {
			return jsonrpc.NewError(-32042, "public denial").WithCause(cause)
		}, wantCode: -32042, wantMessage: "public denial"},
	}
	for _, path := range []string{"canonical", "legacy"} {
		t.Run(path, func(t *testing.T) {
			for _, test := range tests {
				t.Run(test.name, func(t *testing.T) {
					a := rpcContractAuthorizer(func(context.Context, authorization.Request) (authorization.Decision, error) {
						if test.evaluationFailure {
							return authorization.Decision{}, cause
						}
						return authorization.Decision{Outcome: test.outcome, Revision: 7}, nil
					})
					mapper := func(context.Context, json.RawMessage) (authorization.Request, error) {
						if test.mapperFailure {
							return authorization.Request{}, cause
						}
						return authorization.Request{}, nil
					}
					middleware := contractMiddleware(t, path, a, mapper, test.denied)
					if test.mapperFailure || test.evaluationFailure || test.name == "custom-denial" {
						_, err := middleware(func(context.Context, json.RawMessage) (any, error) {
							t.Error("failed authorization invoked handler")
							return nil, nil
						})(t.Context(), nil)
						if !errors.Is(err, cause) {
							t.Fatalf("local cause missing: %v", err)
						}
					}
					calls := 0
					registry := jsonrpc.NewRegistry()
					if err := registry.Register("protected", func(ctx context.Context, _ json.RawMessage) (any, error) {
						calls++
						decision, ok := canonical.DecisionFromContext(ctx)
						if path == "legacy" {
							decision, ok = legacy.DecisionFromContext(ctx)
						}
						if !ok || decision.Outcome != authorization.Allow || decision.Revision != 7 {
							t.Errorf("handler decision=%+v, present=%v", decision, ok)
						}
						return "allowed", nil
					}); err != nil {
						t.Fatal(err)
					}
					wire, reply := jsonrpc.NewDispatcher(registry, jsonrpc.WithMiddleware(middleware)).Dispatch(t.Context(), []byte(`{"jsonrpc":"2.0","id":"request-1","method":"protected"}`))
					if !reply || strings.Contains(string(wire), cause.Error()) {
						t.Fatalf("reply=%v or local cause serialized", reply)
					}
					var envelope map[string]json.RawMessage
					if err := json.Unmarshal(wire, &envelope); err != nil {
						t.Fatal(err)
					}
					if string(envelope["id"]) != `"request-1"` || string(envelope["jsonrpc"]) != `"2.0"` {
						t.Fatalf("wire identity=%s, version=%s", envelope["id"], envelope["jsonrpc"])
					}
					if test.wantCode == 0 {
						if calls != 1 || string(envelope["result"]) != `"allowed"` {
							t.Fatalf("effects=%d, result=%s", calls, envelope["result"])
						}
						if _, exists := envelope["error"]; exists {
							t.Fatal("allowed response has an error")
						}
						return
					}
					if calls != 0 {
						t.Fatalf("forbidden effects=%d", calls)
					}
					if _, exists := envelope["result"]; exists {
						t.Fatal("failed response has a result")
					}
					var failure struct {
						Code    int             `json:"code"`
						Message string          `json:"message"`
						Data    json.RawMessage `json:"data"`
					}
					if err := json.Unmarshal(envelope["error"], &failure); err != nil {
						t.Fatal(err)
					}
					if failure.Code != test.wantCode || failure.Message != test.wantMessage || len(failure.Data) != 0 {
						t.Fatalf("wire failure=%+v", failure)
					}
				})
			}
		})
	}
}

func TestRPCDispatcherMixedBatchKeepsAdmissionAndDecisionsIsolated(t *testing.T) {
	for _, path := range []string{"canonical", "legacy"} {
		t.Run(path, func(t *testing.T) {
			mapper := func(_ context.Context, params json.RawMessage) (authorization.Request, error) {
				var input struct {
					Action string `json:"action"`
				}
				if err := json.Unmarshal(params, &input); err != nil {
					return authorization.Request{}, err
				}
				return authorization.Request{Action: authorization.Action(input.Action)}, nil
			}
			a := rpcContractAuthorizer(func(_ context.Context, request authorization.Request) (authorization.Decision, error) {
				switch request.Action {
				case "allow":
					return authorization.Decision{Outcome: authorization.Allow, Revision: 7}, nil
				case "notify":
					return authorization.Decision{Outcome: authorization.Allow, Revision: 11}, nil
				case "deny":
					return authorization.Decision{Outcome: authorization.Deny}, nil
				default:
					return authorization.Decision{Outcome: 99}, nil
				}
			})
			middleware := contractMiddleware(t, path, a, mapper, nil)
			var effects []authorization.Revision
			registry := jsonrpc.NewRegistry()
			if err := registry.Register("protected", func(ctx context.Context, _ json.RawMessage) (any, error) {
				decision, ok := canonical.DecisionFromContext(ctx)
				if path == "legacy" {
					decision, ok = legacy.DecisionFromContext(ctx)
				}
				if !ok || decision.Outcome != authorization.Allow {
					t.Errorf("handler lacks Allow decision: %+v, %v", decision, ok)
				}
				effects = append(effects, decision.Revision)
				return decision.Revision, nil
			}); err != nil {
				t.Fatal(err)
			}
			payload := []byte(`[{"jsonrpc":"2.0","id":1,"method":"protected","params":{"action":"allow"}},{"jsonrpc":"2.0","id":2,"method":"protected","params":{"action":"deny"}},{"jsonrpc":"2.0","id":3,"method":"protected","params":{"action":"invalid"}},{"jsonrpc":"2.0","method":"protected","params":{"action":"notify"}}]`)
			wire, reply := jsonrpc.NewDispatcher(registry, jsonrpc.WithMiddleware(middleware)).Dispatch(t.Context(), payload)
			if !reply {
				t.Fatal("mixed batch has no replies")
			}
			if len(effects) != 2 || effects[0] != 7 || effects[1] != 11 {
				t.Fatalf("protected effects/decisions=%v", effects)
			}
			var responses []map[string]json.RawMessage
			if err := json.Unmarshal(wire, &responses); err != nil {
				t.Fatal(err)
			}
			if len(responses) != 3 {
				t.Fatalf("response count=%d, want three (notification has no reply)", len(responses))
			}
			seen := map[string]bool{}
			for _, response := range responses {
				id := string(response["id"])
				if seen[id] {
					t.Fatalf("duplicate response id=%s", id)
				}
				seen[id] = true
				if string(response["jsonrpc"]) != `"2.0"` {
					t.Fatal("invalid wire version")
				}
				if id == "1" {
					if string(response["result"]) != "7" {
						t.Fatalf("allowed result=%s", response["result"])
					}
					if _, ok := response["error"]; ok {
						t.Fatal("allowed reply contains error")
					}
					continue
				}
				wantCode := map[string]int{"2": -32001, "3": -32603}[id]
				if wantCode == 0 {
					t.Fatalf("unexpected or notification reply id=%s", id)
				}
				var failure struct {
					Code int `json:"code"`
				}
				if err := json.Unmarshal(response["error"], &failure); err != nil || failure.Code != wantCode {
					t.Fatalf("id=%s, code=%d, decode=%v", id, failure.Code, err)
				}
				if _, ok := response["result"]; ok {
					t.Fatal("failed reply contains result")
				}
			}
		})
	}
}
