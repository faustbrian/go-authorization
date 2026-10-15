package authorization

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type identityAuthorizerFunc func(context.Context, Request) (Decision, error)

func (f identityAuthorizerFunc) Decide(ctx context.Context, request Request) (Decision, error) {
	return f(ctx, request)
}

func identityRequest() Request {
	return Request{Subject: Subject{Kind: SubjectUser, ID: "actor"}, Action: "read", Resource: Resource{Type: "document"}}
}

func TestIdentityContractFailClosedService(t *testing.T) {
	request := DecisionContext{Request: identityRequest(), PolicyRevision: 3}
	for _, test := range []struct {
		outcome  Outcome
		revision Revision
		err      error
		allowed  bool
		wantErr  error
	}{
		{Allow, 3, nil, true, nil}, {Deny, 3, nil, false, nil},
		{Allow, 2, nil, false, ErrRevisionConflict},
		{NotApplicable, 3, nil, false, ErrInvalidOutcome},
		{Outcome(99), 3, nil, false, ErrInvalidOutcome},
		{Allow, 3, errors.New("dependency secret"), false, ErrDecisionUnavailable},
	} {
		service, err := NewDecisionService(identityAuthorizerFunc(func(context.Context, Request) (Decision, error) {
			return Decision{Outcome: test.outcome, Revision: test.revision}, test.err
		}))
		if err != nil {
			t.Fatal(err)
		}
		decision, err := service.Decide(context.Background(), request)
		if !errors.Is(err, test.wantErr) || err != nil && strings.Contains(err.Error(), "dependency secret") {
			t.Fatal("decision error classification or redaction changed")
		}
		if (decision.Outcome == Allow) != test.allowed {
			t.Fatalf("failed closed: %#v %v", decision, err)
		}
		if !test.allowed && decision.Outcome != Deny {
			t.Fatalf("not deny: %#v", decision)
		}
	}
}

func TestIdentityContractDecisionBoundary(t *testing.T) {
	if _, err := NewDecisionService(nil); err != ErrNilAuthorizer {
		t.Fatal(err)
	}
	var nilAuthorizer identityAuthorizerFunc
	if _, err := NewDecisionService(nilAuthorizer); err != ErrNilAuthorizer {
		t.Fatal("typed nil")
	}
	request := DecisionContext{Request: identityRequest(), PolicyRevision: 3}
	maximum := request
	maximum.CorrelationID = strings.Repeat("a", 128)
	if err := maximum.Validate(); err != nil {
		t.Fatal("maximum correlation rejected", err)
	}
	for _, change := range []func(*DecisionContext){func(r *DecisionContext) { r.Request.Subject.ID = "" }, func(r *DecisionContext) { r.PolicyRevision = 0 }, func(r *DecisionContext) { r.CorrelationID = strings.Repeat("a", 129) }, func(r *DecisionContext) { r.CorrelationID = "\xff" }} {
		copy := request
		change(&copy)
		if copy.Validate() == nil {
			t.Fatal("invalid decision context")
		}
	}
	request.Request.Attributes = Attributes{"x": StringValue("original")}
	request.Request.Subject.Groups = []SubjectID{"group"}
	copy := request.Clone()
	copy.Request.Attributes["x"] = StringValue("changed")
	copy.Request.Subject.Groups[0] = "changed"
	if request.Request.Subject.Groups[0] != "group" || !request.Request.Attributes["x"].Equal(StringValue("original")) {
		t.Fatal("context aliases")
	}
	service, _ := NewDecisionService(identityAuthorizerFunc(func(context.Context, Request) (Decision, error) { panic("secret") }))
	decision, err := service.Decide(context.Background(), request)
	if err != ErrPolicyPanic || decision.Outcome != Deny {
		t.Fatal("panic grants")
	}
	for _, ctx := range []context.Context{nil, func() context.Context { ctx, cancel := context.WithCancel(context.Background()); cancel(); return ctx }(), func() context.Context {
		ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
		cancel()
		return ctx
	}()} {
		decision, err := service.Decide(ctx, request)
		if err == nil || decision.Outcome != Deny {
			t.Fatal("context grants")
		}
	}
	invalid := request
	invalid.PolicyRevision = 0
	if decision, err := service.Decide(context.Background(), invalid); err == nil || decision.Outcome != Deny {
		t.Fatal("invalid request grants")
	}
	ctx, cancel := context.WithCancel(context.Background())
	service, _ = NewDecisionService(identityAuthorizerFunc(func(context.Context, Request) (Decision, error) {
		cancel()
		return Decision{Outcome: Allow, Revision: 3}, nil
	}))
	if decision, err := service.Decide(ctx, request); err != context.Canceled || decision.Outcome != Deny {
		t.Fatal("post-decision cancellation grants")
	}
	retained := Decision{Outcome: Allow, Revision: 3, MatchedPolicyIDs: []PolicyID{"policy"}, Trace: []TraceEntry{{PolicyID: "policy", Outcome: Allow}}}
	service, _ = NewDecisionService(identityAuthorizerFunc(func(_ context.Context, input Request) (Decision, error) {
		input.Subject.Groups[0] = "mutated"
		return retained, nil
	}))
	decision, err = service.Decide(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	decision.MatchedPolicyIDs[0] = "mutated"
	decision.Trace[0].PolicyID = "mutated"
	if retained.MatchedPolicyIDs[0] != "policy" || retained.Trace[0].PolicyID != "policy" || request.Request.Subject.Groups[0] != "group" {
		t.Fatal("boundary aliases")
	}
}
