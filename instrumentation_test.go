package authorization

import (
	"context"
	"errors"
	"testing"
	"time"
)

type instrumenterStub struct {
	startPanic  bool
	finishPanic bool
	event       Event
	started     bool
	derivedKey  any
}

func (instrumenter *instrumenterStub) Start(ctx context.Context) (context.Context, func(Event)) {
	instrumenter.started = true
	if instrumenter.startPanic {
		panic("start")
	}
	ctx = context.WithValue(ctx, instrumenter.derivedKey, true)
	return ctx, func(event Event) {
		instrumenter.event = event
		if instrumenter.finishPanic {
			panic("finish")
		}
	}
}

type authorizerFunc func(context.Context, Request) (Decision, error)

func (authorize authorizerFunc) Decide(ctx context.Context, request Request) (Decision, error) {
	return authorize(ctx, request)
}

type beginInstrumenterStub struct {
	beginPanic  bool
	finishPanic bool
	event       Event
	begun       int
	finished    int
	derivedKey  any
}

func (instrumenter *beginInstrumenterStub) Begin(ctx context.Context) (context.Context, func(Event)) {
	instrumenter.begun++
	if instrumenter.beginPanic {
		panic("begin")
	}
	ctx = context.WithValue(ctx, instrumenter.derivedKey, true)
	return ctx, func(event Event) {
		instrumenter.finished++
		instrumenter.event = event
		if instrumenter.finishPanic {
			panic("finish")
		}
	}
}

type typedNilAuthorizer struct{}

func (*typedNilAuthorizer) Decide(context.Context, Request) (Decision, error) {
	return Decision{}, nil
}

type typedNilBeginInstrumenter struct{}

func (*typedNilBeginInstrumenter) Begin(context.Context) (context.Context, func(Event)) {
	return context.Background(), nil
}

type valueAuthorizer struct{}

func (valueAuthorizer) Decide(context.Context, Request) (Decision, error) {
	return Decision{Outcome: Allow}, nil
}

type valueBeginInstrumenter struct{}

func (valueBeginInstrumenter) Begin(ctx context.Context) (context.Context, func(Event)) {
	return ctx, func(Event) {}
}

func TestNewInstrumentedWithBeginRejectsNilDependenciesBeforeClock(t *testing.T) {
	t.Parallel()

	clockCalled := false
	config := InstrumentationConfig{Clock: func() time.Time {
		clockCalled = true
		return time.Now()
	}}
	validAuthorizer := authorizerFunc(func(context.Context, Request) (Decision, error) {
		return Decision{Outcome: Allow}, nil
	})
	validInstrumenter := &beginInstrumenterStub{}
	var nilAuthorizer *typedNilAuthorizer
	var nilInstrumenter *typedNilBeginInstrumenter

	tests := []struct {
		name         string
		authorizer   Authorizer
		instrumenter BeginInstrumenter
		want         error
	}{
		{name: "literal nil authorizer", instrumenter: validInstrumenter, want: ErrNilAuthorizer},
		{name: "typed nil authorizer", authorizer: nilAuthorizer, instrumenter: validInstrumenter, want: ErrNilAuthorizer},
		{name: "literal nil instrumenter", authorizer: validAuthorizer, want: ErrNilInstrumenter},
		{name: "typed nil instrumenter", authorizer: validAuthorizer, instrumenter: nilInstrumenter, want: ErrNilInstrumenter},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewInstrumentedWithBegin(test.authorizer, test.instrumenter, config)
			if !errors.Is(err, test.want) {
				t.Fatalf("NewInstrumentedWithBegin() error = %v, want %v", err, test.want)
			}
		})
	}
	if clockCalled {
		t.Fatal("constructor evaluated clock")
	}
	if _, err := NewInstrumentedWithBegin(valueAuthorizer{}, valueBeginInstrumenter{}, config); err != nil {
		t.Fatalf("value dependencies rejected: %v", err)
	}
}

func TestInstrumentedWithBeginUsesBoundedCommonObservation(t *testing.T) {
	t.Parallel()

	key := struct{}{}
	instrumenter := &beginInstrumenterStub{derivedKey: key}
	authorizer := authorizerFunc(func(ctx context.Context, _ Request) (Decision, error) {
		if value, _ := ctx.Value(key).(bool); !value {
			t.Error("authorizer did not receive derived context")
		}
		return Decision{
			Outcome: Allow, Revision: 9,
			MatchedPolicyIDs: []PolicyID{"one", "two"},
			Trace:            []TraceEntry{{}, {}},
		}, nil
	})
	current := time.Unix(100, 0)
	instrumented, err := NewInstrumentedWithBegin(authorizer, instrumenter, InstrumentationConfig{
		Clock: func() time.Time {
			current = current.Add(time.Millisecond)
			return current
		},
		MaxPolicyIDs: 1,
	})
	if err != nil {
		t.Fatalf("NewInstrumentedWithBegin() error = %v", err)
	}
	decision, err := instrumented.Decide(context.Background(), Request{})
	if err != nil || decision.Revision != 9 {
		t.Fatalf("Decide() = %+v, %v", decision, err)
	}
	if instrumenter.begun != 1 || instrumenter.finished != 1 {
		t.Fatalf("callbacks = begin %d, finish %d", instrumenter.begun, instrumenter.finished)
	}
	if instrumenter.event.Duration != time.Millisecond ||
		len(instrumenter.event.MatchedPolicyIDs) != 1 ||
		!instrumenter.event.MatchedPolicyIDsTruncated || instrumenter.event.TraceCount != 2 {
		t.Fatalf("event = %+v", instrumenter.event)
	}
}

func TestInstrumentedWithBeginIsolatesObservationPanics(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name         string
		instrumenter *beginInstrumenterStub
	}{
		{name: "begin", instrumenter: &beginInstrumenterStub{beginPanic: true}},
		{name: "completion", instrumenter: &beginInstrumenterStub{finishPanic: true}},
	} {
		t.Run(test.name, func(t *testing.T) {
			authorizer := authorizerFunc(func(context.Context, Request) (Decision, error) {
				return Decision{Outcome: Allow, Revision: 8}, nil
			})
			instrumented, err := NewInstrumentedWithBegin(
				authorizer,
				test.instrumenter,
				InstrumentationConfig{},
			)
			if err != nil {
				t.Fatal(err)
			}
			decision, err := instrumented.Decide(context.Background(), Request{})
			if err != nil || decision.Outcome != Allow || decision.Revision != 8 {
				t.Fatalf("Decide() = %+v, %v", decision, err)
			}
		})
	}
}

func TestInstrumentedAuthorizerEmitsBoundedEvent(t *testing.T) {
	t.Parallel()

	key := &struct{}{}
	instrumenter := &instrumenterStub{derivedKey: key}
	times := []time.Time{
		time.Date(2026, 7, 15, 10, 0, 0, 0, time.UTC),
		time.Date(2026, 7, 15, 10, 0, 0, int(5*time.Millisecond), time.UTC),
	}
	index := 0
	authorizer, err := NewInstrumented(
		authorizerFunc(func(ctx context.Context, _ Request) (Decision, error) {
			if ctx.Value(key) != true {
				t.Error("authorizer did not receive derived instrumentation context")
			}
			return Decision{
				Outcome: Allow, Reason: "granted", Revision: 7,
				MatchedPolicyIDs: []PolicyID{"one", "two", "three"},
				Trace:            []TraceEntry{{PolicyID: "one"}}, TraceTruncated: true,
			}, nil
		}),
		instrumenter,
		InstrumentationConfig{
			Clock:        func() time.Time { value := times[index]; index++; return value },
			MaxPolicyIDs: 2,
		},
	)
	if err != nil {
		t.Fatalf("NewInstrumented() error = %v", err)
	}
	decision, err := authorizer.Decide(context.Background(), Request{})
	if err != nil || decision.Outcome != Allow {
		t.Fatalf("Decide() = (%+v, %v)", decision, err)
	}
	event := instrumenter.event
	if event.Outcome != Allow || event.Reason != "granted" || event.Revision != 7 ||
		event.Duration != 5*time.Millisecond || event.Failed ||
		len(event.MatchedPolicyIDs) != 2 || !event.MatchedPolicyIDsTruncated ||
		event.TraceCount != 1 || !event.TraceTruncated {
		t.Errorf("instrumentation event = %+v", event)
	}
	decision.MatchedPolicyIDs[0] = "changed"
	if event.MatchedPolicyIDs[0] != "one" {
		t.Error("event policy IDs alias decision data")
	}
}

func TestInstrumentedAuthorizerPreservesUpstreamDiagnosticTruncation(t *testing.T) {
	t.Parallel()

	instrumenter := &instrumenterStub{derivedKey: &struct{}{}}
	authorizer, err := NewInstrumented(
		authorizerFunc(func(context.Context, Request) (Decision, error) {
			return Decision{
				Outcome: Allow, MatchedPolicyIDs: []PolicyID{"one"},
				MatchedPolicyIDsTruncated: true,
			}, nil
		}),
		instrumenter,
		InstrumentationConfig{},
	)
	if err != nil {
		t.Fatalf("NewInstrumented() error = %v", err)
	}
	if _, err := authorizer.Decide(context.Background(), Request{}); err != nil {
		t.Fatalf("Decide() error = %v", err)
	}
	if !instrumenter.event.MatchedPolicyIDsTruncated {
		t.Error("Event.MatchedPolicyIDsTruncated = false, want true")
	}
}

func TestInstrumentedAuthorizerPreservesExactInstrumentationBoundaries(t *testing.T) {
	t.Parallel()

	instrumenter := &instrumenterStub{derivedKey: &struct{}{}}
	now := time.Date(2026, 7, 15, 10, 0, 0, 0, time.UTC)
	authorizer, err := NewInstrumented(
		authorizerFunc(func(context.Context, Request) (Decision, error) {
			return Decision{
				Outcome:          Allow,
				MatchedPolicyIDs: []PolicyID{"one", "two"},
			}, nil
		}),
		instrumenter,
		InstrumentationConfig{
			Clock:        func() time.Time { return now },
			MaxPolicyIDs: 2,
		},
	)
	if err != nil {
		t.Fatalf("NewInstrumented() error = %v", err)
	}
	if _, err := authorizer.Decide(context.Background(), Request{}); err != nil {
		t.Fatalf("Decide() error = %v", err)
	}
	if instrumenter.event.Duration != 0 {
		t.Errorf("zero elapsed duration = %v, want zero", instrumenter.event.Duration)
	}
	if len(instrumenter.event.MatchedPolicyIDs) != 2 ||
		instrumenter.event.MatchedPolicyIDsTruncated {
		t.Errorf("exact-limit event = %+v, want both policy IDs without truncation", instrumenter.event)
	}
}

func TestInstrumentedAuthorizerPreservesFailuresAndIsolatesInstrumentation(t *testing.T) {
	t.Parallel()

	want := errors.New("evaluation failed")
	for _, instrumenter := range []*instrumenterStub{
		{startPanic: true, derivedKey: &struct{}{}},
		{finishPanic: true, derivedKey: &struct{}{}},
	} {
		authorizer, err := NewInstrumented(
			authorizerFunc(func(context.Context, Request) (Decision, error) {
				return Decision{Outcome: Deny, Reason: ReasonEvaluationError}, want
			}),
			instrumenter,
			InstrumentationConfig{Clock: func() time.Time { return time.Time{} }},
		)
		if err != nil {
			t.Fatalf("NewInstrumented() error = %v", err)
		}
		decision, err := authorizer.Decide(context.Background(), Request{})
		if !errors.Is(err, want) || decision.Outcome != Deny {
			t.Errorf("Decide() = (%+v, %v), want original failure", decision, err)
		}
		if !instrumenter.startPanic && !instrumenter.event.Failed {
			t.Errorf("failure event = %+v", instrumenter.event)
		}
	}
}

func TestInstrumentedAuthorizerValidatesConfigAndClampsClock(t *testing.T) {
	t.Parallel()

	instrumenter := &instrumenterStub{derivedKey: &struct{}{}}
	authorizer := authorizerFunc(func(context.Context, Request) (Decision, error) {
		return Decision{Outcome: NotApplicable}, nil
	})
	if _, err := NewInstrumented(nil, instrumenter, InstrumentationConfig{}); !errors.Is(err, ErrNilAuthorizer) {
		t.Errorf("NewInstrumented(nil authorizer) error = %v", err)
	}
	if _, err := NewInstrumented(authorizer, nil, InstrumentationConfig{}); !errors.Is(err, ErrNilInstrumenter) {
		t.Errorf("NewInstrumented(nil instrumenter) error = %v", err)
	}
	if _, err := NewInstrumented(authorizer, instrumenter, InstrumentationConfig{MaxPolicyIDs: -1}); !errors.Is(err, ErrInvalidInstrumentationConfig) {
		t.Errorf("NewInstrumented(invalid config) error = %v", err)
	}
	if wrapped, err := NewInstrumented(authorizer, instrumenter, InstrumentationConfig{}); err != nil || wrapped == nil {
		t.Errorf("NewInstrumented(defaults) = (%v, %v)", wrapped, err)
	}

	times := []time.Time{time.Unix(2, 0), time.Unix(1, 0)}
	index := 0
	wrapped, err := NewInstrumented(authorizer, instrumenter, InstrumentationConfig{
		Clock: func() time.Time { value := times[index]; index++; return value },
	})
	if err != nil {
		t.Fatalf("NewInstrumented() error = %v", err)
	}
	if _, err := wrapped.Decide(context.Background(), Request{}); err != nil {
		t.Fatalf("Decide() error = %v", err)
	}
	if instrumenter.event.Duration != 0 {
		t.Errorf("negative duration = %v, want zero", instrumenter.event.Duration)
	}
}
