package authorization

import (
	"context"
	"errors"
	"slices"
	"unicode/utf8"
)

// ErrDecisionUnavailable is a redacted dependency failure at Service.Decide.
var ErrDecisionUnavailable = errors.New("authorization decision unavailable")

// DecisionContext binds a complete request to one positive immutable policy
// revision. Optional CorrelationID is limited to 128 valid UTF-8 bytes.
// Consumers own their stricter entry/encoded-size admission limits.
type DecisionContext struct {
	// Request is the complete policy input; callers keep it stable while copied.
	Request Request
	// CorrelationID is optional diagnostic correlation, never policy authority.
	CorrelationID string
	// PolicyRevision is the exact positive revision that may authorize this call.
	PolicyRevision Revision
}

// Validate rejects incomplete requests, zero revisions and invalid correlation IDs.
func (decisionContext DecisionContext) Validate() error {
	if err := decisionContext.Request.Validate(); err != nil {
		return err
	}
	if decisionContext.PolicyRevision == 0 {
		return ErrInvalidRevision
	}
	if len(decisionContext.CorrelationID) > 128 || !utf8.ValidString(decisionContext.CorrelationID) {
		return &ValidationError{Field: "decision.correlation"}
	}
	return nil
}

// Clone copies all request-owned maps and slices; immutable Value data is shared.
func (decisionContext DecisionContext) Clone() DecisionContext {
	decisionContext.Request = cloneRequest(decisionContext.Request)
	return decisionContext
}

// Service is the revision-fenced decision boundary. Implementations must fail
// closed on errors, stale revisions, NotApplicable and invalid outcomes. Calls
// accept bounded caller contexts; implementations document concurrent safety.
type Service interface {
	// Decide returns only revision-matched Allow or Deny; errors never authorize.
	Decide(context.Context, DecisionContext) (Decision, error)
}

type decisionService struct{ authorizer Authorizer }

// NewDecisionService adapts an existing Authorizer without changing its API.
// It rejects nil/typed-nil dependencies, copies inputs/outputs and grants only
// explicit Allow at the requested revision without error. It owns no goroutines,
// stores or locks; the supplied Authorizer must support concurrent calls.
func NewDecisionService(authorizer Authorizer) (Service, error) {
	if isNilInterface(authorizer) {
		return nil, ErrNilAuthorizer
	}
	return &decisionService{authorizer: authorizer}, nil
}

func (service *decisionService) Decide(ctx context.Context, request DecisionContext) (decision Decision, err error) {
	denied := Decision{Outcome: Deny, Reason: ReasonEvaluationError, Revision: request.PolicyRevision}
	defer func() {
		if recover() != nil {
			decision = denied
			err = ErrPolicyPanic
		}
	}()
	if err := request.Validate(); err != nil {
		return denied, err
	}
	if ctx == nil {
		return denied, ErrInvalidRequest
	}
	if err := ctx.Err(); err != nil {
		return denied, err
	}
	result, err := service.authorizer.Decide(ctx, cloneRequest(request.Request))
	if contextError := ctx.Err(); contextError != nil {
		return denied, contextError
	}
	if err != nil {
		return denied, ErrDecisionUnavailable
	}
	if result.Revision != request.PolicyRevision {
		denied.Reason = ReasonPolicyStale
		return denied, ErrRevisionConflict
	}
	if result.Outcome != Allow && result.Outcome != Deny {
		return denied, ErrInvalidOutcome
	}
	return cloneDecision(result), nil
}

func cloneDecision(decision Decision) Decision {
	decision.MatchedPolicyIDs = slices.Clone(decision.MatchedPolicyIDs)
	decision.Trace = slices.Clone(decision.Trace)
	return decision
}
func cloneRequest(request Request) Request {
	request.Subject = cloneSubject(request.Subject)
	request.Resource.Attributes = cloneAttributes(request.Resource.Attributes)
	request.Environment.Attributes = cloneAttributes(request.Environment.Attributes)
	request.Attributes = cloneAttributes(request.Attributes)
	return request
}

func cloneSubject(subject Subject) Subject {
	subject.Groups = slices.Clone(subject.Groups)
	subject.Attributes = cloneAttributes(subject.Attributes)
	return subject
}
func cloneAttributes(attributes Attributes) Attributes {
	if attributes == nil {
		return nil
	}
	result := make(Attributes, len(attributes))
	for key, value := range attributes {
		result[key] = value
	}
	return result
}
