package authorization_test

import (
	"context"
	"fmt"

	authorization "github.com/faustbrian/go-authorization/v4"
)

func ExampleNewDecisionService() {
	snapshot, _ := authorization.NewSnapshot(1, authorization.DenyOverrides)
	engine, _ := authorization.NewEngine(snapshot)
	service, _ := authorization.NewDecisionService(engine)
	decision, err := service.Decide(context.Background(), authorization.DecisionContext{Request: authorization.Request{Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: "user"}, Action: "read", Resource: authorization.Resource{Type: "document"}}, PolicyRevision: 1})
	fmt.Println(decision.Outcome, err)
	// Output: deny <nil>
}
