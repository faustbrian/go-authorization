# HTTP integration

The `adapters/http` package authorizes standard-library HTTP handlers without
coupling policy evaluation to routing, authentication, or transport details.
Applications provide an explicit mapper from `*http.Request` to the typed
authorization request. The released `authhttp` and `httpauth` paths remain
deprecated compatibility facades.

```go
handler, err := authorizationhttp.NewHandler(
    engine,
    func(request *http.Request) (authorization.Request, error) {
        principal, ok := authenticatedPrincipal(request.Context())
        if !ok {
            return authorization.Request{}, errUnauthenticated
        }
        return authorization.Request{
            Subject: principal,
            Action:  authorization.Action("read"),
            Resource: authorization.Resource{
                Type: authorization.ResourceType("document"),
                ID:   authorization.ResourceID(request.PathValue("document")),
            },
        }, nil
    },
    documentHandler,
)
```

Only an explicit `Allow` calls the downstream handler. `Deny` and
`NotApplicable` use the denial handler, which returns HTTP 403 by default.
Mapper errors, evaluator errors, and invalid outcomes use the internal-error
handler, which returns HTTP 500 by default. Custom handlers can be installed
with `WithDeniedHandler` and `WithErrorHandler`.

Allowed downstream handlers can read the complete decision with
`authorizationhttp.DecisionFromContext`. Custom error handlers can read the
original error with `authorizationhttp.ErrorFromContext` for logging, but
neither default handler writes policy details or internal errors to the
response body.
