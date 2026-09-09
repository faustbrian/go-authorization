# JSON-RPC integration

The `adapters/jsonrpc` package provides native middleware for
`github.com/faustbrian/go-jsonrpc`. Applications map each method's context and
raw parameters to a typed authorization request. The released `authrpc` path
remains a deprecated compatibility facade.

```go
middleware, err := authorizationjsonrpc.NewMiddleware(
    engine,
    func(ctx context.Context, params json.RawMessage) (authorization.Request, error) {
        principal, ok := principalFromContext(ctx)
        if !ok {
            return authorization.Request{}, errUnauthenticated
        }
        return authorization.Request{
            Subject:  principal,
            Action:   "invoice.read",
            Resource: authorization.Resource{Type: "invoice"},
        }, nil
    },
)
```

Only an explicit allow invokes the method handler. Deny and not-applicable
return the bounded server error code `authorizationjsonrpc.CodeForbidden`; mapper,
evaluation, and invalid-outcome failures return JSON-RPC internal errors. Local
causes are retained by `jsonrpc` but are not serialized.

Applications can customize the denial and internal error mapping with
`WithDeniedError` and `WithErrorMapper`. Returning nil from either custom
mapper is contained as an internal error. Allowed handlers can inspect the
decision with `authorizationjsonrpc.DecisionFromContext`.
