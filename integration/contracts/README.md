# Authorization integration contracts

This non-releasable module tests composition between Authorization and its
HTTP, authentication, and sibling policy dependencies. It has no independent
release tag or application entry point.

The public module minimum is Go 1.27.0. Development and CI use Go 1.27.2 so
qualification includes the patched standard library.

## Published-module composition

From this directory, run:

```sh
GOWORK=off go test -mod=readonly ./...
```

This resolves the Authorization version declared in this module's `go.mod`.
It does not substitute the current root source.

## Local-source composition

From the repository root, run:

```sh
go test -mod=readonly ./integration/contracts/...
```

The repository workspace composes the local Authorization source with this
harness. These HTTP and policy tests do not establish JSON-RPC wire behavior;
the root dispatcher tests cover that boundary separately. See the
[root documentation](../../README.md) for the supported APIs.
