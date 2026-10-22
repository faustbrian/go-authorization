# Package map

[Documentation index](README.md) · [Repository entry](../README.md)

This map follows the current source modules, not a synchronized release.
Use the repository README for published installation versions; an unpublished
source major is not installable merely because its package appears here.
Internal packages and non-releasable fixtures are intentionally excluded.

## github.com/faustbrian/go-authorization/v4

`authorization` is an application-oriented authorization engine for typed Go policies. It uses explicit ACL, RBAC, and ABAC models rather than a positional string meta-model or separate policy language.

| Import path | Responsibility |
| --- | --- |
| [`github.com/faustbrian/go-authorization/v4`](../attribute.go) | Use for typed authorization requests and decisions, immutable snapshots, policy composition, and fail-closed evaluation. |
| [`github.com/faustbrian/go-authorization/v4/abac`](../abac/abac.go) | Use for bounded attribute-based policies with typed conditions and deterministic evaluation limits. |
| [`github.com/faustbrian/go-authorization/v4/acl`](../acl/acl.go) | Use for typed subject-to-resource access control lists and bounded resource listing. |
| [`github.com/faustbrian/go-authorization/v4/adapters/cache`](../adapters/cache/cache.go) | Use for advisory cache integration keyed by exact policy revision while retaining the repository as source of truth. |
| [`github.com/faustbrian/go-authorization/v4/adapters/http`](../adapters/http/http.go) | Use for the fail-closed net/http authorization adapter. |
| [`github.com/faustbrian/go-authorization/v4/adapters/jsonrpc`](../adapters/jsonrpc/jsonrpc.go) | Use for fail-closed native go-jsonrpc authorization middleware. |
| [`github.com/faustbrian/go-authorization/v4/adapters/otel`](../adapters/otel/otel.go) | Use to observe authorization decisions through caller-owned OpenTelemetry providers. |
| [`github.com/faustbrian/go-authorization/v4/adapters/slog`](../adapters/slog/slog.go) | Use to emit bounded authorization audit events through log/slog. |
| [`github.com/faustbrian/go-authorization/v4/authn`](../authn/authn.go) | Use to map an already authenticated principal into a typed authorization subject without validating credentials. |
| [`github.com/faustbrian/go-authorization/v4/authorizationtest`](../authorizationtest/authorizationtest.go) | Use in tests for deterministic requests, evaluators, assertions, snapshots, and adapter conformance. |
| [`github.com/faustbrian/go-authorization/v4/policy`](../policy/compiler.go) | Use for strict portable manifests, compilation, diff, dry-run, synchronization, and revisioned activation. |
| [`github.com/faustbrian/go-authorization/v4/postgres`](../postgres/migration.go) | Use for caller-owned PostgreSQL persistence of complete policy manifests with optimistic revision checks. |
| [`github.com/faustbrian/go-authorization/v4/rbac`](../rbac/document.go) | Use for tenant-safe roles, permissions, assignments, and bounded inheritance. |
| [`github.com/faustbrian/go-authorization/v4/valkey`](../valkey/invalidator.go) | Use for caller-owned Valkey revision invalidation with durable polling fallback. |

Choose the next guide in the [documentation index](README.md)
or return to the [repository entry](../README.md) for installation and ownership.
