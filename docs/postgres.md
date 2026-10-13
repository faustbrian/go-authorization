# PostgreSQL persistence

[Documentation index](README.md) · [Repository entry](../README.md)

The `postgres` package stores one complete `policy.Manifest` as the current
authorization state. Updates use the manifest revision as an optimistic lock,
so policy publication is atomic across every ACL, RBAC, ABAC, and composite
record in that manifest.

Apply `postgres.GoMigration()` with `go-migrations/v2`, or apply the SQL returned
by `postgres.SchemaMigration()` with the application's migration system. The
migration creates the `authorization_policy_manifests` table.

```go
store, err := postgres.New(pool)
if err != nil {
    return err
}

current, err := store.Load(ctx)
if err != nil {
    return err
}

next := current
next.Revision++

stored, err := store.Update(ctx, current.Revision, next)
if err != nil {
    return err
}
```

`Update` succeeds only when the stored revision equals the expected revision
and the replacement revision is greater. Concurrent writers receive
`postgres.ErrRevisionConflict`; stale or equal replacement revisions receive
`postgres.ErrRevisionNotMonotonic`. Missing initial state is reported as
`postgres.ErrNotInitialized` rather than being interpreted as an empty allow
policy.

The first manifest must be written with expected revision `0`. Initialization
with any other expected revision returns `postgres.ErrRevisionConflict`, so an
empty table does not bypass optimistic concurrency.

The schema revision uses signed bigint while the public API uses uint64; keep
revisions in the compatible signed range. Load reads the JSON manifest without
cross-checking its revision against the SQL column, and driver row allocation
precedes the parser byte cap. Driver errors can expose raw diagnostics; a write
may have committed when response/decoding fails, so reconcile with Load before
retrying unknown outcomes. Store borrows the pool and owns neither schema
execution, retries, invalidation nor shutdown. The supplied Down migration
irreversibly drops the policy table.

The PostgreSQL row remains the source of truth. Caches and invalidation signals
must never turn a missing, stale, or unavailable policy into an allow decision.

Choose the next guide in the [documentation index](README.md)
or return to the [repository entry](../README.md) for installation and ownership.
