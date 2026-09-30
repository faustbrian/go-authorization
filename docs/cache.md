# Cache integration

The `adapters/cache` package configures a typed `cache` cache for versioned
policy manifests. It provides a strict manifest codec, hashed revision keys,
bounded encoded values, and an optional repository loader. The released
`authcache` path remains a deprecated compatibility facade.

Both v3 paths use `github.com/faustbrian/go-cache/v2`. Update backend, clock,
TTL, observer, loader, and returned cache imports together; published
authorization v2 adapters continue using the historical v1 cache contract.

```go
manifests, err := authorizationcache.New(authorizationcache.Config{
    Namespace: "billing",
    Backend:   backend,
    Clock:     cache.SystemClock{},
    TTL:       cache.TTLPolicy{TTL: time.Minute},
})
```

The cache is advisory. A cached manifest must still be compiled and compared
against the active revision, and it must never override a newer repository
manifest. `policy.Synchronizer` continues polling the storage-neutral
repository as the correctness path.

`adapters/cache` bounds each encoded manifest and cache batch. The injected backend
owns the bound on total retained entries and bytes. Production deployments must
use a backend with hard capacity limits and a finite TTL; for the in-memory
backend, configure both `memory.Config.MaxEntries` and
`memory.Config.MaxBytes`. This prevents successive policy revisions from
growing retained cache state without limit.

Default cache-aside admission retains at most 1024 distinct-key flights,
including queued work and loads retained after their caller cancels. Excess
new keys return `cache.ErrFlightLimit`; existing-key coalescing does not reserve
another flight. The cache separately limits executing loaders. Cancellation
reaches the repository context, but application callbacks must cooperate.
Loader diagnostics returned through the core `Cache.GetOrLoad` boundary are
redacted; use `errors.Is` for classification and capture sensitive diagnostics
only at the trusted repository boundary. Calling `RepositoryLoader` directly
returns raw repository errors, which callers must handle as protected
diagnostics rather than exposing to public responses or unrestricted logs.

`Close` closes admission before joining loads for at most five seconds.
Prefer `Shutdown(ctx)` with the service shutdown deadline. A successful join
means active loads finished; `cache.ErrShutdownIncomplete` explicitly permits
late completion by a cancellation-ignoring repository or already-admitted
backend operation. The injected backend's lifecycle remains application-owned.

`authorizationcache.RepositoryLoader` returns a `cache` loader that reports a
hit only when the repository's current manifest exactly matches the requested revision.
It does not cache an arbitrary latest manifest under a stale revision key.
