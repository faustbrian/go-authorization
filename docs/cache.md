# Cache integration

The `adapters/cache` package configures a typed `cache` cache for versioned
policy manifests. It provides a strict manifest codec, hashed revision keys,
bounded encoded values, and an optional repository loader. The released
`authcache` path remains a deprecated compatibility facade.

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

`authorizationcache.RepositoryLoader` returns a `cache` loader that reports a
hit only when the repository's current manifest exactly matches the requested revision.
It does not cache an arbitrary latest manifest under a stale revision key.
