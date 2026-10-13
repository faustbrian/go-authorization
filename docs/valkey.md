# Valkey invalidation

[Documentation index](README.md) · [Repository entry](../README.md)

The `valkey` package distributes policy revision changes across application
processes as advisory hints. It sets a revision key and publishes a wakeup in
the same Lua operation. Persistence/replication, credentials and key isolation
are deployment-owned; this is not a durable publication transaction with PostgreSQL.
Lua `tonumber` comparison is not exact across the full uint64 domain: keep
revisions within the backend numeric representation that the application uses.

```go
invalidator, err := authvalkey.New(client, authvalkey.Options{
    Prefix:       "my-service:authorization",
    PollInterval: 15 * time.Second,
})
if err != nil {
    return err
}

_, err = invalidator.Publish(ctx, stored.Revision)
```

Consumers pass their active revision to `Watch` and reload the authoritative
manifest when a newer revision appears. `policy.Synchronizer` provides that
verified activation path:

```go
synchronizer, err := policy.NewSynchronizer(repository, compiler, engine)
if err != nil {
    return err
}

group.Go(func() error { return synchronizer.Run(ctx) })
group.Go(func() error {
    return invalidator.Watch(ctx, engine.Revision(), synchronizer.Observe)
})
```

Pub/sub payloads are deliberately ignored. A message only wakes the watcher,
which then reads the advisory revision key. The watcher also polls that key at
the configured interval and continues polling after pub/sub disconnects. This
avoids depending on delivery order, but does not preserve a deleted/evicted or
restored key. A missing key means zero, not proof no policy was published.
Watch runs the handler serially and advances its local revision only after
success. It joins the Receive goroutine on exit, so cancellation requires
cooperative client I/O; handler panic/blocking is not contained.

Valkey is an invalidation transport, not the policy source of truth. A failure
to read Valkey or reload the manifest is returned to the caller and must not be
converted into an allow decision. The synchronizer polls the repository
directly as the correctness path, so a PostgreSQL publication that occurs while
Valkey is unavailable is still discovered. Valkey only reduces propagation
latency.

Choose the next guide in the [documentation index](README.md)
or return to the [repository entry](../README.md) for installation and ownership.
