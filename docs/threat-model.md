# Threat model

## Version 3 cache-adoption boundary

The v3 candidate adopts the published `go-cache/v2` contract through both
canonical and legacy adapters. Cache manifests remain reconstructible hints,
not authorization decisions or an authoritative policy source.

| Risk | Disposition and evidence | Owner, mitigation and review trigger |
| --- | --- | --- |
| High: distinct revision-key loads retain unbounded queued work after caller cancellation. | Mitigated by the v2 default 1024-flight admission budget. `TestManifestCacheBoundsCanceledDistinctKeyFlights` exercises both adapter paths and existing-key followers. | Maintainers and integrators; enforce request/key admission and bounded repository operations; review new loading paths or resource-limit incidents. |
| Medium: sensitive repository diagnostics cross public cache errors. | Mitigated by v2 error protection. `TestManifestCacheProtectsRepositoryDiagnostics` checks redacted text and preserved `errors.Is`. | Maintainers and integrators; keep full diagnostics at a trusted repository boundary; review error/telemetry changes. |
| Medium: trusted repository or backend ignores cancellation. | Accepted residual: bounded `Close` or `Shutdown(ctx)` can report incomplete cleanup; work may complete later. `TestManifestCacheCloseBoundsNonCooperativeRepository` checks bounded close, closed admission and successful join after release. | Integrators own callback/I/O deadlines and service supervision; maintainers own truthful lifecycle semantics. Review late-completion incidents or lifecycle/API changes. |
| High: stale cache state overrides a newer authoritative manifest. | Cache remains advisory; exact-revision loaders return a miss on mismatch and policy synchronization verifies the repository independently. Existing canonical/legacy repository-loader and synchronizer tests preserve this boundary. | Maintainers and integrators; never authorize from an unverified stale cache hint; review repository, compiler or synchronizer changes. |

The cancellation residual is Medium because it requires trusted application
code or infrastructure that disregards its context; the cache itself bounds
admission and the join deadline. These protections do not patch historical
authorization v2 or guarantee distributed/durable mutation ordering.

## Policy trust boundaries

The engine assumes policy publishers and application request mappers are
trusted code. Subjects, resource identifiers, tenant identifiers, attributes,
persisted policy documents, cache messages, and transport inputs are treated as
untrusted data.

The primary security properties are:

- no request is allowed without an explicit allow decision;
- explicit deny semantics are deterministic for the selected combining model;
- tenant-scoped rules do not cross tenant boundaries, and global inheritance is
  disabled unless explicitly configured;
- one decision observes one immutable policy snapshot;
- snapshot and stored-manifest revisions never roll back;
- malformed, oversized, cyclic, too-deep, too-costly, canceled, panicking, or
  otherwise invalid evaluation fails closed;
- invalidation messages are hints and cannot directly activate policy state;
  the authoritative repository is verified before activation; and
- traces, default HTTP responses, and policy evaluation errors do not include
  subject attributes or policy document contents.

The package does not authenticate users, derive trusted tenant membership,
secure database or Valkey credentials, authorize policy administration, or
provide network transport security. Applications remain responsible for those
boundaries and for ensuring request mappers do not accept attacker-controlled
identity or tenant claims without verification.

Resource listing is intentionally supported only where the model can enumerate
a bounded explicit set. An unbounded type-wide ACL grant returns an error rather
than causing a storage scan or pretending to return a complete result.

Operationally, applications should supervise synchronizer and invalidation
loops, alert on returned errors, retain the last verified immutable snapshot,
and decide whether prolonged inability to refresh policy requires disabling the
protected operation or removing the instance from service.

An evaluator panic is converted to a denied decision and a
`PolicyEvaluationError` that unwraps to `ErrPolicyPanic`. The panic value is
discarded because it may contain credentials or policy inputs. Panic recovery
protects the process boundary; it does not make a faulty evaluator healthy, so
operators should alert on the sentinel and replace the offending policy code.
