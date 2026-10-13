# Security model

[Documentation index](README.md) · [Repository entry](../README.md)

The library authorizes an already authenticated subject against trusted policy
and application-mapped facts. It does not authenticate identities, secure
transport, authorize policy administrators, or decide which database fields
are trustworthy.

## Security invariants

- Only an explicit final `Allow` grants access.
- Engine rejects invalid requests/outcomes, observed cancellation, evaluator
  errors/panics and selected count-limit violations with a denied result.
  Cancellation is cooperative; clocks, mappers, decoder/options and downstream
  callbacks are trusted code, not covered by evaluator panic recovery.
- Tenant policy is isolated unless global inheritance is explicitly enabled.
- Engine captures one complete snapshot per decision/batch. Metadata is copied;
  evaluator implementations remain borrowed and must be immutable/concurrency-safe.
- Engine replacement and PostgreSQL conditional updates require increasing
  revisions. Backend restoration/reset, administrative writes and uint64/signed
  bigint or Lua numeric ranges remain application/deployment responsibilities.
- Synchronizer authorization fails closed outside the repository-verification
  freshness window.
- Cache and invalidation data cannot directly activate policy.
- Selected work, batch, trace, match, set, depth and document counts/bytes have
  limits. They are not whole-process CPU, allocation, identifier-byte or callback
  duration budgets; some validation/building occurs before count rejection.
- Default engine diagnostics and observation schemas have no dedicated request
  value fields. IDs, reasons, custom callbacks and raw backend causes can still
  carry sensitive text; callers must keep them non-secret and redact exposure.

## Trust boundaries

Authentication adapters must verify subject identity before mapping it.
Resource and ownership attributes must come from authoritative application
state. Tenant, roles, scopes, network identity, and environment facts supplied
by a client are untrusted until independently verified.

Policy publishers are privileged. Restrict manifest update credentials,
separate approval from ordinary application roles, record optimistic revision
conflicts, and retain an immutable administrative audit trail.

PostgreSQL is authoritative. Valkey and `cache` contain hints or advisory
copies and may be stale, missing, duplicated, delayed, or attacker-influenced.
New revisions must be verified and compiled before activation. Synchronizer
accepts an envelope-valid equal revision as fresh without recompiling/comparing
its content: publishers must never change semantics at the same revision.

Sensitive revocations require protected operations to use
`policy.Synchronizer` as their authorizer. Direct calls to the underlying
`Engine` preserve snapshot coherence but do not enforce repository freshness.

## Sensitive data

Use opaque stable IDs for subjects, resources, and policies. Never use bearer
tokens, API-key secrets, credentials, personal attributes, or complete policy
documents as IDs, reason codes, metric labels, or span attributes.

`PolicyEvaluationError.Error` omits the underlying evaluator error. An
application can inspect the wrapped error programmatically, but must apply its
own redaction before logging it. Panic values are discarded entirely.

See the [threat model](threat-model.md) for attacker capabilities and residual
responsibilities, and [SECURITY.md](../SECURITY.md) for private reporting.

Choose the next guide in the [documentation index](README.md)
or return to the [repository entry](../README.md) for installation and ownership.
