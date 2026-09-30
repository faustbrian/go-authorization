# Compatibility and governance

## Go API

The module follows semantic versioning. Exported removals, incompatible type or
method changes, and material semantic changes require the corresponding major
version decision. `./scripts/check-api.sh` compares the current module with the
checked-in API baseline.

The v2 module uses `github.com/faustbrian/go-authorization/v2`. Applications
must update authorization imports together; `postgres.GoMigration` returns a
`github.com/faustbrian/go-migrations/v2` migration. The published v1 module
remains available at its original import path.

The non-releasable `integration/contracts` module selects the published
authorization v2.0.0 module without a local replacement. It retains the
principal, audit-log, and telemetry interoperability checks against that
public contract.

The supported Go versions are the versions exercised by the CI matrix. A
change to the minimum Go version is documented in the changelog and release
notes.

`integration/contracts` is an independent consumer module pinned to published
`authentication`, `log`, and `telemetry` revisions. Its test verifies
principal mapping, audit emission, and telemetry provider interoperability
without adding those modules to the core runtime dependency graph.

## Policy formats

`authorization.policy/v1` and the version fields inside ACL, RBAC, and ABAC
documents are public persistence contracts. Unknown fields and trailing data
are rejected intentionally. Adding optional fields must preserve the meaning of
old documents; incompatible syntax or semantics requires a new version and the
dual-reader migration described in [policy lifecycle](policy-lifecycle.md).

Combining behavior, default deny, tenant isolation, revision monotonicity, and
fail-closed errors are semantic contracts even when the Go type shape does not
change.

## Decision process

Changes to a security invariant, combining algorithm, portable format,
persistence contract, default limit, or redaction boundary require:

1. an explicit problem statement and compatibility analysis;
2. behavior-first tests, including hostile and cross-tenant cases;
3. API and format migration notes when applicable;
4. performance evidence for limit or hot-path changes;
5. threat-model and operations updates; and
6. a changelog entry.

Maintainers should prefer additive versioned evolution. Security fixes may
intentionally tighten previously accepted input or deny behavior; document the
impact and provide a migration path when doing so does not preserve a bypass.

## Releases

Releases are cut from signed annotated semantic-version tags after local and
hosted quality gates pass. The Go module proxy serves module archives and
`go.mod` files, with their hashes recorded by the public checksum database.
Optional custom GitHub release assets must be checksum-bound if published.

Until a stable release, only the latest tagged pre-1.0 line is supported. After
1.0, support windows and deprecation periods must be recorded here before an
older line is retired.
