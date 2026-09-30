# Compatibility and governance

## Go API

The module follows semantic versioning. Exported removals, incompatible type or
method changes, and material semantic changes require the corresponding major
version decision. `./scripts/check-api.sh` compares the current module with the
checked-in API baseline.

The published v3 release uses `github.com/faustbrian/go-authorization/v3`.
Update all authorization imports and cache imports together: canonical and
legacy cache adapters expose `github.com/faustbrian/go-cache/v2` named types.
The previous concrete cache return and configuration types cannot silently
change in an authorization v2 patch. Published v1 and v2 authorization modules
remain available at their historical import paths and behavior; they do not
gain the v3 cache protections. No source directory or maintenance branch is
created for either historical major.

`postgres.GoMigration` continues returning a
`github.com/faustbrian/go-migrations/v2` migration. Portable policy formats,
repository verification, and authorization decision semantics are unchanged.
Direct consumers must choose their major migration explicitly; binaries using
different major imports can coexist but their named types are not interchangeable.

The non-releasable `integration/contracts` module consumes published
authorization v3.0.0 and Cache/v2 v2.0.0 without local replacements. It exercises
the canonical manifest cache adapter with the public memory backend, proving
that a loaded manifest is stored and a subsequent hit does not reload it.
Principal, audit-log, and telemetry interoperability remain covered against
published v3. Historical authorization v1/v2 consumers remain separate
compatibility variants; they do not exercise or inherit the v3 cache contract.

The supported Go versions are the versions exercised by the CI matrix. A
change to the minimum Go version is documented in the changelog and release
notes.

`integration/contracts` is an independent consumer module pinned to published
`authentication`, `log`, and `telemetry` revisions. Its test verifies
principal mapping, manifest cache load/hit composition, audit emission, and
telemetry provider interoperability without adding those modules to the core
runtime dependency graph.

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
