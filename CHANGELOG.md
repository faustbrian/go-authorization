# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog, and this project follows semantic
versioning for its Go API and portable policy format.

## Unreleased

### Maintenance

- Adopt OpenTelemetry API and SDK 1.47 with authorization APIs and
  decision semantics unchanged. Caller-owned metric exporters that used
  OTEL_GO_X_METRIC_EXPORT_BATCH_SIZE must configure WithMaxExportBatchSize
  instead; the experimental environment variable is no longer supported.
- Adopt pgx 5.11 for caller-owned PostgreSQL pools without changing the
  authorization store API, atomic manifest updates, or schema. Review
  connection-string parsing and non-positive pool lifetime settings when
  constructing pools; custom pgx Rows implementations now need TypeMap.
- Use Go 1.27.2 for development and CI builds to include patched standard
  library HTTP and TLS behavior. The public module minimum stays 1.27.0;
  applications should rebuild with the patched compiler.
- Adopt JSON-RPC 1.1.1 with the authorization middleware APIs and
  fail-closed admission rules unchanged. The host dispatcher now limits
  encoded responses to four MiB: oversized results or custom errors become
  internal errors. Aggregate overflow can fail after authorized methods
  execute; callers must not replay a batch assuming no effects occurred.
- Update the caller-owned Valkey client from 1.0.76 to 1.0.78 for
  connection shutdown and topology recovery fixes. Authorization APIs
  and policy formats remain unchanged.
- Update OpenTelemetry API and SDK requirements from 1.44.0 to 1.46.0.
  Default SDK histogram exemplars now use time-unbiased sampling; the update
  also fixes retained exemplar contexts and concurrent span-attribute reads.
  Review telemetry expectations when upgrading caller-owned providers;
  authorization APIs and decision semantics remain unchanged.
- Move the non-releasable integration contract to the published authorization
  v2.0.0 module while retaining principal, audit-log, and telemetry composition.
- Adopt published authorization v3.0.0 in that integration contract after
  root publication, retaining its principal, audit-log, and telemetry assertions.
- Exercise the public authorization v3 manifest cache adapter with Cache/v2
  storage, including a load followed by a hit without another loader call.

## 3.0.0 - 2026-09-30

### Changed

- Move the root module and all authorization imports to
  `github.com/faustbrian/go-authorization/v3` to adopt the published
  `github.com/faustbrian/go-cache/v2` security contract. Canonical and legacy
  cache adapters now expose v2 cache types rather than changing the published
  authorization v2 API in place. Update both authorization and cache imports
  together; published authorization v2 retains its historical behavior.
- Bound default cache-aside work to 1024 distinct flights, including canceled
  callers' retained work, and return `cache.ErrFlightLimit` at saturation.
  Repository diagnostic text is protected while `errors.Is` classification
  remains available. Cache `Close` has a five-second join bound;
  `Shutdown(ctx)` accepts the application's deadline and reports incomplete
  cleanup without claiming to terminate non-cooperative repository work.
- Keep policy formats, exact-revision loading, authoritative repository
  verification, and fail-closed authorization decisions unchanged.

### Maintenance

- Retain the non-releasable integration contract's published-v2 dependency
  until v3 publication permits a separate public-consumer adoption.

## 2.0.0 - 2026-09-30

### Changed

- Raise the minimum supported Go version from 1.26.6 to 1.27.0
  ([e0762d922e](https://github.com/faustbrian/go-authorization/commit/e0762d922e335ee5633bc973a831fca1ce692871)).
- Move the Go module to `github.com/faustbrian/go-authorization/v2` and return
  the `go-migrations/v2` type from `postgres.GoMigration`. Consumers must update
  authorization imports and migrations integrations together; the schema SQL
  and policy behavior are unchanged
  ([0894a2d44e](https://github.com/faustbrian/go-authorization/commit/0894a2d44e271bd46f34cdf96aef941ac8701c33)).

### Maintenance

- Adopt proportional CI assurance and align repository metadata with the
  published 1.1.0 release
  ([1b5318a2cd](https://github.com/faustbrian/go-authorization/commit/1b5318a2cd0b78b236e7ad564703f18acb6a72c0),
  [ce41a61000](https://github.com/faustbrian/go-authorization/commit/ce41a61000844dd3c06484a7799af336ad1b2892)).

## 1.1.0 - 2026-09-09

### Added

- Add target-oriented `adapters/cache`, `adapters/http`,
  `adapters/jsonrpc`, `adapters/otel`, and `adapters/slog` packages while
  retaining every existing adapter path through compatibility facades or
  implementations.
- Add the context-first `BeginInstrumenter` contract and
  `NewInstrumentedWithBegin` constructor with literal and typed-nil dependency
  validation before decision work.

### Changed

- Make the released `authlog` and `authotel` `Start` methods delegate to the
  additive `Begin` lifecycle while preserving their prior completion and
  provider-default behavior.
- Deprecate `authcache`, `authhttp`, `httpauth`, `authlog`, `authotel`, and
  `authrpc` in favor of their target-oriented successors without removing or
  changing their released signatures and named types.
- Adopt the checksum-verified `go-library-tools` v1.4.0 CLI, schema-v2 cohesion
  metadata, and repository-local cohesion gate without changing the public API
  or runtime behavior.
- Pin reusable CI to the immutable v1.4.0 W14-enforcement workflow.
- Run API compatibility through the module-toolchain-aware W14 baseline gate.
- Replace the repository-local verification implementation with the pinned
  `go-library-tools` v1.0.13 CLI and reusable workflow while preserving package
  policy and content-addressed evidence in this repository.
- Use canonical public module checksums for the root module and non-releasable
  integration contract instead of mutable-origin or bootstrap-only archives.

### Documentation

- Link consumers to the immutable v1.4.0 Golib ecosystem index and Service edge
  package-family guidance.
- Replace release-process evidence and the archived monorepo link with a
  package-owned documentation index.

## 1.0.0 - 2026-08-25

### Fixed

- Refresh the exported API baseline with the repository's Go 1.26 toolchain so
  identical JSON types are compared by their current standard-library identity.

- Bind the reviewed zero-mutant `authhttp` compatibility facade to its exact
  standalone source identity.

### Changed

- Exclude intentional nested modules from root local-proxy archives so local,
  bootstrap, CI, and public module checksums describe the same source
  boundary.

- Track the pinned documentation-tool lockfile so clean CI checkouts install
  the exact validated cspell dependency.

- Reconcile standalone dependency checksums against deterministic current
  module archives so CI, local verification, and release consumers resolve
  identical content.

- Harden standalone documentation validation with deterministic spelling and
  link checks, package-specific documentation gates, and repository-local
  contributor guidance.

### Documentation

- Correct stale package, standalone, and authoritative-source links in public
  documentation.

### Documentation

- Link the package README to package-owned documentation.

### Changed

- Publish the module from its standalone `github.com/faustbrian/go-authorization` identity while preserving its documented API and behavior.
- Replace obsolete owned-module pseudo-version pins with the monorepo's local
  `v0.0.0` source-proxy coordinates; release tooling continues to emit exact
  `v1.0.0` dependency versions.
- Delegate package mutation checks to the canonical exact-100 repository
  runner instead of permissive package-local Gremlins configuration.
- Require owned sibling modules at local `v0.0.0`; clean external consumers
  pin each module to an exact main pseudo-version.

- Align the integration-contract module's indirect system dependency with its
  resolved graph so clean consumers and CI obtain reproducible module metadata.
- Make synchronizer cancellation coverage deterministic across scheduler timing
  differences on local and hosted runners.
- Execute API compatibility tooling against the isolated module graph so owned
  dependency source changes cannot conflict with release checksums.
- Refresh owned-module checksums against the final consolidated archives.
- Normalized standalone module metadata against the canonical owned dependency
  graph, including complete checksums for clean consumer resolution.
- Use the repository-pinned current `apidiff` revision for the canonical API
  compatibility gate.

### Added

- Typed authorization requests, outcomes, reasons, explanations, and limits.
- Four explicit policy combining algorithms with exhaustive truth tables.
- Immutable revisioned snapshots and atomic optimistic engine replacement.
- Tenant-safe typed ACL evaluation, groups, batches, and resource-ID listing.
- Tenant-safe RBAC, bounded inheritance, effective permission inspection, and
  revisioned in-memory assignment administration.
- Closed typed ABAC conditions with versioned reusable conditions and bounded
  cost, depth, match, batch, and collection cardinality.
- Snapshot diff and decision dry-run support.
- Strict `authorization.policy/v1` JSON envelope and storage-neutral repository
  contract.
- Bounded manifest compiler with a copied, explicit model decoder registry.
- Strict versioned ACL, RBAC, and ABAC documents and built-in compiler
  decoders.
- PostgreSQL manifest repository with atomic optimistic updates and a reusable
  schema migration.
- Monotonic Valkey invalidation with durable revision polling and pub/sub
  wakeups.
- Repository synchronizer with direct source-of-truth polling and verified
  invalidation hints.
- Configurable fail-closed repository freshness enforcement for synchronizer
  authorization, including explicit stale-policy decisions.
- Fail-closed `net/http` integration with explicit request mapping and separate
  denial and internal-error handlers.
- Canonical `authhttp` package, dependency-neutral authenticated-principal
  mapper, and native fail-closed `jsonrpc` middleware.
- Failure-isolated decision instrumentation, bounded `log` audit events,
  `telemetry`-compatible OpenTelemetry metrics and spans, and an explicit
  advisory `cache` manifest adapter.
- Deterministic `authorizationtest` request builders, evaluators, assertions,
  canonical decision snapshots, and authorizer conformance suites.
- Independently bounded matched-policy diagnostics with explicit truncation
  propagated through engines, dry runs, snapshots, logs, and telemetry.
- Fail-closed evaluator panic containment and hostile-input fuzz coverage for
  every portable policy decoder.
- Positive snapshot revisions and pre-parse model/manifest byte limits, plus
  compiler policy-count and aggregate-document limits.
- Iterative ABAC condition preflight that enforces configured depth before
  descending into typed or portable condition trees.
- Pinned whole-module mutation testing with measured efficacy and mutant
  coverage gates.
- Shared ACL, RBAC, and ABAC model conformance, rolling-revision differential
  tests, and cold, warm, batch, inheritance, predicate, reload, compiler, and
  policy-size benchmarks.
- Complete API, model-selection, application-pattern, lifecycle, operations,
  security, troubleshooting, compatibility, and governance guides; a compiled
  multi-model example; and dedicated documentation and example automation.
- Formal decision tables, tenant-isolation evidence, a maintained hardening
  report, explicit stale-policy guidance, and versioned compatibility corpora.
- Executable consumer contracts for published `authentication`, `log`,
  and `telemetry` modules, including authentication claim collections.
- Environment-gated PostgreSQL and Valkey integration tests, manifest fuzzing,
  a decision benchmark, exact-coverage enforcement, and CI quality gates.
- API compatibility enforcement, reproducible release archives, release
  automation, security guidance, and an explicit threat model.
