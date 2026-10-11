# Contributing

## Before Editing

1. Read [`AGENTS.md`](AGENTS.md) and the affected package's docs.
2. Run the focused Go tests for the affected package.
3. Identify owned dependencies and reverse dependants in `modules.json`.
4. Preserve unrelated work and generated/corpus provenance.

## Changes

Keep commits focused and conventional. Update every affected changelog with
the behavior and migration impact. Public API changes require compatibility
evidence and documentation. Specification behavior requires a decision record,
fixture coverage, and interoperability evidence.

New direct dependencies and dependency updates must follow the
[dependency governance policy](AGENTS.md#dependencies-and-supply-chain). Package-local
update bots are forbidden; the root policy owns every module and action update.

Specification-backed changes must follow the
[specification governance contract](AGENTS.md#design), update
the affected stable decision entries, and complete the Specification Decisions
section of the pull request template. An unresolved interpretation or stale
source pin is release-blocking; peer behavior cannot silently select policy.

Selected full and release mutation gates must finish with zero surviving viable
mutants; mutation is not a prerequisite for ordinary edits or pull requests.

Do not add package-local workflows, permanent replacements, machine-specific
paths, bypass flags, broad mutation exclusions, or aggregate quality metrics
that hide a failing package.

## Verification

Use Go 1.27.2 from this standalone repository; no sibling checkout or ecosystem
goal ledger is required. Start with deterministic tests (including fuzz seeds):

```bash
GOWORK=off go test ./...
GOWORK=off go test ./policy -run '^$' -fuzz '^FuzzDecode$' -fuzztime=2s -timeout=2m
```

The second command is an explicit active fuzz smoke for the changed parser.
Choose the actual affected package and native fuzz target for other changes.

Install the exact published `golib` release declared by `.golib.yaml`, without
building it from source. CI verifies that release automatically. Ordinary routes:

```bash
make check
make ci
```

Both routes are bounded across the catalog's two modules, retaining PostgreSQL
and Valkey prerequisites and the selected snapshot race tests. Base-free local
checks run deterministic fuzz seeds/corpus, not active fuzz campaigns;
changed-source CI selects bounded active smoke for affected fuzz targets.
Direct backend tests use `POSTGRES_URL` and `VALKEY_ADDRESS` and skip when absent.
The `integration/contracts` module intentionally checks its existing public
compatibility bindings; run it directly with:

```bash
(cd integration/contracts && GOWORK=off go test -mod=readonly ./...)
```

Optional focused mutation and explicit full/API/release qualification:

```bash
golib mutation --module . --package rbac
make check-full
golib api check
golib release dry-run --module .
```

`check-full` retains the original coverage, mutation, fuzz, benchmark and
compatibility campaigns. Release rehearsals are available locally, not only in
CI. Report unavailable or failing commands; partial results are not release-ready.

## Adding A Module

Follow [repository structure policy](AGENTS.md#repository-structure). New modules
require an explicit purpose, ownership boundary, dependency review, package
catalog entry, full quality gates, documentation, changelog, license, security
policy, compatibility plan, and release dry-run.
