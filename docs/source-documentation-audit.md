# Source documentation audit

## Owner, contract, consumers and smallest checks

Base bbc8f794d3ee74525428d6b532c5fd5ab391440e; detached main-source worktree.
Tier A documentation-only. Maintainers own explicit authorization values,
ACL/RBAC/ABAC evaluation, coherent engine publication and optional adapters.
Applications own authentication, tenant/resource/action trust, data freshness,
source/SDK/database/client lifecycle and configuration/refresh policy. Direct
consumers include Engine/Authorizer callers, policy publication/synchronization,
HTTP/JSON-RPC gates, cache/log/OTel adapters, compatibility facades and the separate
public-dependency integration/contracts test module. Existing identity-platform
worktrees and their frozen records are not this task's delivery boundary.

Audit every one of 93 tracked Go files across two modules: public/private
implementation, adapters/facades, tests/helpers, four declared fuzz boundaries,
benchmarks, examples and metadata/markers. The root has 23 catalog entries but
scripts is shell-only: scripts/check-api.sh requires an immutable apidiff identity
and reads api/authorization.txt, not a full-prose snapshot producer. Root .golib
API mode is apidiff; preserve the baseline. Integration/contracts contains two
Go test files and frozen released dependency bindings, not library source APIs.
No generated Go/build tag/go:generate marker is present; valid facade Deprecated
and explicit lint directives must be preserved.

Named risks: identity/action/resource/tenant matching versus authentication;
default-deny and combining precedence/short circuits; snapshot evaluator copying
versus borrowing; request/decision ownership and diagnostic/privacy bounds;
batch partial results, callback context/panic/liveness; policy cache/reload/revision
and backend publication/failure windows. Smallest checks: changed formatting,
all-file AST/noncomment token/literal/directive identity, public/member and canonical
header structure, parsed HTML and native renders for all actual source packages;
local source/docs/offline specification and affected local links, frozen inputs,
pinned changed/staged secrets and one ordinary complete-diff truth/usefulness
inspection. Native API signature proof follows source identity, without rewriting
structural baselines. Unchanged examples/runtime/tests, races/leaks, active fuzz,
benchmarks, PostgreSQL/Valkey services, consumers and release campaigns are not
selected. Go waits for the coordinator's explicit slot and uses three owned
immediately disposable caches, including failure cleanup.

## Missing versus investigated documentation

Initially missing: root canonical package comment, many exported identifiers,
fields/interface methods and option contracts; semantic matching/ownership and
resource/callback/lifecycle/privacy boundaries; important cache/snapshot/reload
invariants and test/fuzz/benchmark intent. Existing useful comments stay.
Deprecated facades retain their versioned successor links and actual identities.
No TODO/FIXME/HACK/generated/build marker was found.

Investigated: exact identity/action/resource/tenant matching is separate from
upstream authentication and trusted fact mapping. Engine default-denies, but
standalone models return NotApplicable; scopes/precedence and cancellation
checkpoints differ intentionally. Snapshot metadata is copied while custom
Evaluators remain borrowed. Request maps/groups, unused assignment attributes,
repositories, decoder/option/clock/observer/SDK callbacks have their documented
ownership and cooperative concurrency obligations. Batch results remain ordered
with joined errors, not a transaction.

Parser profiles are application envelope authorization.policy/v1 and built-in
model DocumentVersion 1; they are not external authorization standards.
encoding/json rejects unknown/trailing data, accepts duplicate members last-wins,
and materializes before constructor count checks. Encode limits apply after
allocation; compiler validation precedes its selected byte/count caps. ABAC cost
is visited nodes, not string CPU or a constructor heap budget. Diff/DryRun do not
prove evaluator equivalence, undo side effects or install candidates.

Synchronizer's equal-revision envelope check refreshes verification without
recompile/content comparison; publishers must preserve revision semantics.
Freshness admits at Decide entry, not throughout callbacks. Cache hits are
advisory; exact-revision loaders cannot authenticate content or replace repository
verification. PostgreSQL update is one conditional statement, not a cross-store
transaction, and SQL bigint has a smaller range than public uint64. Lua tonumber
is not exact full-uint64 ordering; missing Valkey keys do not prove never-published.
Receive shutdown joins cooperative client I/O. Unknown write outcomes require
reconciliation rather than blind replay.

Observation schemas omit dedicated request fields, not arbitrary secret-bearing
IDs/reasons/raw causes. Count caps do not bound text; direct slog callbacks are
repeatable and OTel completion is once-only, not durable delivery. SDK panic before
End and authorizer panic before finish can leave observations incomplete. OTel
v1.47.0, cache/v2, JSON-RPC v1.1.1, migrations/v2, pgx v5.11.0 and Valkey v1.0.78
remain exact existing dependencies, not newly qualified integrations. Seven facade
Deprecated contracts/reflection identities and lint directives remain intact.

Rationale supported by tests includes [coherent replacement](../engine_test.go),
[missing/null expression semantics](../abac/abac_test.go),
[acyclic role inheritance](../rbac/rbac_test.go),
[revision verification](../policy/synchronizer_test.go),
[observation privacy](../instrumentation_test.go), and
[released adapter identity/cache boundaries](../adapter_successor_test.go).
The file inventory below lists every existing test, helper, example, fuzz and
benchmark entrypoint. Their unchanged bodies were investigated, not executed.
Fuzz targets assert panic safety, not semantic conformance; benchmarks vary their
named local workload rather than supporting a new performance claim.

No unresolved documentation gap remains. No pinned specification/decision
register exists in either module, so no decision history/source authority is
fabricated or rewritten. Unknown original reasons for unguarded typed-nil/custom
callback seams, same-revision no-recompile behavior and backend numeric domains
are not invented. Runtime hardening or broader guarantees would need a separately
scoped behavioral decision; this pass documents those observable limitations.

## Reproducible complete module/package/file inventory

Use git ls-files '*.go' '*go.mod' '*go.sum', modules.json/packages.json, package
and declaration/marker scans, .golib.yaml and scripts/check-api.sh/Make/CI.
Root is github.com/faustbrian/go-authorization/v3; nested test module is
 github.com/faustbrian/go-authorization/integration/contracts. Both minimums
are Go 1.27.0; repository verification pins 1.27.2. All paths are below.

| Go file | Package | Audit role and existing evidence |
| --- | --- | --- |
| `abac/abac.go` | `abac` | Source contract and important private invariant |
| `abac/abac_test.go` | `abac_test` | Existing test/helper evidence: TestEvaluatorUsesTypedAttributeSources, TestConditionMissingNullAndTypeMismatchSemantics, TestBoundedConditionOperators, TestNamedConditionsAreVersionedAndReusable, TestEvaluatorOrderingIsDeterministic, TestEvaluatorContinuesAfterNonMatchingRule, TestEvaluatorFailsClosedOnLimitsAndCancellation, TestEvaluateConditionRejectsMalformedConditions, TestNewRejectsInvalidRulesAndNamedConditions, TestConditionValidationRejectsInvalidOperands, TestConditionCardinalityLimitsNestedAndLiteralSets, TestOperatorNonMatchAndTypeSemantics, TestConditionsTreatPresentMissingValuesAsMissing, TestAnyPreservesFirstDiagnosticStatus, TestEqualSupportsEveryValueKind, TestEvaluatorSkipsScopesAndNonMatchingConditions, TestEvaluatorNeverGrantsMismatchedScopes, TestAllRequiresEveryChildToMatch, TestEvaluatorBatchReturnsEquivalentDecisionsAndErrors, TestConditionCancellationAtEveryNodeBoundary, TestNestedValidationPropagatesChildErrors, TestLoadOperatorsPreserveMissingStatus, TestRuntimeAttributeCollectionsAreBounded |
| `abac/benchmark_test.go` | `abac` | Existing test/helper evidence: BenchmarkEvaluatePredicateCount |
| `abac/conditions.go` | `abac` | Source contract and important private invariant |
| `abac/document.go` | `abac` | Source contract and important private invariant |
| `abac/document_test.go` | `abac` | Existing test/helper evidence: TestDocumentDecodeEncodeAndEvaluate, TestConditionDocumentPreservesOperatorSemantics, TestDocumentRejectsInvalidInput, TestValueDocumentTimeUsesUTC, TestConditionValidationAppliesBoundsBeforeDescending, TestDocumentBuildAppliesDepthBeforeNestedSemantics, TestDocumentBuildValidatesInlineRulesAfterConditionReferences |
| `abac/example_test.go` | `abac_test` | Existing test/helper evidence: Example |
| `abac/fuzz_test.go` | `abac` | Existing test/helper evidence: FuzzDecodeDocument |
| `acl/acl.go` | `acl` | Source contract and important private invariant |
| `acl/acl_test.go` | `acl_test` | Existing test/helper evidence: TestEvaluatorMatchesInstanceAndTypeEntries, TestEvaluatorExplicitDenyOverridesAllow, TestEvaluatorTenantAndGlobalScopes, TestDuplicateGroupsDoNotHideLaterPrincipals, TestNewRejectsInvalidEntries, TestEvaluatorMatchesTrustedSubjectGroups, TestEvaluatorEnforcesWorkLimitsAndCancellation, TestEvaluatorBatchMatchesIndependentDecisions, TestEvaluatorListsExplicitlyAllowedResourceIDs, TestEvaluatorPreservesEntryIdentityThroughRootEngine, TestListResourceIDsHonorsBoundsGroupsAndTypeDeny, TestListResourceIDsContinuesAfterNonMatchingAndTypeWideEntries |
| `acl/benchmark_test.go` | `acl` | Existing test/helper evidence: BenchmarkEvaluateByPolicySize |
| `acl/document.go` | `acl` | Source contract and important private invariant |
| `acl/document_test.go` | `acl` | Existing test/helper evidence: TestDocumentDecodeEncodeAndEvaluate, TestDocumentRejectsInvalidInput |
| `acl/example_test.go` | `acl_test` | Existing test/helper evidence: Example |
| `acl/fuzz_test.go` | `acl` | Existing test/helper evidence: FuzzDecodeDocument |
| `adapter_successor_test.go` | `authorization_test` | Existing test/helper evidence: TestAdapterSuccessorsPreserveSentinelIdentity, TestLegacyAdaptersRetainNamedReflectionIdentity, TestLegacyInstrumentersRetainReflectionVisibleLayouts, TestSuccessorAdaptersExposeTargetOrientedNamedIdentities, TestManifestCacheBoundsCanceledDistinctKeyFlights, TestManifestCacheProtectsRepositoryDiagnostics, TestManifestCacheCloseBoundsNonCooperativeRepository, TestManifestCacheShutdownPropagatesCancellationAndJoins |
| `adapters/cache/cache.go` | `authorizationcache` | Source contract and important private invariant |
| `adapters/cache/cache_test.go` | `authorizationcache` | Existing test/helper evidence: TestManifestCodecRoundTripsStrictPolicyFormat, TestNewManifestCacheUsesIsolatedRevisionKeys, TestRevisionKeyEncoderAndRepositoryLoader |
| `adapters/http/http.go` | `authorizationhttp` | Source contract and important private invariant |
| `adapters/http/http_test.go` | `authorizationhttp` | Existing test/helper evidence: TestHandlerAllowsAndExposesDecision, TestHandlerDenialsFailuresOptionsAndValidation |
| `adapters/jsonrpc/jsonrpc.go` | `authorizationjsonrpc` | Source contract and important private invariant |
| `adapters/jsonrpc/jsonrpc_test.go` | `authorizationjsonrpc` | Existing test/helper evidence: TestMiddlewareAllowsAndExposesDecision, TestMiddlewareFailuresOptionsAndValidation |
| `adapters/otel/otel.go` | `authorizationotel` | Source contract and important private invariant |
| `adapters/otel/otel_test.go` | `authorizationotel` | Existing test/helper evidence: TestNewRejectsLiteralAndTypedNilProviders, TestBeginAndStartUseExplicitProviders, TestNewPreservesInstrumentConstructionErrors |
| `adapters/slog/slog.go` | `authorizationslog` | Source contract and important private invariant |
| `adapters/slog/slog_test.go` | `authorizationslog` | Existing test/helper evidence: TestInstrumenterBeginWritesRepeatableBoundedEvents, TestNewRejectsNilLogger |
| `attribute.go` | `authorization` | Source contract and important private invariant |
| `attribute_test.go` | `authorization` | Existing test/helper evidence: TestTypedAttributeValues, TestValueEqualityAndOrdering, TestValueCollectionLength |
| `authcache/authcache.go` | `authcache` | Source contract and important private invariant |
| `authcache/authcache_test.go` | `authcache` | Existing test/helper evidence: TestManifestCodecRoundTripsStrictPolicyFormat, TestNewManifestCacheUsesIsolatedRevisionKeys, TestRevisionKeyEncoderAndRepositoryLoader |
| `authhttp/authhttp.go` | `authhttp` | Source contract and important private invariant |
| `authhttp/authhttp_test.go` | `authhttp` | Existing test/helper evidence: TestHandlerCompatibilitySurface |
| `authlog/authlog.go` | `authlog` | Source contract and important private invariant |
| `authlog/authlog_test.go` | `authlog` | Existing test/helper evidence: TestInstrumenterWritesBoundedAuditEvent, TestNewRejectsNilLogger |
| `authn/authn.go` | `authn` | Source contract and important private invariant |
| `authn/authn_test.go` | `authn` | Existing test/helper evidence: TestSubjectMapsExplicitClaimsAndGroups, TestSubjectAcceptsGroupsAtExactLimit, TestSubjectFailsClosed, TestClaimValueSupportsEveryBoundedScalar |
| `authorizationtest/authorizationtest.go` | `authorizationtest` | Source contract and important private invariant |
| `authorizationtest/authorizationtest_internal_test.go` | `authorizationtest` | Existing test/helper evidence: TestFailureReportingBranches |
| `authorizationtest/authorizationtest_test.go` | `authorizationtest_test` | Existing test/helper evidence: TestRequestBuilderCreatesIndependentDeterministicRequests, TestRequestBuilderOverridesTypedFields, TestStaticEvaluators, TestCanonicalDecisionJSON, TestMustHelpersAndDecisionAssertions, TestRunAuthorizerConformance |
| `authotel/authotel.go` | `authotel` | Source contract and important private invariant |
| `authotel/authotel_test.go` | `authotel` | Existing test/helper evidence: TestInstrumenterRecordsBoundedMetricsAndSpan, TestInstrumenterNormalizesBoundedResults, TestNewReturnsInstrumentConstructionErrors |
| `authrpc/authrpc.go` | `authrpc` | Source contract and important private invariant |
| `authrpc/authrpc_test.go` | `authrpc` | Existing test/helper evidence: TestMiddlewareAllowsAndExposesDecision, TestMiddlewareMapsDenialsAndFailures, TestMiddlewareOptionsAndValidation |
| `benchmark_test.go` | `authorization` | Existing test/helper evidence: BenchmarkEngineDecideWarm, BenchmarkEngineDecideCold, BenchmarkEngineDecideBatch100, BenchmarkEngineReload |
| `decision.go` | `authorization` | Source contract and important private invariant |
| `decision_test.go` | `authorization` | Existing test/helper evidence: TestCombineDenyOverrides, TestCombineAllowOverrides, TestCombineOrderedAlgorithms, TestCombineRejectsInvalidInput, TestCombiningAlgorithmString, TestOutcomeString, TestCombiningAlgorithmsExhaustiveTruthTables |
| `engine.go` | `authorization` | Source contract and important private invariant |
| `engine_test.go` | `authorization` | Existing test/helper evidence: TestEngineDefaultsToDeny, TestEngineCombinesAndExplainsApplicablePolicies, TestEngineEvaluatesPriorityOrderUntilApplicable, TestEngineStopsAfterDecisiveOutcome, TestEngineFailsClosed, TestEngineDecideBatchMatchesIndependentDecisions, TestEngineReplaceSnapshotIsMonotonicAndOptimistic, TestEngineBoundsPoliciesAndTrace, TestEngineZeroLimitsRetainDefaultsAndExactPolicyLimitIsAccepted, TestEngineHonorsCancellationBeforeEvaluation, TestEngineUsesRequestTimeForActivationWindows, TestNewEngineRejectsNilSnapshot, TestEngineRevision, TestEngineUsesInjectedClock, TestPolicyEvaluationErrorRedactsCause, TestEngineReplaceSnapshotRejectsNilAndOversizedSnapshots, TestEngineBatchReturnsDecisionsWithValidationErrors, TestEngineHonorsCancellationBetweenPolicies, TestEngineFailsClosedForCorruptedSnapshotAlgorithm, TestEngineAllowsOnlyOneConcurrentSnapshotReplacement, TestEngineConcurrentDecisionsUseOneCoherentSnapshot, TestEnginePreservesEvaluatorMatchedPolicyIDs |
| `examples/tenant_documents/main.go` | `main` | Source contract and important private invariant |
| `httpauth/httpauth.go` | `httpauth` | Source contract and important private invariant |
| `httpauth/httpauth_test.go` | `httpauth` | Existing test/helper evidence: TestHandlerAllowsAndExposesDecision, TestHandlerDeniesWithoutCallingNext, TestHandlerFailsClosedOnMapperEvaluatorAndOutcomeErrors, TestHandlerSupportsCustomDenialAndErrorHandlers, TestNewHandlerValidatesDependencies |
| `instrumentation.go` | `authorization` | Source contract and important private invariant |
| `instrumentation_test.go` | `authorization` | Existing test/helper evidence: TestNewInstrumentedWithBeginRejectsNilDependenciesBeforeClock, TestInstrumentedWithBeginUsesBoundedCommonObservation, TestInstrumentedWithBeginIsolatesObservationPanics, TestInstrumentedAuthorizerEmitsBoundedEvent, TestInstrumentedAuthorizerPreservesUpstreamDiagnosticTruncation, TestInstrumentedAuthorizerPreservesExactInstrumentationBoundaries, TestInstrumentedAuthorizerPreservesFailuresAndIsolatesInstrumentation, TestInstrumentedAuthorizerValidatesConfigAndClampsClock |
| `integration/contracts/authentication_v2_test.go` | `contracts_test` | Existing test/helper evidence: TestAuthenticationV2AdmissionAndMapping, TestAuthenticationV2MappingRejectsInvalidSubjects |
| `integration/contracts/contracts_test.go` | `contracts_test` | Existing test/helper evidence: TestPublishedManifestCacheLoadsThenHits, TestOwnedModuleInteroperability |
| `internal/authorizationotel/instrumenter.go` | `authorizationotel` | Source contract and important private invariant |
| `internal/authorizationotel/instrumenter_test.go` | `authorizationotel` | Existing test/helper evidence: TestInstrumenterRecordsOneBoundedCompletion, TestNewPreservesInstrumentConstructionErrors, TestResultClassifications |
| `jsonrpc_dispatch_contract_test.go` | `authorization_test` | Existing test/helper evidence: TestRPCDispatcherBoundsAuthorizationResponses, TestRPCDispatcherPreservesFailClosedWireContracts, TestRPCDispatcherMixedBatchKeepsAdmissionAndDecisionsIsolated |
| `model_conformance_test.go` | `authorization_test` | Existing test/helper evidence: TestPolicyModelsConformToCommonOutcomes |
| `otel_sdk_compatibility_test.go` | `authorization_test` | Existing test/helper evidence: TestOTelSDKPreservesBoundedCompletionData |
| `policy/benchmark_test.go` | `policy_test` | Existing test/helper evidence: BenchmarkCompilerCompile |
| `policy/compatibility_test.go` | `policy_test` | Existing test/helper evidence: TestVersionOneCompatibilityCorpus |
| `policy/compiler.go` | `policy` | Source contract and important private invariant |
| `policy/compiler_test.go` | `policy` | Existing test/helper evidence: TestCompilerBuildsSnapshotWithModelDecoder, TestCompilerMapsEveryAlgorithm, TestCompilerFailsClosed, TestCompilerAcceptsExactConfiguredLimits, TestNewCompilerRejectsNilDecoderAndCopiesRegistry |
| `policy/fuzz_test.go` | `policy` | Existing test/helper evidence: FuzzDecode |
| `policy/manifest.go` | `policy` | Source contract and important private invariant |
| `policy/manifest_test.go` | `policy_test` | Existing test/helper evidence: TestManifestRoundTripsStrictHumanReadableJSON, TestManifestValidationAndStrictDecode |
| `policy/policy.go` | `policy` | Source contract and important private invariant |
| `policy/policy_test.go` | `policy_test` | Existing test/helper evidence: TestDiffReportsAddedRemovedAndChangedPolicies, TestDryRunComparesDecisionsWithoutChangingPrimary, TestDryRunDetectsMatchedPolicyDiagnosticTruncation, TestDiffAndDryRunRejectNilAndBoundOversizedSnapshots, TestDiffSortsMultiplePolicyIDs, TestDiffDetectsEachInspectablePolicyChange, TestDryRunDetectsEachDecisionDifference |
| `policy/rolling_test.go` | `policy_test` | Existing test/helper evidence: TestRollingDeploymentConvergesOnOneRevision |
| `policy/synchronizer.go` | `policy` | Source contract and important private invariant |
| `policy/synchronizer_test.go` | `policy` | Existing test/helper evidence: TestSynchronizerReloadsNewerManifest, TestSynchronizerAuthorizerFailsClosedOutsideFreshnessWindow, TestSynchronizerFailsClosed, TestSynchronizerRejectsCanceledAndConcurrentReplacement, TestSynchronizerObserveVerifiesHintAgainstRepository, TestSynchronizerRunPollsSourceOfTruth, TestSynchronizerRunReturnsCancellation, TestSynchronizerRunReturnsReloadError, TestSynchronizerRunReturnsPollingError, TestNewSynchronizerValidatesDependencies |
| `postgres/cancellation_integration_test.go` | `postgres_test` | Existing test/helper evidence: TestIntegrationCanceledBlockedUpdateReleasesConnection |
| `postgres/integration_test.go` | `postgres_test` | Existing test/helper evidence: TestIntegrationAtomicManifestUpdates |
| `postgres/migration.go` | `postgres` | Source contract and important private invariant |
| `postgres/store.go` | `postgres` | Source contract and important private invariant |
| `postgres/store_test.go` | `postgres` | Existing test/helper evidence: TestStoreLoadAndUpdateManifest, TestStoreErrorsAreFailClosed, TestNewValidatesPool, TestSchemaMigrationAndGoMigration |
| `rbac/benchmark_test.go` | `rbac` | Existing test/helper evidence: BenchmarkEvaluateInheritanceDepth |
| `rbac/document.go` | `rbac` | Source contract and important private invariant |
| `rbac/document_test.go` | `rbac` | Existing test/helper evidence: TestDocumentDecodeEncodeAndEvaluate, TestDocumentRejectsInvalidInput |
| `rbac/example_test.go` | `rbac_test` | Existing test/helper evidence: Example |
| `rbac/fuzz_test.go` | `rbac` | Existing test/helper evidence: FuzzDecodeDocument |
| `rbac/manager.go` | `rbac` | Source contract and important private invariant |
| `rbac/manager_test.go` | `rbac_test` | Existing test/helper evidence: TestManagerAssignInspectRevokeAndSnapshot, TestManagerRejectsInvalidInitialStateAndRevokesByID, TestManagerSupportsConcurrentAdministrationAndInspection |
| `rbac/rbac.go` | `rbac` | Source contract and important private invariant |
| `rbac/rbac_test.go` | `rbac_test` | Existing test/helper evidence: TestEvaluatorCombinesAssignedRolePermissions, TestEvaluatorSkipsEveryMismatchedPermissionScope, TestEvaluatorInheritsRolesAndCalculatesEffectivePermissions, TestNewRejectsRoleCyclesAndDepthOverflow, TestNewValidatesRolesPermissionsAndAssignments, TestEvaluatorGlobalInheritanceGroupsAndPriorityOrder, TestEvaluatorEnforcesLimitsCancellationAndBatchBounds |
| `request.go` | `authorization` | Source contract and important private invariant |
| `request_test.go` | `authorization` | Existing test/helper evidence: TestRequestValidate, TestRequestValidateAllowsResourceTypeAndGlobalScope, TestRequestValidateRejectsEmptyGroupID |
| `snapshot.go` | `authorization` | Source contract and important private invariant |
| `snapshot_test.go` | `authorization` | Existing test/helper evidence: TestNewSnapshotRejectsInvalidPolicies, TestNewSnapshotRejectsZeroRevision, TestSnapshotCopiesInspectablePolicyMetadata, TestNewSnapshotRejectsInvalidActivationWindow, TestNewSnapshotAcceptsOpenActivationWindows, TestNewSnapshotRejectsInvalidCombiningAlgorithm |
| `valkey/integration_test.go` | `valkey_test` | Existing test/helper evidence: TestIntegrationDurableInvalidationAndPolling |
| `valkey/invalidator.go` | `valkey` | Source contract and important private invariant |
| `valkey/invalidator_test.go` | `valkey` | Existing test/helper evidence: TestNewValidatesOptions, TestPublishAdvancesMonotonically, TestPublishFailsClosed, TestRevisionReadsDurableState, TestRevisionRejectsUnavailableOrInvalidState, TestWatchUsesDurableRevisionAfterPubSubWakeup, TestWatchStopsAfterSuccessfulHandler, TestWatchPollsWhenPubSubFails, TestWatchValidatesInputsAndErrors |

## Verification disposition

Inventory preceded source edits. The bounded Go 1.27.2 session formatted 44 owned
Go files and proved all 93 parsed executable ASTs, noncomment tokens/literals and
implicit semicolons identical. All module/catalog/.golib/.go-version/structural
API bytes and retained directives are unchanged. All 836 parsed comment groups rendered as HTML; 794 public declarations,
fields/interface methods and 22 canonical package headers passed the structural
inspection. All 22 actual source packages rendered with
native go doc -all, excluding shell-only scripts and the test-only contract module.
Native source structure has zero findings, local documentation is valid, and
offline specification reports zero registered modules/decisions. The final affected prose refresh repeated exact all-file identity/comment
proof and seven affected native renders; 15 unchanged original renders and the
zero-register offline specification proof were reused. Local source evidence
does not certify hosted CI or services. Changed relative links, default pinned
secret scans and ordinary complete-diff inspection support the prose delivery;
staged content receives its own final secret scan before commit.
Unchanged executable examples/tests/fixtures, backend services, active fuzz,
benchmarks, race/leak/conformance/public consumers/online/releases were not run.
Runtime/dependencies/fixtures/frozen identity-platform records remain unchanged.

## Objective Enforcement

The checksum-pinned public Tools v2.4.0 verifier now supplies
`make source-docs-check` as a prerequisite of the existing local and CI Make
routes. Ordinary shared CI selects strict source-documentation checking and
requires its result. Native prerequisites, operation budgets, security and
release controls are retained. Hosted exact-head evidence is recorded by the
coordination ledger; configuration alone does not establish green delivery.
