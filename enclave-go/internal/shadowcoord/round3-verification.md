# PR 4 round-3 verification

Base HEAD `4d7cf2ba`, branch `speculation/shadow-coordinator-go`. All changes remain
uncommitted. No git write or deployment was performed. Mode remains off by default;
enforce remains unavailable.

## Findings → fixes → killing regressions

Paths below are relative to `enclave-go/internal/shadowcoord` unless qualified.
The five survivor findings were coverage gaps: their existing production guards
were retained and are now killed by regressions. Both P2s also have serveOne tests.

| Finding | Cause-level fix (file:line) | Regression that fails without it |
|---|---|---|
| P2 partial denial identity | `coordinator.go:624` preserves the independently known key for matching partial workspace metadata; conflicts require re-confirmation. | TestReviewR2PartialScopeMustPreserveKnownKey; TestConflictAndRequestOnlyVerdicts; TestReviewR2PartialKeyScopeThroughHandler |
| P2 unknown invalid credentials | `coordinator.go:636` classifies before coverage invalidation; unresolved key-invalid and request-only verdicts change no health. | TestReviewR2UnknownInvalidKeyDoesNotCloseOtherWorkspace; TestConflictAndRequestOnlyVerdicts; TestReviewR2InvalidCredentialClosesWarmCoverageThroughHandler |
| F1 infrastructure recovery | `recovery.go:19,67,88` tracks per-key/boot failures, clean probe span and post-failure grant; `trustedrouter/shadow.go:69` captures the request-start version. Full identity caches do not swallow boot probes (`coordinator.go:248`). | TestInfrastructureRecovery; TestRecoveryRequiresFreshEvidenceAndSpanningSuccesses; TestBootRecoveryCountsUncachedOrdinarySuccess |
| F1 scoped recovery | `recovery.go:32,100` records the latched epoch and receipt event, requires a higher verified epoch, and advances local snapshots monotonically. `speculation/shadow_refresh.go:6` permits authenticated health epoch changes while retaining other bindings. | TestEpochRecoveryScopes; TestHigherEpochCannotRepairOtherScope; TestGrantReceiptCannotRepairLaterLatch |
| F1 uncertain coverage / capacity fallback | `recovery.go:28` uses one bounded re-confirmation generation; `coordinator.go:301,485` orders refresh sends and checks per-identity confirmation. Capacity emits records and uses re-confirmation or the recoverable boot breaker. | TestUnresolvedDenialRequiresLaterSend; TestCapacityFallbackReconfirmation; TestInfrastructureCapacityBootRecovery; TestProductionRecoverySequence |
| F2 actual error contract | `trustedrouter/shadow.go:118` classifies authenticated types, including exact forbidden/billing_paused; `trustedrouter/client.go:1404` explicitly labels scope parsing proposed. README documents timing-only data and the prerequisite router/shared-fixture change. | TestLiteralAuthorizeErrorEnvelopes (all five literal cases, digest, status, type, Retry-After, typed timing, absent scope) |
| F3 identity truncation | `coordinator.go:250`, `recovery.go:137` emit bounded capacity records and evict expired policy/grant entries without active ownership or retained liability. | TestIdentityCapacityEvictionAndRecord |
| F4 seam depth / measurement | `input.go:7`, `coordinator.go:185`, `cmd/enclave/speculation.go:81` enforce depth ≤32 and 8,192 bytes before the second decode, yielding input_bound. Split decode/preparation benchmarks added. | TestInputDepthBound; BenchmarkShadowCostSplit; BenchmarkShadowDeepRequestAddedWork |
| Survivor: health revision | Existing invariant at `coordinator.go:619`; added a paused-evaluation regression. | TestReviewR2HealthArrivesDuringEvaluation |
| Survivors: workspace and fleet liability cleanup | Existing invariant at `coordinator.go:450`; assert all four retained counters across repeated cleanup. | TestReviewR2ReleaseRetainsEveryLiability |
| Survivor: final observer-fault revalidation | Existing invariant at `coordinator.go:554`; inject a fault after snapshot and before depletion. | TestReviewR2FaultArrivesDuringEvaluation |
| Survivor: cancellation hides denial | Existing distinction at `trustedrouter/shadow.go:228`; a concurrently canceled caller still records the real 402. | TestReviewR2ConcurrentCancellationDoesNotHideDenial |

## Recovery state table

| Scope | What closes it | What reopens it | What never reopens it |
|---|---|---|---|
| Workspace | Resolved credit, trust, abuse, payment, pause or workspace/ambiguous rate denial | Verified grant received after the latch with strictly higher workspace epoch | Time, volume, success callback, expiry, eviction, same epoch, key-only repair |
| Key | Resolved invalid/revoked/expired key, key budget or explicit key-rate denial | Verified grant received after the latch with strictly higher key epoch | Time/window reset, volume, old success, expiry, same epoch, workspace-only repair |
| Key infrastructure | Retryable 5xx/timeout/transport failure | Three clean ordinary successes for this key whose first/last span ≥30s after the latest failure, plus a verified grant received after failure | Another key's successes, old callbacks, time alone, pre-failure grant |
| Boot infrastructure | Unscoped infrastructure failure or bounded key-breaker overflow | Same three-success/30s rule on this boot plus a post-failure verified grant | Time alone, old callbacks, pre-failure grant |
| Uncertain coverage | Unbound authenticated business denial, conflicting binding, or scope capacity overflow | Each identity's verified grant from a refresh **sent after** the denial | An already-in-flight refresh, ordinary success, time alone |
| No health change | Unresolvable invalid credential; request-only other 4xx | No recovery needed | These responses cannot latch an unrelated workspace |

The epoch-bearing shadow grant attests the issuer's repair/history/limiter checks;
the enclave does not infer those checks from local time or traffic. The original
VerifyGrant exact-binding API and both wire fixtures remain unchanged. Refresh uses
a separate verifier permitting signed health-epoch changes only. Health snapshots
and bindings never regress. A recovered key cannot reopen a workspace latch.

Request starts, refresh sends, receipts and denials use one mutex-ordered event
sequence, including when fake-clock readings are equal. Calls begun before a
failure cannot count as clean probes. Three successes must span 30 seconds between
the first and last success, not merely be followed by a 30-second timer. Each new
failure resets the probe/grant requirements. A grant first received before a newer
failure cannot repair it even if verification finishes later.

Unresolved business denials invalidate eligibility by generation without storing
unknown credential identities. Only a refresh sent after that denial can confirm
each identity again. Records count invalidations and capacity loss within the
existing 100-record/second and 512-queued-record bounds; dropped counts stay visible.
Expired entries are evictable only without retained liability or active ownership.
Unknown retained exposure has no local expiry; health recovery never refunds it.

## Mutation table

All **56/56**: green baseline → named assertion failure → green restoration.
The harness only edits disposable copies. Compilation failures do not count.
An initial unknown-invalid mutation survived because its test refreshed before
checking; the regression now also checks health immediately after denial. The full
final harness below passed with that strengthened assertion.

| Mutation | Named failing test | Baseline / mutant / restored |
|---|---|---|
| decision-after-authorize | `TestShadowSelfQualificationPredecisionBeforeNetwork` | green / RED / green |
| predecision-before-credential-guard | `TestShadowCredentialBackoffOrderingCounters` | green / RED / green |
| five-second-cache-expiry-reopens-health | `TestConcurrentRenewalDenyAndNoTimerRecovery` | green / RED / green |
| extra-provider-call | `TestShadowPhysicalMoneyOutputDifferential` | green / RED / green |
| sum-a-p-as-measured-overlap | `TestSerialTimingAndDeniedEvidence` | green / RED / green |
| guessed-denied-p-as-measured | `TestSerialTimingAndDeniedEvidence` | green / RED / green |
| prompt-field-in-telemetry | `TestSuppressionJoinsAndTelemetryAllowlist` | green / RED / green |
| renew-deadline-at-receipt | `TestLateGrantCannotGainReceiptTTL` | green / RED / green |
| accept-enforce | `TestMode` | green / RED / green |
| unknown-miss-as-malformed-error | `TestUnknownMissTyping` | green / RED / green |
| observer-panic-escapes | `TestReviewObserverPanicPreservesOrdinarySuccess` | green / RED / green |
| refresh-worker-panic-escapes | `TestRefreshPanicFailsClosedAndCountsLoss` | green / RED / green |
| forget-original-grant-receipt | `TestReviewReplayAfterMissCannotRenewMonotonicDeadline` | green / RED / green |
| unbounded-enclave-concurrency | `TestReviewEnclaveUnresolvedCapacity` | green / RED / green |
| unbounded-simulated-memory | `TestSimulatedMemoryAndRelease` | green / RED / green |
| finish-leaks-ownership | `TestReviewHandlerEarlyCredentialReturnLeaksSlot` | green / RED / green |
| unresolved-denial-ignored | `TestReviewUnresolvedWorkspaceDenialInvalidatesCoverage` | green / RED / green |
| resolved-scope-discarded | `TestAuthenticatedErrorScopeCarriedToObserver` | green / RED / green |
| caller-cancellation-poisons-health | `TestReviewCancellationNotInfrastructureFailure` | green / RED / green |
| eager-off-mode-regexp | `TestOffModePackageInitAllocations` | green / RED / green |
| duplicate-response-identity | `TestReviewWireAdditionalBounds` | green / RED / green |
| suppress-retry-health | `TestShadowRetryTimingAndByteParity` | green / RED / green |
| fallback-measured-as-first-route | `TestFallbackIsNotProposedRoute` | green / RED / green |
| decoder-size-guard-removed | `TestReviewWireAdditionalBounds` | green / RED / green |
| refresh-signer-signs-ordinary | `TestShadowBootOnlyHeaderParity` | green / RED / green |
| evaluate-under-coordinator-lock | `Test64PredecisionsDoNotHoldLockDuringEvaluation` | green / RED / green |
| unchecked-route-claim | `TestVerifiedTierCeilingAndClaimShapes` | green / RED / green |
| skip-tier2-ceiling | `TestVerifiedTierCeilingAndClaimShapes` | green / RED / green |
| decode-before-input-length-check | `TestInputLengthRejectsBeforeDecode` | green / RED / green |
| uncapped-record-rate | `TestRecordRateAndVisibleLoss` | green / RED / green |
| mixed-module-imports | `TestShadowModuleImportGroups` | green / RED / green |
| identity-index-change-not-revalidated | `TestSnapshotRevalidatesNewLookupAmbiguity` | green / RED / green |
| unbounded-authenticated-denial-scopes | `TestAuthenticatedDenialScopeMemoryBound` | green / RED / green |
| internal-timeout-as-caller-cancellation | `TestShadowInternalDeadlineClosesHealth` | green / RED / green |
| partial-scope-erases-key | `TestReviewR2PartialScopeMustPreserveKnownKey` | green / RED / green |
| unknown-invalid-closes-boot | `TestReviewR2UnknownInvalidKeyDoesNotCloseOtherWorkspace` | green / RED / green |
| no-health-revision | `TestReviewR2HealthArrivesDuringEvaluation` | green / RED / green |
| release-workspace-liability | `TestReviewR2ReleaseRetainsEveryLiability` | green / RED / green |
| release-fleet-liability | `TestReviewR2ReleaseRetainsEveryLiability` | green / RED / green |
| skip-final-fault-revalidation | `TestReviewR2FaultArrivesDuringEvaluation` | green / RED / green |
| infra-never-recovers | `TestInfrastructureRecovery` | green / RED / green |
| same-epoch-repairs-workspace | `TestEpochRecoveryScopes` | green / RED / green |
| same-epoch-repairs-key | `TestEpochRecoveryScopes` | green / RED / green |
| stale-send-reconfirms | `TestUnresolvedDenialRequiresLaterSend` | green / RED / green |
| other-key-repairs-infra | `TestInfrastructureRecovery` | green / RED / green |
| infra-grant-not-required | `TestInfrastructureRecovery` | green / RED / green |
| infra-span-not-required | `TestRecoveryRequiresFreshEvidenceAndSpanningSuccesses` | green / RED / green |
| old-success-repairs-infra | `TestInfrastructureRecovery` | green / RED / green |
| capacity-permanent-boot | `TestCapacityFallbackReconfirmation` | green / RED / green |
| silent-identity-capacity | `TestIdentityCapacityEvictionAndRecord` | green / RED / green |
| no-expired-identity-eviction | `TestIdentityCapacityEvictionAndRecord` | green / RED / green |
| no-depth-cap | `TestInputDepthBound` | green / RED / green |
| conflicting-binding-accepted | `TestConflictAndRequestOnlyVerdicts` | green / RED / green |
| cancel-hides-real-denial | `TestReviewR2ConcurrentCancellationDoesNotHideDenial` | green / RED / green |
| billing-paused-unclassified | `TestLiteralAuthorizeErrorEnvelopes` | green / RED / green |
| identity-capacity-swallows-boot-probes | `TestBootRecoveryCountsUncachedOrdinarySuccess` | green / RED / green |

Final logs: `/var/folders/th/1hvz8frd3p551wg24zytym940000gn/T/quill-e4-mutation-results-jhozihhn`; summary: `/tmp/e4-r3-mutations-final.log`.

## Shadow request cost

Darwin/arm64, Apple M2, Go 1.24.13, three samples. These are local request-seam
samples, not hard latency guarantees or provider/network timings. Host load differs
from the prior round; unchanged shallow-path allocations remain substantial.
The depth cap addresses the recursive-input cost; it does not claim a general
optimization of payload preparation. The near-budget input has 7,900 content bytes.

| Work | Time/request (min–max) | Bytes/request (max) | Allocations/request |
|---|---:|---:|---:|
| Second decode + depth/length checks | 49.882–64.620 µs | 40,729 | 47 |
| Payload preparation alone | 75.732–77.285 µs | 24,305 | 844 |
| Eligibility evaluation (includes payload preparation) | 112.590–117.150 µs | 48,769 | 1,689 |
| Near-budget full seam | 253.520–258.457 µs | 143,176 | 2,647 |
| Small Chat full seam | 135.273–136.070 µs | 80,487 | 2,643 |
| Deep unknown field, full seam rejection | 1.431–1.442 µs | 704 | 11 |
| Deep containers, parse rejection alone | 0.063–0.063 µs | 0 | 0 |
| 1 MiB input, full seam rejection | 1.173–1.173 µs | 704 | 11 |
| Many shallow containers, second decode | 206.956–207.882 µs | 320,619 | 2,761 |

Full seam includes parsing, predecision, authorization start/end and Finish;
asynchronous serialization and provider streaming are excluded. Deep input takes
InputMiss before preparation, preserving ordinary traffic. The split rows are
independent samples and are not additive (eligibility includes preparation).
Depth >32 is rejected without allocation; braces inside escaped strings are ignored.

```sh
GOTOOLCHAIN=go1.24.13 GOFLAGS=-mod=mod GOCACHE=/tmp/quill-e4-go-cache \
  go test -tags cloud_gcp,llm_multi -run '^$' \
  -bench 'BenchmarkShadow(CostSplit|RequestAddedWork|DeepRequestAddedWork|ParseWorstCase)' \
  -benchmem -count=3 ./internal/shadowcoord
```

Raw samples: `/tmp/e4-r3-bench.log`.

## Gates and preservation evidence

All **26/26**: gofmt plus five tag sets × build, vet, pinned lint, test and race.
Environment and exact command pattern (from `enclave-go`):

```sh
export GOTOOLCHAIN=go1.24.13 GOFLAGS=-mod=mod
export PATH=/Users/jperla/josh/repos/tr/quill-router/.venv/bin:$PATH
export GOCACHE=/tmp/quill-e4-go-cache GOLANGCI_LINT_CACHE=/tmp/e4-r3-lintcache
gofmt -l .
# For each tag set below:
go build -tags "$tags" ./...
go vet -tags "$tags" ./...
go run github.com/golangci/golangci-lint/cmd/golangci-lint@v1.64.8 run --allow-serial-runners --build-tags "$tags"
go test -count=1 -tags "$tags" ./...
go test -race -count=1 -tags "$tags" ./...
```

| Tags | Build | Vet | Lint 1.64.8 | Test | Race |
|---|---|---|---|---|---|
| cloud_aws,llm_bedrock | PASS | PASS | PASS | PASS | PASS |
| cloud_aws,llm_multi | PASS | PASS | PASS | PASS | PASS |
| cloud_azure,llm_multi | PASS | PASS | PASS | PASS | PASS |
| cloud_gcp,llm_vertex | PASS | PASS | PASS | PASS | PASS |
| cloud_gcp,llm_multi | PASS | PASS | PASS | PASS | PASS |

Exact final commands/exits/log paths: `/tmp/e4-r3-gates.json`.
`gofmt -l` has no output; `git diff --check` is clean. Production code imports no
new test helper. All 89 golden files are byte-identical to the prior pinned manifest
and HEAD blobs. The fixtures are unchanged:

* `shadow-refresh-wire.json`: `ad8d4161013cdf442aa4f221abf06c418ee15353d646487ac95ac8419d8aef39`
* `authorize-error-envelopes.json`: `a2f388da8afd619793fedfb78013dcdf61843ae0a9b5dca936647ca8582746d4`

Off-mode uninstrumented init evidence:

```sh
go test -c -tags cloud_gcp,llm_multi -o /tmp/e4-r3-init.test ./internal/shadowcoord
GODEBUG=inittrace=1 QUILL_SPECULATIVE_PROVIDER_MODE=off /tmp/e4-r3-init.test -test.run='^$'
```

`/tmp/e4-r3-init.log` contains no init entries for shadowcoord or shadowobserve:
zero initialization bytes/allocations from either package. The off-mode subprocess
regression passes. This excludes instrumentation allocations and does not claim
zero CPU cost for existing off-mode nil checks.

Coverage command:

```sh
go test -count=1 -tags cloud_gcp,llm_multi \
  -coverpkg=./internal/shadowcoord,./internal/shadowobserve,./internal/trustedrouter,./internal/speculation,./cmd/enclave \
  -coverprofile=/tmp/e4-r3-cover.out \
  ./internal/shadowcoord ./internal/shadowobserve ./internal/trustedrouter ./internal/speculation ./cmd/enclave
python3 internal/shadowcoord/testdata/coverage.py /tmp/e4-r3-cover.out
```

Every new file is ≥90% after merging duplicate instrumented blocks:

```text
cmd/enclave/speculation.go: 38/42 = 90.5%
internal/shadowcoord/coordinator.go: 368/397 = 92.7%
internal/shadowcoord/input.go: 18/18 = 100.0%
internal/shadowcoord/recovery.go: 97/97 = 100.0%
internal/shadowobserve/boundary.go: 9/9 = 100.0%
internal/shadowobserve/execution.go: 139/140 = 99.3%
internal/shadowobserve/mode.go: 5/5 = 100.0%
internal/shadowobserve/timing.go: 27/27 = 100.0%
internal/shadowobserve/wire.go: 51/52 = 98.1%
internal/speculation/shadow_refresh.go: 12/12 = 100.0%
internal/trustedrouter/shadow.go: 122/123 = 99.2%
merged=/tmp/e4-r3-cover-merged.out
```

## git status --short

```text
 M enclave-go/cmd/enclave/speculation.go
 M enclave-go/internal/shadowcoord/README.md
 M enclave-go/internal/shadowcoord/coordinator.go
 M enclave-go/internal/shadowcoord/round2_test.go
 M enclave-go/internal/shadowcoord/testdata/coverage.py
 M enclave-go/internal/shadowcoord/testdata/mutate.py
 M enclave-go/internal/trustedrouter/client.go
 M enclave-go/internal/trustedrouter/shadow.go
 M enclave-go/internal/trustedrouter/shadow_test.go
?? enclave-go/cmd/enclave/review_r2_test.go
?? enclave-go/internal/shadowcoord/input.go
?? enclave-go/internal/shadowcoord/recovery.go
?? enclave-go/internal/shadowcoord/recovery_test.go
?? enclave-go/internal/shadowcoord/review_r2_test.go
?? enclave-go/internal/shadowcoord/round3-verification.md
?? enclave-go/internal/speculation/shadow_refresh.go
?? enclave-go/internal/speculation/testdata/speculation_v1/authorize-error-envelopes.json
?? enclave-go/internal/trustedrouter/error_fixture_test.go
?? enclave-go/internal/trustedrouter/review_r2_test.go
```
