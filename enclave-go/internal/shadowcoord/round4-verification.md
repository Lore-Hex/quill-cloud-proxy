# PR 4 round 4 verification

Only the three recovery defects and three regression gaps from review 3 are in
scope. Production edits are confined to `coordinator.go` and `recovery.go`; no
configuration, wire, request-path, billing, or provider behavior was added. The
watermark's conservative replay rejection is the required journal fix, not a new
recovery policy. Changes remain uncommitted; no git writes were performed.

## Finding → fix → failing test

| Finding | Cause-level fix | Test killed by reverting/removing the fix |
|---|---|---|
| Pre-denial receipt replay clears workspace/key latch | `coordinator.go:362,417`: store the first receipt event with its original wall/monotonic receipt and use that event for recovery on every replay. | `TestReplayKeepsOriginalRecoveryOrder` (workspace and key) |
| Tracked-key failure leaves active boot recovery evidence | `recovery.go:56`: every infrastructure failure resets an active boot breaker before the scoped update. | `TestBootFailureRestartsRecovery` |
| Healthy refresh permanently fills receipt journal | `coordinator.go:400,425`: retire records past their original monotonic start deadline; bound records at 256. | `TestHealthyReceiptJournal24Hours` |
| Retirement must not renew old deadlines after rollback | `coordinator.go:402`: reject unseen signed issuance times at or below the inclusive retired watermark. | `TestRetiredReceiptRejectsClockRollback` |
| Eviction deletes negative health mutant survives | Existing preservation in `recovery.go:146` is unchanged; add eviction/relearning assertions for both scopes. | `TestEvictionPreservesNegativeHealth` |
| New failure keeps prior probe window mutant survives | Existing fresh breaker construction in `recovery.go:55` is unchanged; assert count, first/last and grant evidence reset between probes. | `TestKeyFailureRestartsProbeWindow` |
| Lower grant regresses workspace epoch mutant survives | Existing monotonic epoch update in `recovery.go:120` is unchanged; assert epoch and eligibility after a lower verified grant. | `TestLowerGrantCannotRegressWorkspaceEpoch` |

Before the fixes, the new replay tests admitted both scopes, boot reset retained
2 probes plus grant evidence, and the healthy journal hit capacity at 46m56s.
The rollback test also failed because expired fingerprints were never retired.
Raw reproduction output: `/tmp/e4-r4-before-fixes.log`.

The soak refreshes distinct valid signed grants every 11 seconds for 24h0m5s
(7,855 refreshes), with independently valid 25-hour policy/route evidence and no
permit consumption until its final eligibility assertion. The journal peaks at
3 records and the identity remains eligible. The rollback regression retains
monotonic time, moves wall time backwards, and verifies that both an old
fingerprint strictly below the watermark and new signatures at/below it are
`grant-replay` misses. A newer issuance restores eligibility.

The watermark is constant-size and monotonic. Retirement uses only the original
monotonic deadline. The signed `iat` orders the retired issuance range, so an old
fingerprint cannot be admitted again after its hash is deleted. Still-live
fingerprints retain their original event/deadline, even below the watermark.
Previously unseen, out-of-order grants in the retired range are conservatively
rejected. Eviction still requires expired independent policy, no liability and no
active owner; relearning alone supplies no new independent policy.

Three existing recovery fixtures now issue a distinct post-failure grant instead
of replaying one received before the failure. The existing capacity test seeds
live receipt records rather than expired zero-value records. No production
refactor or wider change was necessary.

## Recovery state table

| Scope | What closes it | What reopens it | What never reopens it |
|---|---|---|---|
| Workspace | Resolved credit, trust, abuse, payment, pause or workspace/ambiguous rate denial | Verified grant first received after the latch with strictly higher workspace epoch | Time, volume, success callback, expiry, eviction, same epoch, key-only repair |
| Key | Resolved invalid/revoked/expired key, key budget or explicit key-rate denial | Verified grant first received after the latch with strictly higher key epoch | Time/window reset, volume, old success, expiry, same epoch, workspace-only repair |
| Key infrastructure | Retryable 5xx/timeout/transport failure | Three clean ordinary successes for this key whose first/last span ≥30s after the latest failure, plus a verified grant first received after failure | Another key's successes, old callbacks, time alone, pre-failure grant |
| Boot infrastructure | Unscoped infrastructure failure or bounded key-breaker overflow; every further infrastructure failure restarts it while active | Same three-success/30s rule on this boot after the latest failure plus a grant first received after it | Time alone, old callbacks, pre-failure grant replays or probe evidence |
| Uncertain coverage | Unbound authenticated business denial, conflicting binding, or scope capacity overflow | Each identity's verified grant from a refresh **sent after** the denial | An already-in-flight refresh, ordinary success, time alone |
| No health change | Unresolvable invalid credential; request-only other 4xx | No recovery needed | These responses cannot latch an unrelated workspace |

The issuer still certifies actual workspace/key state repair. The coordinator
simulates these rules and does not introduce a durable fence or real rights.

## Mutation table

The harness mutates a disposable module copy and requires a green named baseline,
a compiled mutant's named assertion failure, then a green restored baseline.
It contains the original 56 semantic mutants plus 7: one for each of the three
fixes, the three reported survivors, and the retirement watermark safeguard.

The original `forget-original-grant-receipt` injection now deletes the fingerprint
as well as treating it as unseen. Merely bypassing the lookup leaves the original
record available to the new retirement guard, which safely rejects the replay;
that old partial injection no longer models forgetting the receipt journal.

| Mutant | Named failing test | Baseline / mutant / restored |
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
| replay-renews-recovery-order | `TestReplayKeepsOriginalRecoveryOrder` | green / RED / green |
| key-failure-preserves-boot-window | `TestBootFailureRestartsRecovery` | green / RED / green |
| receipt-journal-never-retires | `TestHealthyReceiptJournal24Hours` | green / RED / green |
| retired-receipt-readmitted | `TestRetiredReceiptRejectsClockRollback` | green / RED / green |
| eviction-deletes-negative-health | `TestEvictionPreservesNegativeHealth` | green / RED / green |
| new-failure-retains-probe-window | `TestKeyFailureRestartsProbeWindow` | green / RED / green |
| lower-grant-regresses-workspace-epoch | `TestLowerGrantCannotRegressWorkspaceEpoch` | green / RED / green |

All **63/63** mutants fail by their named tests, with green baseline/restoration.
Raw results: `/tmp/e4-r4-mutations-final.log`.
Detailed logs: `/var/folders/th/1hvz8frd3p551wg24zytym940000gn/T/quill-e4-mutation-results-2w0fx0ws`.

## Gates and preservation

All **26/26** pass: clean gofmt plus five tag sets × build, vet, pinned lint,
uncached tests and uncached race tests. Exact commands, executed from `enclave-go`:

```sh
export GOTOOLCHAIN=go1.24.13 GOFLAGS=-mod=mod
export PATH=/Users/jperla/josh/repos/tr/quill-router/.venv/bin:$PATH
export GOCACHE=/tmp/quill-e4-go-cache GOLANGCI_LINT_CACHE=/tmp/e4-r4-lintcache
gofmt -l .
# Each tag set in the table below:
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

Every command's exit code and log path: `/tmp/e4-r4-gates.json`.
Targeted normal and race logs: `/tmp/e4-r4-targeted.log`,
`/tmp/e4-r4-regressions-race.log`. `git diff --check` is clean, and production
shadow code imports no test helpers. The unchanged ordinary header/body,
provider/billing/output differential and Stage C/D regressions pass in full gates.

All **89/89** golden files match both `/tmp/e4-golden-pins.txt` and HEAD blob bytes.
Both wire fixtures match HEAD and retain their exact hashes:

* `shadow-refresh-wire.json`: `ad8d4161013cdf442aa4f221abf06c418ee15353d646487ac95ac8419d8aef39`
* `authorize-error-envelopes.json`: `a2f388da8afd619793fedfb78013dcdf61843ae0a9b5dca936647ca8582746d4`

Off-mode initialization proof:

```sh
go test -c -tags cloud_gcp,llm_multi -o /tmp/e4-r4-init.test ./internal/shadowcoord
GODEBUG=inittrace=1 QUILL_SPECULATIVE_PROVIDER_MODE=off /tmp/e4-r4-init.test -test.run='^TestOffModePackageInitAllocations$'
```

`/tmp/e4-r4-init.log`: PASS, no `shadowcoord` or `shadowobserve` init entries;
zero package-init bytes/allocations from either. This is an uninstrumented binary.

Coverage gate:

```sh
go test -count=1 -tags cloud_gcp,llm_multi \
  -coverpkg=./internal/shadowcoord,./internal/shadowobserve,./internal/trustedrouter,./internal/speculation,./cmd/enclave \
  -coverprofile=/tmp/e4-r4-cover.out \
  ./internal/shadowcoord ./internal/shadowobserve ./internal/trustedrouter ./internal/speculation ./cmd/enclave
python3 internal/shadowcoord/testdata/coverage.py /tmp/e4-r4-cover.out
```

Every new production file is ≥90% after merging duplicate instrumented blocks:

```text
cmd/enclave/speculation.go: 38/42 = 90.5%
internal/shadowcoord/coordinator.go: 387/411 = 94.2%
internal/shadowcoord/input.go: 18/18 = 100.0%
internal/shadowcoord/recovery.go: 99/99 = 100.0%
internal/shadowobserve/boundary.go: 9/9 = 100.0%
internal/shadowobserve/execution.go: 139/140 = 99.3%
internal/shadowobserve/mode.go: 5/5 = 100.0%
internal/shadowobserve/timing.go: 27/27 = 100.0%
internal/shadowobserve/wire.go: 51/52 = 98.1%
internal/speculation/shadow_refresh.go: 12/12 = 100.0%
internal/trustedrouter/shadow.go: 122/123 = 99.2%
merged=/tmp/e4-r4-cover-merged.out
```

## Git status

Changes left uncommitted; `git status --short`:

```text
 M enclave-go/internal/shadowcoord/README.md
 M enclave-go/internal/shadowcoord/coordinator.go
 M enclave-go/internal/shadowcoord/recovery.go
 M enclave-go/internal/shadowcoord/recovery_test.go
 M enclave-go/internal/shadowcoord/round2_test.go
 M enclave-go/internal/shadowcoord/testdata/mutate.py
?? enclave-go/internal/shadowcoord/round4-verification.md
?? enclave-go/internal/shadowcoord/round4_test.go
```
