# PR 4 round-2 verification

Worktree `/Users/jperla/josh/repos/tr/wt/spec-e4`, base HEAD `3d914826`.
No git write, deployment, live provider invocation or external message was performed.
Changes are uncommitted. Mode stays off by default; enforce remains unavailable.

## Findings and regressions

| Finding | Fix location | Behavior | Failing-without-fix test |
|---|---|---|---|
| 1 / P1 observer and worker isolation | `internal/trustedrouter/shadow.go:195`; `internal/shadowobserve/boundary.go:17`; `internal/shadowcoord/coordinator.go:271` | Narrow recovery, sticky fail-closed eligibility, counted faults; ordinary errors/context and Goexit preserved. | TestReviewObserverPanicPreservesOrdinarySuccess; TestEveryObserverCallbackIsIsolated; TestRefreshPanicFailsClosedAndCountsLoss; TestBoundaryOnlyRecoversCallbackPanics |
| 2 / P2 original deadlines | `internal/shadowcoord/coordinator.go:301` | SHA-256 receipt journal is independent of cache invalidation; retain original monotonic grant/history deadlines. | TestReviewReplayAfterMissCannotRenewMonotonicDeadline; TestGrantReceiptJournalBound |
| 3 / P2 capacity | `internal/shadowcoord/coordinator.go:522` | Atomically reserve one of 32 slots, 128 KiB simulated memory, workspace ownership, ordinal and money. | TestReviewEnclaveUnresolvedCapacity; TestSimulatedMemoryAndRelease |
| 4 / P2 exit cleanup | `internal/shadowobserve/execution.go:218`; `internal/shadowcoord/coordinator.go:410` | Idempotent cleanup on Finish and EndAuthorize; retain hypothetical liability. Unlock/release even if a clock callback fails. | TestReviewHandlerEarlyCredentialReturnLeaksSlot; TestReviewFinishReleasesUnstartedAdmission; TestEndAuthorizeClockFaultUnlocksAndReleases |
| 5 / P2 unresolved denial | `internal/shadowcoord/coordinator.go:568`; `internal/trustedrouter/client.go:1404` | Carry authenticated scope; otherwise close uncertain coverage without learning a key/workspace assignment. Parse optional data independently of ordinary errors. | TestReviewUnresolvedWorkspaceDenialInvalidatesCoverage; TestAuthenticatedErrorScopeCarriedToObserver; TestResolvedDenialScopeAndUnknownCoverage; TestMalformedShadowScopePreservesOrdinaryError; TestAuthenticatedDenialScopeMemoryBound |
| 6 / P2 cancellation | `internal/trustedrouter/shadow.go:209` | Caller cancellation/deadline errors produce no infrastructure verdict; internal retry/transport timeouts still close health. Original ordinary errors propagate. | TestReviewCancellationNotInfrastructureFailure; TestShadowInternalDeadlineClosesHealth |
| 7 / P3 off init | `internal/shadowobserve/wire.go:20` | Bounded byte validators replace eager regex compilation. | TestOffModePackageInitAllocations; TestByteValidators |
| 8a duplicate identities | `internal/shadowobserve/wire.go:125` | Add a same-length two-identity duplicate response regression. | TestReviewWireAdditionalBounds |
| 8b retry health | `internal/trustedrouter/shadow.go:149` | Assert physical retry failure closes health even when the logical call succeeds. | TestShadowRetryTimingAndByteParity |
| 8c fallback timing | `internal/shadowobserve/execution.go:178` | Mark fallback provider completion successful, isolating the first-attempt predicate. | TestFallbackIsNotProposedRoute |
| 8d response size | `internal/shadowobserve/wire.go:95` | Use oversized valid JSON, so JSON invalidity cannot kill the size mutant. | TestReviewWireAdditionalBounds |
| 9 header parity | `internal/trustedrouter/shadow.go:184`; `cmd/enclave/main.go:501` | Refresh-only signer; ordinary boot header remains absent with Stage A/D disabled. Existing Stage D body/signature differential retained. | TestShadowBootOnlyHeaderParity; TestShadowOffBodyAndSignatureParity; TestShadowBootOnlyFrozenWire |
| A mutex contention | `internal/shadowcoord/coordinator.go:172`; `internal/shadowcoord/coordinator.go:464` | O(1) lookup index and scalar snapshot; evaluate outside mutex, revalidate revision/deadlines/health before atomic depletion. Refresh crypto/claims decoding also runs outside request mutex. Index ambiguity increments revision. | Test64PredecisionsDoNotHoldLockDuringEvaluation; TestSnapshotRevalidatesNewLookupAmbiguity |
| B claim shape and tier | `internal/shadowcoord/coordinator.go:627`; `internal/shadowcoord/coordinator.go:640` | Checked route/claim access; exact integral tier parsing, including VerifyGrant int64; fixed tier-2 ceiling. | TestVerifiedTierCeilingAndClaimShapes |
| C input bound | `internal/shadowcoord/coordinator.go:177`; `internal/speculation/payload_budget.go:10` | Share the certified 8,192-byte maximum with PR 2b; reject oversized raw input before JSON decode, report input_bound. | TestInputLengthRejectsBeforeDecode |
| D log rate | `internal/shadowcoord/coordinator.go:195` | 100 records per one-second monotonic window, 512 queued records; cumulative rate/queue/fault loss in subsequent records. | TestRecordRateAndVisibleLoss |
| E import groups | `cmd/enclave/main.go:48` | Move module imports out of standard-library groups in main, http_io, provider_stream, speculation_test and coordinator_test. | TestShadowModuleImportGroups |

The four surviving mutants required stronger tests; their existing production guards
were already correct. Unresolved denial closes coverage, not a fabricated durable
workspace assignment. The original predecision remains immutable after an observer
fault; subsequent eligibility is closed. Recovery boundaries wrap only shadow code,
never the ordinary handler, network result or cancellation path. Runtime Goexit is
explicitly tested to leave its goroutine. No panic content is logged.

## Mutation results

The runner edits only a disposable source copy. Each row requires a green named
baseline, a failing named assertion (compilation failure does not count), then a
green restored baseline. The import-group mutant is a style regression; all others
are behavioral mutants.

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

Completed: 34/34. Log: `/tmp/e4-r2-mutations-verified.log`.

## Off-mode startup evidence

```
GOTOOLCHAIN=go1.24.13 GOFLAGS=-mod=mod GOCACHE=/tmp/quill-e4-go-cache \
  go test -c -tags cloud_gcp,llm_multi -o /tmp/e4-r2-init.test ./internal/shadowcoord
GODEBUG=inittrace=1 QUILL_SPECULATIVE_PROVIDER_MODE=off \
  /tmp/e4-r2-init.test -test.run='^$' > /tmp/e4-r2-init.log 2>&1
rg 'init .*internal/(shadowobserve|shadowcoord) ' /tmp/e4-r2-init.log
```

The last command has no matches: neither new package has runtime initialization,
hence neither adds init bytes or allocations. The uninstrumented subprocess test
also passes. Inserting the old eager regex kills it. Coverage instrumentation adds
its own init counters, so the init assertion explicitly skips instrumented binaries;
coverage is measured separately. This does not claim zero ordinary off-mode CPU:
existing nil checks, context lookups and enlarged structs remain as documented in
round 1. `initializeSpeculation` returns off before config/coordinator/worker creation.

## Cost and bounds

Benchmarks run on Darwin/arm64, Apple M2, Go 1.24.13, three samples. These are measured
request-seam costs, not end-to-end network/provider latency or hard timing guarantees.
Shared-host gate activity makes the maximum observed sample conservative/noisy.
The parse benchmark includes maximum-budget strings, many small containers, and
4,090-deep arrays. The request benchmarks include valid Chat input with a deeply nested unknown field
(the highest measured added cost), as well as small/near-budget/oversized inputs.
They include ParseRequest, predecision, authorize
start/end and Finish; asynchronous serialization and streamed provider content are
not part of these request-seam measurements.

| Benchmark | Max observed time/request | Max B/request | Allocations/request |
|---|---:|---:|---:|
| `BenchmarkShadowParseWorstCase/max-budget-8` | 84,952.000 ns | 39,689 | 16 |
| `BenchmarkShadowParseWorstCase/many-containers-8` | 1,008,648.000 ns | 320,617 | 2,761 |
| `BenchmarkShadowParseWorstCase/deep-containers-8` | 1,253,099.000 ns | 451,588 | 8,225 |
| `BenchmarkShadowParseWorstCase/oversized-1MiB-8` | 9.988 ns | 0 | 0 |
| `Benchmark64Predecisions-8` | 2,580.000 ns | 785 | 8 |
| `BenchmarkShadowRequestAddedWork/128-8` | 478,644.000 ns | 80,541 | 2,643 |
| `BenchmarkShadowRequestAddedWork/7900-8` | 819,490.000 ns | 143,847 | 2,647 |
| `BenchmarkShadowRequestAddedWork/1048576-8` | 3,446.000 ns | 704 | 11 |
| `BenchmarkShadowDeepRequestAddedWork-8` | 3,606,396.000 ns | 498,286 | 9,756 |

`Test64PredecisionsDoNotHoldLockDuringEvaluation` parks one predecision at evaluation
and requires the other 63 to finish before releasing it. Its mutex-around-evaluation
mutant fails. The benchmark's SetParallelism(64) means 64 × GOMAXPROCS goroutines;
the deterministic test is the exact 64-request contention evidence.

Each ordinary observed request proposes two records (predecision, execution);
physical retries are embedded in the execution record, bounded at 16 samples.
A backoff hit proposes one suppression record. Refresh proposes at most 64 misses
per tick, at least ten seconds apart. All share the 100-record/second window cap
(at most 200 records across a window boundary), with a 512-record queue. Later
records report cumulative `dropped_observations`, including queue/rate/fault loss.

Simulated capacity is at most 32 unresolved invocations per enclave, each reserving
64 KiB spool plus 64 KiB frame/parser state, against an independent 8 MiB limit.
These are hypothetical capacity reservations, not measurements of an enforce spool.
Finish releases capacity idempotently while money remains retained. The receipt
journal keeps at most 256 fingerprints per identity; saturation is a typed miss.

## Verification gates

Environment for every command:

```sh
export GOTOOLCHAIN=go1.24.13 GOFLAGS=-mod=mod
export PATH=/Users/jperla/josh/repos/tr/quill-router/.venv/bin:$PATH
export GOCACHE=/tmp/quill-e4-go-cache GOLANGCI_LINT_CACHE=/tmp/e4-r2-lintcache
```

For each tag set in the table:

```sh
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

Detailed command lines and logs: `/tmp/e4-r2-verified-gates.json`.

```
go test -count=1 -tags cloud_gcp,llm_multi \
  -coverpkg=./internal/shadowcoord,./internal/shadowobserve,./internal/trustedrouter,./cmd/enclave \
  -coverprofile=/tmp/e4-r2-final-cover.out \
  ./internal/shadowcoord ./internal/shadowobserve ./internal/trustedrouter ./cmd/enclave
python internal/shadowcoord/testdata/coverage.py /tmp/e4-r2-final-cover.out
```

```text
cmd/enclave/speculation.go: 38/42 = 90.5%
internal/shadowcoord/coordinator.go: 349/369 = 94.6%
internal/shadowobserve/boundary.go: 9/9 = 100.0%
internal/shadowobserve/execution.go: 139/140 = 99.3%
internal/shadowobserve/mode.go: 5/5 = 100.0%
internal/shadowobserve/timing.go: 27/27 = 100.0%
internal/shadowobserve/wire.go: 51/52 = 98.1%
internal/trustedrouter/shadow.go: 111/113 = 98.2%
merged=/tmp/e4-r2-final-cover-merged.out
```

`gofmt -l` and `git diff --check` are clean. A production-source search for
`internal/(testutil|testhelper)|/testdata` has no matches.
All **89/89** pinned golden files match both the manifest and HEAD git blob bytes.
Manifest SHA-256:
`fe51959ba875b92105177676a830ca9a94a41fe7c7edf2f4fc92d1b6460891d9`.
The wire fixture is unchanged:
`ad8d4161013cdf442aa4f221abf06c418ee15353d646487ac95ac8419d8aef39`.

## Working-tree status

```text
 M enclave-go/cmd/enclave/http_io.go
 M enclave-go/cmd/enclave/main.go
 M enclave-go/cmd/enclave/provider_stream.go
 M enclave-go/cmd/enclave/speculation.go
 M enclave-go/cmd/enclave/speculation_test.go
 M enclave-go/internal/shadowcoord/README.md
 M enclave-go/internal/shadowcoord/coordinator.go
 M enclave-go/internal/shadowcoord/coordinator_test.go
 M enclave-go/internal/shadowcoord/testdata/mutate.py
 M enclave-go/internal/shadowcoord/timing_test.go
 M enclave-go/internal/shadowcoord/verification.md
 M enclave-go/internal/shadowobserve/execution.go
 M enclave-go/internal/shadowobserve/wire.go
 M enclave-go/internal/speculation/payload.go
 M enclave-go/internal/speculation/payload_budget.go
 M enclave-go/internal/trustedrouter/client.go
 M enclave-go/internal/trustedrouter/shadow.go
 M enclave-go/internal/trustedrouter/shadow_test.go
?? enclave-go/cmd/enclave/review_repro_test.go
?? enclave-go/internal/shadowcoord/review_capacity_test.go
?? enclave-go/internal/shadowcoord/review_repro_test.go
?? enclave-go/internal/shadowcoord/review_wire_test.go
?? enclave-go/internal/shadowcoord/round2-verification.md
?? enclave-go/internal/shadowcoord/round2_test.go
?? enclave-go/internal/shadowobserve/boundary.go
?? enclave-go/internal/shadowobserve/boundary_test.go
?? enclave-go/internal/trustedrouter/review_repro_test.go
```
