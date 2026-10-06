# PR 4 round-1 verification and handoff

Historical round-1 results. See [round2-verification.md](round2-verification.md) for
the request-changes fixes and current verification.

Worktree: `/Users/jperla/josh/repos/tr/wt/spec-e4`.
Base HEAD: `06e6ffef`. Changes are uncommitted; no git write command was used.
The pre-existing untracked refresh fixture is unchanged. Deployment remains off.
No provider service, deployment, external application, commit, push or PR was used.

## Files and seams

| Files | Change |
|---|---|
| `cmd/enclave/speculation.go`, `speculation_test.go` | Off-first initialization, independent trusted configuration, original caller provenance, positive eligible-grant handler differential, ordering/counters |
| `cmd/enclave/main.go` | Mode startup validation, independent boot signer, shadow bypass of Stage A, predecision immediately before ordinary authorize, separate suppression observation |
| `cmd/enclave/http_io.go` | Empty-header idempotency presence and client content observation after successful writes |
| `cmd/enclave/provider_stream.go` | Observe existing first physical route, provider content/end, distinguish fallback/retry; no new dispatch |
| `internal/bootstrap/bootstrap_gcp.go` | Independent mode validation; shadow does not read the retired Stage A issuer secret |
| `internal/trustedrouter/shadow.go`, `shadow_test.go` | Actual frozen boot-auth client; decode/attempt observers; bounded typed timing; authenticated error-type normalization |
| `internal/trustedrouter/client.go`, `spend_lease.go`, `authorization_retry.go`, `stage_c.go` | Nil observer hooks, final logical verdict, per-retry timing/health, skip legacy local admission |
| `internal/shadowcoord/coordinator.go`, `observation.go` | Grant/cache/worker, immutable decision, atomic hypothetical admission, scoped sticky health, bounded telemetry queue |
| `internal/shadowcoord/coordinator_test.go`, `timing_test.go` | Literal wire pins, fake clocks, concurrency, provenance, scope, schema and timing tests |
| `internal/shadowobserve/{mode,wire,timing,decision,execution,observer}.go` | Dependency-free mode/wire/timing/observation layer; prevents AWS and LLM test import cycles |
| `internal/shadowcoord/testdata/{mutate,coverage}.py` | Temporary-copy mutation runner and coverage union/threshold checker |
| `internal/shadowcoord/{README,verification}.md` | Contract, configuration/evidence limits, handoff and reproducible verification |
| `internal/speculation/robustness_test.go` | Retire the PR 2a “no production consumer” assertion; assert no production test-helper import instead |
| `internal/speculation/testdata/speculation_v1/shadow-refresh-wire.json` | Supplied before this task; preserved byte for byte |

Off returns at `cmd/enclave/speculation.go:16` before configuration decoding,
coordinator creation, refresh, observation queues or serialization.
`predecideSpeculation` also returns immediately when the client has no observer.
The new main seam is `cmd/enclave/main.go:1246`, after the credential/backoff and
parsing/cohort guards, immediately before `AuthorizeWithRoute`. No provider launch
was added. The common decode observer handles excluded routes too; retries keep
the same body, nonce and boot signature. Existing requesttiming code is unchanged.

PR 2b integration additions are named explicitly: decision-time history freshness;
conservative request/provider-policy and hidden-prefix applicability checks;
actual boot/local Stage D/region/cache-scope binding; independent evidence expiry and the fixed tier-2 $0.25 maximum;
atomic simulated ordinal/concurrency/retained-budget admission; normalization of
existing authenticated router key-error types. No v1 claim or fixture was changed.

## Miss taxonomy

Batch/per-item router misses retain `(HTTP status, bounded code)`, including every
frozen literal and unknown future codes. No refresh miss becomes an ordinary
request error. Malformed response, boot/transport unavailable, invalid/misbound grant and
stale policy are separate local misses. PR 2b's request/key/trust/health/deadline/
cost reasons remain intact. Additional local reasons are `history-stale`,
`identity-ambiguous`, `request-route-uncertain`, `payload-context-uncertain`,
`policy_stale`, `allocation-unknown`, `simulated-concurrency`,
`simulated-retained-budget`, `simulated-journal-capacity`, and
`simulated-permits-exhausted`.

Missing allocation/certification evidence intentionally produces misses. The
frozen refresh response supplies no independent allocation snapshot. No remote
capacity is guessed, and no source configuration enables a production cohort.
Sticky simulated health/retained liability do not recover on ordinary success,
refresh, billing-cache expiry or a local reboot counter reset. This is conservative
shadow observation, not an implementation of later durable allocation/recovery.

## Required test mapping

| Requirement | Named tests |
|---|---|
| Literal request/header/response/JWS/claims and misses | `TestFrozenRefreshRoundTrip`, `TestShadowBootOnlyFrozenWire`, `TestUnknownMissTyping` |
| Exclusions and 19/20 distinct history | `TestCallerIdempotencyAndExclusions`, existing `TestEligibilityExclusions`, `TestEveryPublicExclusionField`, `TestHistoryDistinctThreshold` |
| Late grant/key/trust/price expiry and concurrent renewal/deny | `TestLateGrantOriginalDeadline`, `TestConcurrentRenewalDenyAndNoTimerRecovery`, existing `TestOriginalDeadlineBoundaries`, `TestConcurrentRenewalStaleDelivery` |
| Caller provenance before generated IDs | `TestSpeculationStartupAndProvenance`, `TestCallerIdempotencyAndExclusions` |
| Credential/backoff order, no extension/recovery | `TestShadowCredentialBackoffOrderingCounters`, `TestConcurrentRenewalDenyAndNoTimerRecovery`, existing `TestBillingBackoffTTL`, `TestBillingBackoffConcurrent` |
| Boot-only, Stage A off | `TestShadowBootOnlyFrozenWire`, existing Stage D boot tests |
| Off/shadow attempts, holds, usage, finalization and output | `TestShadowPhysicalMoneyOutputDifferential` (verified eligible grant), `TestShadowOffBodyAndSignatureParity`; existing Stage C/D regressions and goldens |
| Success/error/retry/malformed timing | `TestPhysicalTimingUnknown`, `TestShadowRetryTimingAndByteParity`, `TestShadowTimingBodyBounded` |
| Reused public backoff IDs | `TestSuppressionJoinsAndTelemetryAllowlist`, `TestShadowCredentialBackoffOrderingCounters` |
| First content vs metadata, active interval unknown | `TestFirstContentVersusSSEMetadata`, `TestUnfinishedProviderIntervalRemainsUnknown` |
| Interval union/intersection and serial counterfactual | `TestIntervalUnionIntersection`, `TestSerialTimingAndDeniedEvidence`, `TestFallbackIsNotProposedRoute`; unchanged requesttiming regressions |
| Mode off/shadow/enforce/invalid/unset | `TestMode`, `TestSpeculationStartupAndProvenance` |
| Immutable local evidence and scoped infrastructure | `TestTrustedConfigurationCopiedAndMalformedFailsClosed`, `TestInfrastructureBreakerIsKeyBootScoped`, `TestRefreshGrantCannotCrossIdentityWithMisboundConfiguration` |

## Mutation gate

`python3 enclave-go/internal/shadowcoord/testdata/mutate.py` copies the Go module
to a temporary directory. Every row runs a green named baseline, a compiling red
mutant, restores exact source bytes, then runs a green named baseline again.

| Mutant | Failing test | Baseline / mutant / restored |
|---|---|---|
| `decision-after-authorize` | `TestShadowSelfQualificationPredecisionBeforeNetwork` | green / red / green |
| `predecision-before-credential-guard` | `TestShadowCredentialBackoffOrderingCounters` | green / red / green |
| `five-second-cache-expiry-reopens-health` | `TestConcurrentRenewalDenyAndNoTimerRecovery` | green / red / green |
| `extra-provider-call` | `TestShadowPhysicalMoneyOutputDifferential` | green / red / green |
| `sum-a-p-as-measured-overlap` | `TestSerialTimingAndDeniedEvidence` | green / red / green |
| `guessed-denied-p-as-measured` | `TestSerialTimingAndDeniedEvidence` | green / red / green |
| `prompt-field-in-telemetry` | `TestSuppressionJoinsAndTelemetryAllowlist` | green / red / green |
| `renew-deadline-at-receipt` | `TestLateGrantCannotGainReceiptTTL` | green / red / green |
| `accept-enforce` | `TestMode` | green / red / green |
| `unknown-miss-as-malformed-error` | `TestUnknownMissTyping` | green / red / green |

Detailed logs: `/var/folders/th/1hvz8frd3p551wg24zytym940000gn/T/quill-e4-mutation-results-_q6j5223`. All mutants compiled; build failures do not count as kills.

## Full CI commands

All commands run from `enclave-go` with:

```sh
export PATH=/Users/jperla/josh/repos/tr/quill-router/.venv/bin:$PATH
export GOTOOLCHAIN=go1.24.13 GOFLAGS=-mod=mod
export GOCACHE=/tmp/quill-e4-go-cache
export GOLANGCI_LINT_CACHE=/tmp/quill-e4-lint-cache
```

The temporary caches satisfy this session's filesystem sandbox; they do not
change the repository or the CI tool versions. For each tag row below:

```sh
go build -tags "$tags" ./...
go vet -tags "$tags" ./...
go run github.com/golangci/golangci-lint/cmd/golangci-lint@v1.64.8 run --allow-serial-runners --build-tags "$tags"
go test -count=1 -tags "$tags" ./...
go test -race -count=1 -tags "$tags" ./...
```

| Build tags | Build | Vet | Lint 1.64.8 | Test -count=1 | Full race |
|---|---|---|---|---|---|
| `cloud_aws,llm_bedrock` | PASS | PASS | PASS | PASS | PASS |
| `cloud_aws,llm_multi` | PASS | PASS | PASS | PASS | PASS |
| `cloud_azure,llm_multi` | PASS | PASS | PASS | PASS | PASS |
| `cloud_gcp,llm_vertex` | PASS | PASS | PASS | PASS | PASS |
| `cloud_gcp,llm_multi` | PASS | PASS | PASS | PASS | PASS |

All **25/25 gates passed**. Exact command/exit/log records: `/tmp/e4-verified-gates-results.json`; logs: `/tmp/e4-verified-gate-<tags>-<0..4>.log`.


Full-package race testing includes changed cmd/enclave, trustedrouter, speculation,
requesttiming, both new packages, and the existing Stage C/D suites.

## Coverage

```sh
go test -count=1 -tags 'cloud_gcp,llm_multi' \
  -coverpkg=./internal/shadowcoord,./internal/shadowobserve,./internal/trustedrouter,./cmd/enclave \
  -coverprofile=/tmp/e4-verified-cover.out \
  ./internal/shadowcoord ./internal/trustedrouter ./cmd/enclave
python3 internal/shadowcoord/testdata/coverage.py /tmp/e4-verified-cover.out
```

Cross-package profiles repeat blocks for separate test binaries. The checker takes
the union (maximum count) per identical block, writes a standard merged profile,
and requires >=90% in every new executable Go file. Type/alias-only files have no
executable statements.

```text
cmd/enclave/speculation.go: 35/37 = 94.6%
internal/shadowcoord/coordinator.go: 241/251 = 96.0%
internal/shadowobserve/execution.go: 126/127 = 99.2%
internal/shadowobserve/mode.go: 5/5 = 100.0%
internal/shadowobserve/timing.go: 27/27 = 100.0%
internal/shadowobserve/wire.go: 36/37 = 97.3%
internal/trustedrouter/shadow.go: 85/85 = 100.0%
merged=/tmp/e4-verified-cover-merged.out
```

## Off-mode and static proof

* `rg --files enclave-go -g '*.go' -0 | xargs -0 gofmt -l`: empty output.
* `git diff --check`: clean.
* `rg -n 'internal/(testutil|testhelper)|/testdata' enclave-go/cmd enclave-go/internal -g '*.go' -g '!**/*_test.go' -g '!**/testdata/**'`: no matches.
* All **89** tracked fixture/golden files under `enclave-go` match the HEAD git
  blob bytes. Their SHA-256 manifest is
  `fe51959ba875b92105177676a830ca9a94a41fe7c7edf2f4fc92d1b6460891d9`;
  `/tmp/e4-golden-pins.txt` lists every path/digest.
* The supplied refresh fixture SHA-256 remains
  `ad8d4161013cdf442aa4f221abf06c418ee15353d646487ac95ac8419d8aef39`.
* No changes to `internal/requesttiming/timing.go`, credential-cache policy,
  either billing-backoff implementation, or any existing golden/fixture bytes.
* The positive handler differential compares exact SSE bytes after normalizing
  existing random response IDs/created values and existing timing fields. Exact
  authorize body/signature parity is tested separately with a fixed invocation.

## Final working-tree status

```text
 M enclave-go/cmd/enclave/http_io.go
 M enclave-go/cmd/enclave/main.go
 M enclave-go/cmd/enclave/provider_stream.go
 M enclave-go/internal/bootstrap/bootstrap_gcp.go
 M enclave-go/internal/speculation/robustness_test.go
 M enclave-go/internal/trustedrouter/authorization_retry.go
 M enclave-go/internal/trustedrouter/client.go
 M enclave-go/internal/trustedrouter/spend_lease.go
 M enclave-go/internal/trustedrouter/stage_c.go
?? enclave-go/cmd/enclave/speculation.go
?? enclave-go/cmd/enclave/speculation_test.go
?? enclave-go/internal/shadowcoord/
?? enclave-go/internal/shadowobserve/
?? enclave-go/internal/speculation/testdata/speculation_v1/shadow-refresh-wire.json
?? enclave-go/internal/trustedrouter/shadow.go
?? enclave-go/internal/trustedrouter/shadow_test.go
```
