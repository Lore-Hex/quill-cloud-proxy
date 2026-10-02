# PR 2b round 2: ordinary wire parity and bounded work

`llm.PrepareChatRequest` in `internal/llm/chat_preparation.go` now prepares the
ordinary dispatch payload and its path/response-mode metadata. It resolves the
provider model ID, uses the existing ordered builder, applies the remaining
provider transformations, and marshals once. It performs no network operations,
clock reads, randomness, secret resolution or input mutation. Ordinary dispatch
sends its bytes unchanged. Image fetching and Privatemode random salt resolution
remain outside preparation. The eligibility seam is still unwired.

The seam retains the closed text-only field allowlist and requires an independently
certified route. After a bounded precheck, it uses ordinary typed parsing and
Anthropic normalization, including system-message merging and empty-message
handling, then consumes the shared preparation bytes. A trusted provider cache
scope is an explicit certificate input, identical to ordinary dispatch. Privatemode
is excluded from the seam because its salt resolution is outside this contract.

The precheck traverses the parsed request once, spending an escaped UTF-8 budget
on strings, keys, values and containers. String lengths and container cardinality
reject impossible inputs without scanning their contents. Strings that fit in raw
bytes stop as soon as JSON escaping exhausts the budget. Depth is capped at 64.
System additions and cache scope share the same budget. No request copy or marshal
happens before this check. It conservatively includes control-plane fields that
will not appear on the wire and allows 24 bytes per finite floating-point number.
A final exact wire-byte check handles adapter-added fields; SHA-256, the certified
input bound and B all derive from those exact bytes. The signed grant decoding and
certificate comparison have fixed, independently protocol-bounded overhead.

The reviewer's §2 telemetry note is addressed: distinct local inputs now produce
`not_pilot_workspace`, `paid_provenance_missing`, and `key_ineligible`.
`local_trust` covers boot verification only. The closed taxonomy is documented in
`eligibility-verification.md`.

## Differential and regression tests

- **1,200 ordinary-path differential cases:** 30 provider/model routes × two
  client stream values × explicit/implicit output cap × ten request variants.
  Variants cover implicit defaults, explicit sampling/stop/cache/format fields,
  system additions, Unicode/HTML escaping, empty messages, 64 KiB content, effort,
  disabled reasoning, tools and native thinking. The frozen builder and dispatch
  preparation were copied from `4a4f0695` into `chat_preparation_frozen_test.go`.
  A separate 1 MiB HTML-escaping case also checks frozen/shared/HTTP equality,
  for **1,201 ordinary wire cases** in total. Each matrix case compares
  bytes/errors/metadata and intercepts the actual ordinary
  HTTP request. Shared inputs are checked for mutation.
- **48 seam parity cases:** 12 provider/model routes × implicit/explicit optional
  fields × plain/system-added requests. These assert byte/hash parity, preservation
  of `stop`, the system role and merged contents, usage options, sampling and cap
  transformations, and scoped Tinfoil cache identity.
- Empty-only and malformed requests, invalid marshal inputs, unresolved private
  cache, native Responses validation, and missing model errors are covered.
- Encoded-budget tests cover UTF-8, every JSON escape class, scalars, containers,
  deep/cyclic inputs, oversized strings, message counts, nested parameters,
  system additions, cache scope, and exact budget boundaries. Allocation tests
  reject a 9 MiB string, a million messages, a million nested values, and an
  8,000-byte HTML string whose escaped form exceeds the budget.
- Existing provider-stream regression tests run with every CI tag set. All frozen
  protocol tests and fixtures remain unchanged. `TestPreparedOrdinaryWire` pins
  adapter bytes independently of the synthetic `provider-wire.json` literal.

The eligible adapter fixture now has 144 wire bytes, input bound 176 and B=600
microdollars. Its wire SHA-256 is
`200c013d1356147e94433b181a904d217c1a97b5cc54fd3d84bdfcb1119eafd4`.
The frozen protocol literal and descriptor retain their original bytes/hash.

## Allocation evidence

A fresh-process one-iteration baseline benchmark of the committed seam, on the
same Apple M2 and Go 1.24.13, rejected the 9 MiB `<` input in **144,178,000 ns**, using
**427,924,440 B/op and 1,004 allocations/op**. The review independently measured
427,947,416 bytes. Pool reuse in subsequent baseline iterations reduced buffer
allocations, but still serialized the entire input.

The updated regression test reports **23,651 B/op and 882 allocations/op** for
all four oversized shapes. Allocation assertions cap each operation at 128 KiB
and 1,000 allocations, independent of supplied length. The bounded traversal
itself allocates nothing; the remaining allocations are verified-grant decoding
and certificate comparison. Benchmark logs are in `/private/tmp/spec-e2b-round2/`.
After the other gates finished, three one-second benchmark runs measured
**112,419 / 108,037 / 148,383 ns/op**, each with **23,648 B/op and 882
allocations/op** (median 112.4 microseconds). See `after-idle-benchmark.log`.
The cold baseline above and these steady-state measurements are labeled
separately because encoding/json buffer-pool reuse affects allocations.

## Verification environment

Every Go gate uses `GOTOOLCHAIN=go1.24.13 GOFLAGS=-mod=mod`, with PATH beginning
`/Users/jperla/josh/repos/tr/quill-router/.venv/bin`, and writable Go/lint caches
under `/private/tmp`. Lint is golangci-lint v1.64.8 with
`--allow-serial-runners`. Each of the five CI tag sets runs lint, `go vet`, and
`go test -count=1 ./...`. Race checks run `cmd/enclave`, `internal/llm`, and
`internal/speculation` under all five tag sets (cmd/enclave requires cloud tags).

No git write commands were used. Changes remain uncommitted. The production
import/call-site grep for speculation remains empty; ordinary dispatch does not
consult eligibility, health, grants, descriptors or speculative authority.

## Mutation results

All 11 round-1 mutations and seven additional mutations are red. No survivors or
build failures. The runner applies each edit to an isolated full-module copy.

| Mutation | Behavioral test | Result |
|---|---|---|
| `receipt_time_ttl` | `TestLateGrantCannotGainReceiptTTL` | red |
| `nineteen_successes` | `TestHistoryDistinctThreshold/nineteen` | red |
| `retry_counted_twice` | `TestHistoryDistinctThreshold/retry_counted_twice` | red |
| `chars4_method` | `TestPayloadMisses/chars4` | red |
| `chars4_bound` | `TestPayloadFramingSystemAndExactBounds` | red |
| `default_512` | `TestPayloadMisses/cap_missing` | red |
| `erase_caller_provenance` | `TestEligibilityExclusions/header_idempotency` | red |
| `shadow_dispatch` | `TestDispatchAuthoritySeparation` | red |
| `lease_dispatch` | `TestDispatchAuthoritySeparation/spend-lease+jws` | red |
| `missing_health` | `TestMissingHealthAndScopedEpochs/workspace_missing` | red |
| `confidential_host` | `TestEligibilityExclusions/confidential` | red |
| `seam_one_byte` | `TestSeamAdapterParity` | red |
| `ordinary_one_byte` | `TestChatPreparationDifferential/fixture-provider/fixture-text/stream=false/cap=false/implicit` | red |
| `remove_precheck` | `TestOversizedPayloadAllocations/text` | red |
| `drop_stop` | `TestSeamAdapterParity` | red |
| `prefix_role` | `TestPayloadFramingSystemAndExactBounds` | red |
| `older_workspace_epoch` | `TestMissingHealthAndScopedEpochs/workspace_epoch_older` | red |
| `older_key_epoch` | `TestMissingHealthAndScopedEpochs/key_epoch_older` | red |

Raw evidence: `/var/folders/th/1hvz8frd3p551wg24zytym940000gn/T/spec-e2b-mutations-99skvwtw`.

## Final coverage

| Production file | Covered statements | Coverage |
|---|---:|---:|
| `llm/chat_preparation.go` | 39/39 | 100% |
| `speculation/deadline.go` | 13/13 | 100% |
| `speculation/eligibility.go` | 83/83 | 100% |
| `speculation/health.go` | 13/13 | 100% |
| `speculation/payload.go` | 88/88 | 100% |
| `speculation/payload_budget.go` | 65/65 | 100% |

The package totals are 99.4% for speculation and 71.3% for llm; the required
new-file threshold is met by each file above. Profile:
`/private/tmp/spec-e2b-round2/final-coverage.out`.

## Final gate lines

```text
cloud_aws,llm_bedrock lint: exit 0 (18.1s)
cloud_aws,llm_bedrock vet: exit 0 (2.0s)
cloud_aws,llm_bedrock test: exit 0 (27.2s)
cloud_aws,llm_multi lint: exit 0 (21.6s)
cloud_aws,llm_multi vet: exit 0 (1.8s)
cloud_aws,llm_multi test: exit 0 (30.6s)
cloud_azure,llm_multi lint: exit 0 (22.5s)
cloud_azure,llm_multi vet: exit 0 (2.2s)
cloud_azure,llm_multi test: exit 0 (31.8s)
cloud_gcp,llm_vertex lint: exit 0 (24.1s)
cloud_gcp,llm_vertex vet: exit 0 (1.6s)
cloud_gcp,llm_vertex test: exit 0 (30.2s)
cloud_gcp,llm_multi lint: exit 0 (6.7s)
cloud_gcp,llm_multi vet: exit 0 (2.6s)
cloud_gcp,llm_multi test: exit 0 (34.3s)
```

Lint reports `v1.64.8 built with go1.24.13`. Gofmt emits no paths,
`git diff --check` is clean, and the production eligibility-import grep is empty.
The frozen protocol/fixture files have no changes.

Race gates (`go test -race -count=1` on all three requested packages):

```text
cloud_aws,llm_bedrock race: exit 0 (88.7s)
cloud_aws,llm_multi race: exit 0 (97.4s)
cloud_azure,llm_multi race: exit 0 (98.3s)
cloud_gcp,llm_vertex race: exit 0 (98.6s)
cloud_gcp,llm_multi race: exit 0 (79.7s)
```

## Uncommitted worktree status

```text
 M enclave-go/internal/llm/byok.go
 M enclave-go/internal/speculation/eligibility-verification.md
 M enclave-go/internal/speculation/eligibility.go
 M enclave-go/internal/speculation/eligibility_test.go
 M enclave-go/internal/speculation/payload.go
 M enclave-go/internal/speculation/payload_test.go
 M enclave-go/internal/speculation/testdata/eligibility_mutations.py
?? enclave-go/internal/llm/chat_preparation.go
?? enclave-go/internal/llm/chat_preparation_frozen_test.go
?? enclave-go/internal/llm/chat_preparation_test.go
?? enclave-go/internal/speculation/eligibility-round2.md
?? enclave-go/internal/speculation/payload_budget.go
?? enclave-go/internal/speculation/payload_budget_test.go
?? enclave-go/internal/speculation/payload_parity_test.go
```
