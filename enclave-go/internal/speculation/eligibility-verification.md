# PR 2b: pure eligibility and payload preparation

Round 2 extracts `internal/llm/chat_preparation.go:PrepareChatRequest` for both
ordinary dispatch and this seam. The only ordinary-path change is calling that
shared preparation (with random Privatemode cache isolation resolved outside it).
There are no production imports of eligibility, flags, git writes, or changes to
the v1 protocol, Stage C, or any frozen fixture. Round-2 evidence supersedes the
historical round-1 verification below; see [eligibility-round2.md](eligibility-round2.md). The pre-existing `VerifyGrant`, `CostCeiling`,
`RenewalVerdict`, and authenticated `ClassifyVerdict` remain authoritative for
those respective contracts.

## API boundaries

1. `VerifyGrant` verifies the original signed history, identity, prices, route,
   epochs and start deadline. Success count and sequence are issuer attestations
   about distinct ordinary authorizations; this PR does not add an event counter
   or count callbacks/retries. The issuer must deduplicate the underlying events.
2. `ReceiveGrant` converts that deadline once using simultaneous wall/boot
   monotonic samples. A nonnegative upper bound on local clock lag is subtracted,
   never added. Receipt after the original deadline, wall time before issuance,
   negative clock inputs, and monotonic overflow fail closed. Subsequent
   evaluation never consults wall time. An unbounded/unknown clock error cannot
   establish eligibility; the integration must provide bounded trusted time.
3. `CaptureCallerIdempotency` records original header/body presence, even an
   empty value, before request normalization or internal key generation. An
   uncaptured zero value is ineligible. `ParsedRequest.Body` retains all public
   fields in the protocol's JSON domain; unknown fields are misses. Trusted
   internal request facts include confidential ingress hosts, BYOK, custom
   models, orchestration, receipts and response rewriting.
4. `EvaluateEligibility` consumes a coherent, pre-authorize local snapshot.
   Current identity/generation/route bindings are independent of the candidate
   grant. `RequestPolicyHash` must be independently derived from this request's
   current routing/privacy requirements by the caller; this seam neither selects
   routes nor copies policy from a candidate. Pilot/paid/key/boot eligibility,
   a single owner boot, fresh policy, and local Stage D must be affirmative.
   Workspace/key/provider identity and health must be known and healthy; latches
   win over renewal and epoch equality is exact. The shadow decision uses the
   same predicates, but `shadow_dispatch_allowed` is always false.
5. `PreparePayload` has no I/O, callbacks, clock access, cache, or input mutation.
   Before copying or marshaling request data, one bounded traversal checks escaped
   UTF-8 size, container counts, nested parameters, system additions and the trusted
   provider cache scope against the signed input budget minus framing (at most
   8,192). Raw lengths reject oversized strings in constant time. A depth limit
   rejects cyclic/overdeep non-JSON inputs. The precheck is conservative: even
   provider controls omitted from the wire consume traversal budget.
   Only then does the seam parse the bounded data into ordinary request types,
   apply ordinary `adapter.ToAnthropic` normalization, and call the shared
   `llm.PrepareChatRequest`. This preserves the adapter's byte order, default
   tier, usage hint, output-cap translation and provider transformations. Explicit
   system additions participate in the same system-message merging. The trusted
   `ProviderCacheScope` must equal the ordinary invocation's resolved scope.
   Privatemode, which requires random cache isolation, is excluded from this seam.
   The exact final bytes are checked again against the signed bound and used for
   SHA-256 and B. E12 must send those bytes without rewriting them. Explicit
   integer `max_tokens` remains mandatory (1..512, within the signed cap).

Exactly one independently supplied `AdapterCertificate` must match the entire
signed route. Certification includes hard output-cap behavior, single physical
attempt, no hidden tools/reasoning, all reachable vendor prices/fees, and known
framing. No production endpoint is certified by this PR. The implemented bound
algorithm is `conservative-utf8-bytes-v1`: final serialized byte count plus the
certified maximum implicit framing/system allowance. Explicit system additions
are in those bytes. This bound is usable only for endpoint/model tokenization
independently certified to satisfy it. The signed `input_bound_method` must name this method or the explicitly
supported frozen-fixture alias `certified-fixture-bound-v1`; both still require
independent local certification. It cannot select an arbitrary estimator. `chars/4`, unknown tokenizers, and missing framing evidence miss.

Both the signed input maximum and 8,192-token pilot maximum apply. B uses the
existing upward-rounded cost ceiling with the final bound and explicit cap,
including mandatory fees. It must be positive and within both the grant ceiling
and 10,000 microdollars. The frozen `provider-wire.json` is a synthetic protocol literal, not an adapter
oracle. Its protocol/hash tests stay frozen. Production-adapter parity has separate
byte-equality tests; the actual prepared bound may be smaller than the signed
route maximum/permit ceiling.

This is an eligibility snapshot, not an atomic physical-send gate. Permit
consumption, risk/money reservation, concurrency/buffer/reporting capacity,
owner serialization, and production wiring remain later PRs. Timing fields from
design §7 are untouched.

## Closed reason taxonomy

```text
eligible
grant_missing
shadow_grant
clock_invalid
start_deadline
binding_mismatch
owner_boot
local_trust
not_pilot_workspace
paid_provenance_missing
key_ineligible
policy_stale
stage_d_unavailable
health_missing
health_unhealthy
workspace_latched
key_latched
workspace_epoch
key_epoch
route_uncertified
not_streaming_chat
credits_not_explicit
service_tier
idempotency_provenance_missing
caller_idempotency
inference_receipts
tools
reasoning
media
byok
custom_model
orchestration
confidential_host
extra_reservation_cost
response_model_rewriting
provider_preferences
external_prompt
prompt_cache_write
unsupported_attribution
unsupported_field
invalid_payload
explicit_output_cap
unsupported_token_bound
input_bound
cost_ceiling
```

The reviewer noted that `local_trust` conflated distinct §2 inputs. Pilot
allowlisting, paid provenance and key eligibility now return
`not_pilot_workspace`, `paid_provenance_missing`, and `key_ineligible`, respectively.
`local_trust` is retained solely for failed boot verification. The taxonomy above
is closed; key subconditions remain the trusted `KeyEligible` attestation.

## Historical round-1 evidence

The tables and commands below describe the committed round-1 baseline. The
current runner copies the full module (the seam now depends on the ordinary
adapter) and runs 18 mutations. Current results are in `eligibility-round2.md`.

## Mutations on temporary copies

Run `python3 internal/speculation/testdata/eligibility_mutations.py` from the module.
The runner verifies a clean baseline, copies the package/fixtures into separate
temporary modules, applies exactly one edit, and runs the named behavioral test.
Build failures are classified separately. No fixture or worktree source is mutated.

| Mutation | Named test | Result |
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

**11 red / 0 survived / 0 build-broken.** Raw evidence: `/var/folders/th/1hvz8frd3p551wg24zytym940000gn/T/spec-e2b-mutations-65f53y23`.

## Verification

Environment for every gate:

```sh
export PATH=/Users/jperla/josh/repos/tr/quill-router/.venv/bin:$PATH
export GOTOOLCHAIN=go1.24.13 GOFLAGS=-mod=mod
export GOCACHE=/private/tmp/spec-e2b-go-cache
export GOLANGCI_LINT_CACHE=/private/tmp/spec-e2b-lint-cache
```

The temporary caches keep tool writes inside sandbox-writable roots.
`golangci-lint v1.64.8` reports it was built with `go1.24.13`.
For each of the five CI tag sets, the final-tree gates are:

```sh
go run github.com/golangci/golangci-lint/cmd/golangci-lint@v1.64.8 run --allow-serial-runners --build-tags "$tags"
go vet -tags "$tags" ./...
go test -count=1 -tags "$tags" ./...
```

Standalone `go test -race -count=1 ./internal/speculation/`: PASS.
The earlier full matrix also passed `go build` and `go test -race -count=1`
for all five tag sets. Final lint/vet/test logs are in
`/private/tmp/spec-e2b-final-gates`; full-matrix build/race logs are in
`/private/tmp/spec-e2b-gates`.

`gofmt -l internal/speculation`: empty. `git diff --check`: clean.
`TestFixturePins`, `TestNoProductionImports`, and `TestPreparedFixtureWire`: PASS.
All 442 protocol literals and 24 verdict vectors run in the package suite.
Production-import/call-site grep (excluding this package and tests): no matches.

```sh
rg -n '"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/speculation"|speculation\.' . --glob '*.go' --glob '!**/*_test.go' --glob '!internal/speculation/**' --glob '!**/internal/speculation/**'
```

New-file coverage (`/private/tmp/spec-e2b-final.cover`):

| File | Covered statements | Coverage |
|---|---:|---:|
| deadline.go | 13/13 | 100% |
| eligibility.go | 77/77 | 100% |
| health.go | 13/13 | 100% |
| payload.go | 73/73 | 100% |

Whole-package coverage: **99.3%**. Serializer properties cover 500 seeded
Unicode payload/map-order cases, with hash/bound consistency and input immutability.

Prepared fixture SHA-256: `75e9f95d9e202c66fcffb7d4c7aa7c88e3dfb80a51e2cddc7539a6e461188f88`.

Final gate lines:

```text
cloud_aws,llm_bedrock lint: exit 0 (1.7s)
cloud_aws,llm_bedrock vet: exit 0 (0.7s)
cloud_aws,llm_bedrock test: exit 0 (25.8s)
cloud_aws,llm_multi lint: exit 0 (1.1s)
cloud_aws,llm_multi vet: exit 0 (0.6s)
cloud_aws,llm_multi test: exit 0 (25.0s)
cloud_azure,llm_multi lint: exit 0 (1.1s)
cloud_azure,llm_multi vet: exit 0 (0.6s)
cloud_azure,llm_multi test: exit 0 (26.3s)
cloud_gcp,llm_vertex lint: exit 0 (2.5s)
cloud_gcp,llm_vertex vet: exit 0 (0.6s)
cloud_gcp,llm_vertex test: exit 0 (25.1s)
cloud_gcp,llm_multi lint: exit 0 (1.7s)
cloud_gcp,llm_multi vet: exit 0 (0.6s)
cloud_gcp,llm_multi test: exit 0 (27.7s)
```
