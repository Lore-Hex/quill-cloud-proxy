# Enclave speculative-invocation shadow (PR 4)

This package has no provider, billing, credential-cache, or real admission authority.
`QUILL_SPECULATIVE_PROVIDER_MODE` is independent of Stage A and defaults to `off`.
Only exact `off` and `shadow` values are accepted; `enforce` refuses startup until
PR 15. No deployment setting is enabled by this change.

`cmd/enclave/initializeSpeculation` returns off before reading configuration,
constructing a coordinator, starting a worker, allocating records, or serializing.
Request/decode/retry hooks return on a nil observer. Existing ordinary timing and
Stage D continue unchanged. Shadow skips the old local admission/echo state.

## Trust and lifecycle

`QUILL_SPECULATIVE_PROVIDER_CONFIG` is independently authenticated deployment
configuration decoded as `Config`, not public request input or token-supplied
trust. Empty configuration deliberately admits nobody. It includes verifier keys,
complete local policy/route certificates and bindings, stable slot/owner evidence,
local health, evidence expiry, clock uncertainty, and plane/region/paired SHAs.
Production contains no fixture keys. Startup additionally checks the boot signer,
actual local Stage D enablement and `TR_REGION`; provider cache scope uses the
same workspace derivation as ordinary dispatch.

`RemoteKnown` must certify the remote hypothetical allocation, including other
owners, previous incarnations of the stable slot, and retained unknown exposure.
It must not mean “the router answered”, an observed empty local counter, or an
assumption of idle fleet capacity. Missing/expired evidence is a miss. Source
configuration must reserve the represented capacity consistently across the
cohort; PR 4 does not manufacture distributed allocation evidence from the frozen
grant-only refresh response. Activation evidence is a later release input.

Only ordinary successful authorizations add resolved identities to the bounded
256-entry hot set. The identity uses **the same `requestLookupHash` passed to
`authorizeAtDecodeSeamWithAdmission` and serialized as `api_key_lookup_hash`**,
plus the returned workspace and stored key ID. The request path never refreshes.
One worker sends at most 64 items after 10 seconds plus [0,1 second) jitter, with
a five-second call deadline. Failure retries on a later tick, never inside the
router's per-boot ten-second limit. The Stage D boot signer and existing internal
gateway token authenticate exact canonical request bytes.

Grants are verified with `VerifyGrant(..., shadow=true)` using independent local
context. Original grant/key/trust/price deadlines are converted once using
`ReceiveGrant`, retaining the final two-second margin. A repeated JWS does not
renew a deadline, grant allowance or ordinal. History freshness has its own
original, monotonic deadline. Misses invalidate cached capability without touching
ordinary traffic or credential state.

## Decision and evidence

The main Chat hook follows target/confidential validation, credential guard,
identical-request 402 backoff, parsing/validation and orchestration exclusions,
and immediately precedes ordinary authorize. Header presence (including an empty
header) and original body provenance survive internally generated idempotency.
The immutable predecision is emitted before authorize and joins to the subsequent
logical call by execution ID; nonce and authorization ID are attached when known.
Other authorize entry points get excluded predecisions at the common decode seam.

The PR 2b evaluator prepares the exact shared Chat adapter payload, checks its
serialized output cap and computes the vendor bound. Additional integration
predicates conservatively reject provider preferences whose applicability is not
proved, hidden system-prefix differences, expired independent policy/allocation
facts and history older than thirty seconds at decision time. The evaluator's
wire contract and all frozen fixtures are unchanged.

Simulation atomically consumes a grant ordinal, one unresolved workspace slot,
and retained workspace/stable-slot/fleet budget under the coordinator lock. The
limits are W from `WorkspaceAllowance` (never above $0.25 for tier 2), $1 per slot, $10 per fleet, and the signed
per-request bound. A refresh does not refill permits. Unknown liability stays
retained; this implementation does not infer a refund, recovery or newly free
capacity from an ordinary success, cache expiry, grant renewal or elapsed day.
Sticky workspace/key denial state and key/boot infrastructure suppression cannot
be cleared by a late success. Restart requires independent new-boot/stable-slot
allocation evidence, rather than reusing the previous boot's local counters.

`shadowobserve` contains the dependency-free wire, execution and telemetry types.
This keeps `trustedrouter` independent of `speculation`/`llm`, including the AWS
image-fetch dependency. Every physical retry contributes bounded typed router
phase timing (or UNKNOWN) and closes local infrastructure health immediately when
retryable, even when its logical call succeeds. Real error types
`invalid_api_key`, `key_limit_exceeded` and `key_window_limit_exceeded` are normalized
to PR 2b reasons; human messages never classify health.

A backoff hit emits `billing_backoff_suppressed` with a new observation ID and the
original denial's audit identity, without another predecision, permit or authorize.
It is not a fresh verdict and cannot extend the five-second window.

Matching first-route ordinary executions expose monotonic authorize/provider/
first-content/client-first-content intervals. SSE metadata is not content. A
fallback or same-provider retry does not substitute for the proposed first
attempt. Denied calls have null measured P. Successful matching calls have a
separately labelled `counterfactual_min_a_p_ns`; actual shadow A/P overlap is zero.
Durable-denial/send/spool/adoption/handoff are explicitly `not-applicable`.
Existing cumulative authorize, invocation union, first-byte and settle-overlap
measurements are not redefined. Router wall timestamps are never subtracted from
enclave timestamps.

The telemetry type is a closed content-free allowlist. Prepared bytes, prompts,
raw bodies/errors, headers, BYOK and credentials cannot enter the observation
queue. Its 512 records and 16 attempt samples per execution are bounded. Queue
loss is counted monotonically and included in later records. Capacity evidence is
labelled `simulation`; it is not a measurement of a speculative spool or remote
backpressure. Missing joins or dropped observations disqualify complete release
evidence.

## Miss taxonomy

* Router misses: preserve HTTP status plus bounded code, both batch and per-item.
  The router's list is open: future codes remain typed misses. No error is returned
  to an ordinary inference caller. Invalid envelopes become `malformed-response`.
* Transport/boot: `boot-unavailable`, `transport-unavailable`.
* Verification/freshness: `grant-invalid`, `grant-identity-mismatch`, `policy-stale`, `history-stale`, the
  original PR 2b deadline/binding/key/trust/health/request/payload/cost reasons.
* Local simulation: `identity-ambiguous`, `request-route-uncertain`,
  `payload-context-uncertain`, `policy_stale`, `allocation-unknown`,
  `simulated-concurrency`, `simulated-retained-budget`,
  `simulated-journal-capacity`, `simulated-permits-exhausted`.

The frozen refresh fixture SHA-256 is
`ad8d4161013cdf442aa4f221abf06c418ee15353d646487ac95ac8419d8aef39`.
Its request digest is
`62e20eb1f9a0c794abd38c61a03c86fec1edae0a0435702c0b37f7d9bcf8b880`.
`TestFrozenRefreshRoundTrip` verifies the exact body/header/JWS/claims and every
literal miss; `TestShadowBootOnlyFrozenWire` tests the actual HTTP client.

Run mutations with `python3 internal/shadowcoord/testdata/mutate.py` from the Go
module or repository root using the corresponding path. It copies the module to
a temporary directory, checks each named baseline, injects one fault, requires a
named test failure (not a build failure), restores the bytes, and requires green.
It never writes git or mutates the working source tree.
