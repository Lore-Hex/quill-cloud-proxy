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
router's per-boot ten-second limit. A refresh-only boot signer and the existing internal
gateway token authenticate exact canonical request bytes. Enabling shadow does not
install an ordinary authorize signer when Stage A/D are disabled.

Grants are verified with `VerifyGrant(..., shadow=true)` using independent local
context. Original grant/key/trust/price deadlines are converted once using
`ReceiveGrant`, retaining the final two-second margin. A repeated JWS does not
renew a deadline, grant allowance or ordinal. History freshness has its own
original, monotonic deadline. A bounded, independent SHA-256 receipt journal retains
the first conversion across cache invalidations (256 fingerprints per identity;
saturation fails closed). Misses invalidate cached capability without touching
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

Lookup digests have an O(1) identity index. The coordinator snapshots state under
its mutex, runs refresh verification and request payload work outside it, then revalidates the revision,
health and deadlines before depletion. A concurrent change yields a typed miss.
Raw input above the shared 8,192-byte certified maximum or container nesting
deeper than 32 misses with `input_bound` before JSON decoding. A bounded byte scan
tracks quoted strings and escapes; unknown fields cannot hide deep recursion.

Simulation atomically consumes a grant ordinal, one unresolved workspace slot,
one of 32 enclave slots, 128 KiB of the 8 MiB simulated memory budget (64 KiB spool
and 64 KiB parser/frame state), and retained workspace/stable-slot/fleet budget
under the coordinator lock. Every execution exit idempotently releases ownership
and simulated memory/concurrency; the hypothetical money remains retained. The
limits are W from `WorkspaceAllowance` (never above $0.25 for tier 2), $1 per slot, $10 per fleet, and the signed
per-request bound. A refresh does not refill permits. Unknown liability stays
retained; this implementation does not infer a refund, recovery or newly free
capacity from an ordinary success, cache expiry, grant renewal or elapsed day.
Workspace/key denial state survives time, volume, grant expiry, eviction, and
ordinary successes. Recovery rules appear below. Restart requires independent new-boot/stable-slot
allocation evidence, rather than reusing the previous boot's local counters.

`shadowobserve` contains the dependency-free wire, execution and telemetry types.
This keeps `trustedrouter` independent of `speculation`/`llm`, including the AWS
image-fetch dependency. Every physical retry contributes bounded typed router
phase timing (or UNKNOWN) and closes local infrastructure health immediately when
retryable, even when its logical call succeeds. Authenticated error types `invalid_api_key`, `insufficient_credits`,
`key_limit_exceeded`, `key_window_limit_exceeded`, and `service_unavailable`
normalize to scoped or infrastructure reasons. The router's exact
`forbidden` / message `billing_paused` pair also denotes workspace state; arbitrary
human messages do not classify health. Caller cancellation/deadline errors retain
their original ordinary error and contribute no infrastructure verdict. A real
router denial remains observable even if the caller concurrently cancels. Internal
retry-budget/transport timeouts with a live caller still close infrastructure health.

Optional authenticated error `data.workspace_id`, `key_id`, `lookup_digest`, and
`rate_scope` are **proposed; not emitted by the router today**. This is a
forward-compatible parse, never a required contract. The router change and a shared
literal fixture must land before anything relies on these fields. The pinned
`authorize-error-envelopes.json` has timing-only `data` in all five cases; absent
scope is the normal production path. Independently known lookup bindings resolve
normal denials. Matching partial workspace metadata preserves the known key;
conflicting metadata produces coverage uncertainty without inventing an assignment.
Malformed optional metadata cannot affect ordinary error decoding.

## Recovery and capacity

All state below is simulation. Signed shadow grants attest the issuer's repair
checks (including durable health, limiter reset/clearance and history); the enclave
does not synthesize those facts from elapsed time. `VerifyShadowRefreshGrant` keeps
all deployment/route bindings fixed, permits only authenticated signed health epochs
to change, and retains the unchanged exact-binding `VerifyGrant` API. Epoch snapshots
advance monotonically; a lower-epoch replay cannot regain eligibility.

| Scope | What closes it | What reopens it | What never reopens it |
|---|---|---|---|
| Workspace | Resolved credit, trust, abuse, payment, pause or workspace/ambiguous rate denial | Verified grant first received after the latch with strictly higher workspace epoch | Time, volume, success callback, expiry, eviction, same epoch, key-only repair |
| Key | Resolved invalid/revoked/expired key, key budget or explicit key-rate denial | Verified grant first received after the latch with strictly higher key epoch | Time/window reset, volume, old success, expiry, same epoch, workspace-only repair |
| Key infrastructure | Retryable 5xx/timeout/transport failure | Three clean ordinary successes for this key whose first/last span ≥30s after the latest failure, plus a verified grant first received after failure | Another key's successes, old callbacks, time alone, pre-failure grant |
| Boot infrastructure | Unscoped infrastructure failure or bounded key-breaker overflow; every further infrastructure failure restarts it while active | Same three-success/30s rule on this boot after the latest failure plus a grant first received after it | Time alone, old callbacks, pre-failure grant replays or probe evidence |
| Uncertain coverage | Unbound authenticated business denial, conflicting binding, or scope capacity overflow | Each identity's verified grant from a refresh **sent after** the denial | An already-in-flight refresh, ordinary success, time alone |
| No health change | Unresolvable invalid credential; request-only other 4xx | No recovery needed | These responses cannot latch an unrelated workspace |

Refresh sends, receipts, denial observations and ordinary request starts have a
mutex-ordered event sequence. Receipt ordering is independent of the original grant
monotonic-deadline journal. Ordinary calls started before a failure cannot count as
clean recovery probes; a successful retry does not erase the observed failure.
Reopening any health scope never releases retained hypothetical liability.

Identity and scope maps cap at 256 entries. Identity admission first evicts an entry
whose policy and grant have expired, with no active owner and no retained liability;
it removes the hot-set/index entry too. Unknown retained loss has no local expiry and
is never evicted as if refunded. If every entry is live or retains liability, the new
identity is skipped with a bounded `capacity` record (`identity-capacity`). Eviction
also emits `identity-evicted`. Scoped-map overflow emits `health-capacity` and applies
re-confirmation instead of permanent boot closure. Infrastructure-map overflow emits
`infrastructure-capacity` and uses the recoverable boot breaker. Recovered scope
entries are removed. All capacity/invalidation records share the existing rate and
queue bounds, with dropped-record counts visible in subsequent records. An unbound
denial uses one global generation plus one confirmation scalar per identity, rather
than an unbounded unknown-credential map.

Narrow callback/worker recovery boundaries count observation faults, permanently
fail shadow eligibility closed, and preserve ordinary results, errors and context
cancellation. Runtime exits are not recovered; panic values are never logged.

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
loss is counted monotonically and included in later records. A shared admission
cap allows 100 records per one-second monotonic window (at most 200 across a window
boundary), including refresh misses. An ordinary observed request proposes two
records: predecision and execution, with retries embedded in that execution. A
backoff-suppressed request proposes one record; refresh proposes up to 64 misses
per tick, at least ten seconds apart. Rate/queue/fault loss appears in subsequent
`dropped_observations` values. Capacity evidence is
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
  `simulated-journal-capacity`, `simulated-permits-exhausted`,
  `simulated-enclave-concurrency`, `simulated-memory`, `snapshot-changed`,
  `observer-failed`, `grant-shape`, `grant-journal-capacity`, `grant-replay`, `input_bound`,
  `coverage-unconfirmed`.

Receipt journals retain at most 256 live fingerprints per identity. Each record
keeps its first receipt event and original monotonic deadline, even across misses
and replays. Refresh processing retires expired records into a constant-size,
inclusive signed `iat` watermark. An unseen fingerprint at or below that watermark
is a `grant-replay` miss, including after wall-clock rollback; it cannot acquire a
new deadline or recovery order. This conservatively rejects previously unseen
out-of-order grants in the retired issuance range. Still-retained fingerprints
keep their original deadlines/events. A full live journal returns
`grant-journal-capacity`; newer grants resume admission once old records expire.
The watermark lasts for the identity's policy lifetime; identity eviction already
requires expired policy and no retained liability or active owner.

Every infrastructure failure while the boot breaker is active restarts its failure
time, clean-probe count/span and fresh-grant requirement, including a failure on an
already-tracked key. A replay never supplies new post-failure grant evidence.

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

Round-2 findings, mutation kills, startup traces, performance and the complete
five-tag gate results are recorded in [round2-verification.md](round2-verification.md).

The timing-only authorize error fixture SHA-256 is
`a2f388da8afd619793fedfb78013dcdf61843ae0a9b5dca936647ca8582746d4`.
`TestLiteralAuthorizeErrorEnvelopes` decodes every case through the HTTP client,
checking status, authenticated type/classification, Retry-After, typed timing and
absent scope. Round-3 recovery, mutations, split cost measurements and full gates
are recorded in [round3-verification.md](round3-verification.md).

Round-4 fixes, regression/mutation evidence and gates: [round4-verification.md](round4-verification.md).
