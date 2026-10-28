# Maple pilot qualification

**Not deployed or customer-routable.** This change adds a qualification client
and a candidate one-shot encrypted adapter, not serving-image integration.
The paired control-plane provider remains internal-only,
with Credits, BYOK, ZDR and confidential/E2EE eligibility all disabled.

The operator explicitly requested **Confidential**, confirmed resale permission
and zero API prompt/response retention on 2026-10-28. Policy confirmation is not
an attestation result. Do not activate a weaker plaintext or ZDR-only route to
work around the remaining confidential-path gates.

The requested model is `deepseek-v4-1-flash-1017-uncensored`. Keep it separate
from stock DeepSeek. At the supplied source commit it routes only to Maple's
dedicated i02 worker; stock DeepSeek can also route to shared Tinfoil.

## Qualification client

`tools/maple-pilot` source-pins Maple's Rust SDK at
`c668d817dceec5c2e7390de7c68a581c88ea2eea` and locks its dependencies. It uses
the vendor's Transport V2 implementation, including Nitro certificate/COSE
verification, fresh challenge and client/server key binding, directional
encryption, ordered frames and authenticated finality. No custom crypto or
bearer-only HTTP fallback is implemented here.

The client accepts only candidate PCR0
`ada74c7aa10cbde75f83d7ec674cc4fc4a4cf9cc555e367189fbec332dffa985c6082ae4647fd50242a590bf9cd1d3f0`,
the latest production-history entry in that immutable source snapshot.
Remote-history trust is disabled. This is a qualification pin, not an approval
of the live source/image binding or of the downstream GPU/model. A mismatch is
a stop condition; do not replace it with whichever measurement the server sends.

Maple's [measurement approval commit](https://github.com/MaplePrivacyLabs/Maple/commit/942efea0bfcbb7523d320186404dcb4cd8f27c0a)
attributes this PCR0 to backend source
`7957ce78ad8eee7a173a9d877ff6e320876894c8` and EIF SHA-256
`9702de6b825bb024d843fb840bf1c638ca7443bbd6ba49f93d14f6e6dfc60e23`,
published by [release run 40226283053](https://github.com/MaplePrivacyLabs/Maple/actions/runs/40226283053).
The run reports success at that source commit. This is vendor-published build
provenance, not an independently reproduced EIF or a verified artifact signature.

```sh
cargo test --locked --manifest-path tools/maple-pilot/Cargo.toml
cargo run --locked --manifest-path tools/maple-pilot/Cargo.toml -- attest
cargo run --locked --manifest-path tools/maple-pilot/Cargo.toml -- reject-pin
cargo run --locked --manifest-path tools/maple-pilot/Cargo.toml -- reject-key
# Supply MAPLE_API_KEY from the operator secret loader, never as a command argument.
cargo run --locked --manifest-path tools/maple-pilot/Cargo.toml -- probe
cargo run --locked --manifest-path tools/maple-pilot/Cargo.toml -- cache
```

`probe` uses the account key and paid inference: one discovery, one JSON
and one SSE synthetic PONG request, each capped at 1,024 output tokens. `cache`
adds three bounded synthetic requests: cold, warm and a separate cache namespace.
Inference
send budget is exactly one per request: no automatic replay after uncertain
delivery. The client checks exact model identity, PONG content, normal finish,
integer token counts, cached-token bounds and streaming usage. Cumulative
streaming counts may begin at zero; they must be monotonic, are never added
together, and require a nonzero terminal usage snapshot for the PONG probe.
It drains SSE
through encrypted EOF even after `[DONE]`, so a missing authenticated terminal
record cannot be mistaken for success. Responses have time/size bounds.

Output contains only fixed-vocabulary errors and metadata. SDK debug logging
is not installed. Never print raw provider errors, response content, credentials,
session keys or cache roots. The wrong-key check uses a deliberate fake key and
does not test the real account's entitlement. Positive front attestation alone
is not end-to-end qualification.

## Initial evidence (2026-10-28)

Local qualification against the production backend:

- Fresh front-enclave session accepted the exact candidate PCR0 above (235 ms
  in one observation; not an inference latency benchmark).
- A deliberately different PCR0 was rejected after a successful positive
  control handshake. The SDK returns a combined attestation/PCR rejection;
  network errors are not accepted as a passing negative test.
- Encrypted `GET /v1/models` with a deliberate invalid key returned logical
  HTTP 401, not a transport failure.
- The operator subsequently supplied `MAPLE_API_KEY` in the keyfile. It was
  loaded only into the test process environment, not printed or provisioned to clouds.
- Authenticated encrypted discovery returned 13 models including the requested
  uncensored ID. JSON and SSE PONG probes passed with exact model identity and
  integer usage. One completed run measured 1,036 ms for JSON (39 input/16 output)
  and 699 ms for SSE (39 input/4 output, first delta 699 ms). These are individual
  short-request observations, not a latency or incremental-delivery benchmark.
- The first stream probe exposed an overly strict test-client assumption that
  every usage snapshot was final and nonzero. Maple sends cumulative snapshots;
  the client now validates monotonic counters and final usage with a regression test.
- A fresh cache qualification sent 12,369 input tokens per call: cold cached 0,
  warm cached 12,288, a new independent namespace cached 0. Output counts were
  10/19/22. This verifies SDK namespace isolation locally, not production
  workspace isolation or account-debit reconciliation.
- The signed-in dashboard confirms the dedicated TrustedRouter key and an
  active Pro plan expiring November 28, 2026, with zero purchased extra credits.
  It does not expose per-request debits or the remaining included allowance.
  No subscription, purchase, or key changes were made.
- Local Claude CLI Opus review was attempted but OAuth refresh failed. No private
  Claude API key was substituted and no successful review is claimed.

## Dedicated worker qualification

The exact deployed front source pins i02 to
[`MaplePrivacyLabs/inference-deepseek-uncensored`](https://github.com/MaplePrivacyLabs/inference-deepseek-uncensored/tree/76a8e5fdaa7dbade1640025829ba0bfeae7a3495),
tag `v0.1.0-rc.1+b300`, digest
`1d92cd06f7b47179bf81612f6a41fdb0a329253affef1803f0cdeb5175cc80c4`.
A fresh nonce-bound worker report passed the pinned vendor verifier
[`f0fef79eec6a5a2c8592cf8aff4b90ab556acfbc`](https://github.com/MaplePrivacyLabs/tinfoil-rs/tree/f0fef79eec6a5a2c8592cf8aff4b90ab556acfbc).
Wrong nonce, wrong measurement and tampered CPU signature were rejected.
Attested `/health` succeeded before and after negative checks rejecting
plaintext HTTP, a different port and a wrong TLS key pin. No account credential
was sent to the worker. Its unauthenticated `/v1/models` returns 401; this is
not a successful catalog probe and must not be represented as one.

The measured worker config uses CVM v0.14.13, an immutable container digest,
and dm-verity verified weights at
`dealignai/DeepSeek-V4.1-Flash-1017-UNCENSORED-FP8@c19ca5ca4eaeb79d29fdf08aea8327da95b1116a`.
Source review of [CVM v0.14.13](https://github.com/tinfoilsh/cvmimage/tree/c3b4860d72e78baf61140778b92986b102716b87)
found that the measured config hash is checked before use; GPU appraisal runs
before serving and failures leave the GPU not ready. Model volumes are mounted
read-only through dm-verity. The Rust client binds device evidence into the
CPU report but delegates NVIDIA appraisal to this measured boot implementation.
Do not describe it as a separate NVIDIA signature verification by TR's client.

## Candidate serving protocol

`maple-transport` accepts one bounded JSON envelope on stdin: the managed API
key, a base64 32-byte cache root from the authorized workspace, and an OpenAI
chat body. It permits only the exact uncensored model with streaming enabled;
TR can aggregate that stream for non-streaming public requests. Backend and
PCR0 are compiled constants, not environment or request overrides. Caller cache
fields are removed and usage is mandatory. An SDK send budget of one forbids
automatic inference replay.

Output is one JSON status line followed by canonical SSE. The relay validates
model identity, integer cumulative token/cache counts and frame/response limits.
It withholds `[DONE]` until the SDK reports authenticated encrypted EOF.
Malformed/truncated streams and upstream error events never emit success.
Errors are fixed vocabulary; no tracing subscriber is installed.

One live synthetic adapter call passed with 36 input / 4 output tokens, cached
input 0 and authenticated completion (1,456 ms, not a latency benchmark).
The helper is **not yet embedded in any cloud image or wired to the gateway**.
Process isolation, authorized workspace derivation, bounded concurrency and AWS
TLS-only vsock egress remain serving-integration requirements.

## Dependency-scan blocker

The initial CI scan flags `block-buffer 0.10.4` under
[GHSA-qwgh-2vcv-g2f7](https://github.com/RustCrypto/utils/security/advisories/GHSA-qwgh-2vcv-g2f7).
The primary advisory lists the affected range as `>=0.11.0,<0.12.1`, whereas
the scanner's advisory data includes earlier versions. The SDK's SHA-2/HKDF
dependencies require the 0.10 line. Inspection of 0.10.4 shows a separate
`pos: u8` field, not the inline cursor targeted by the advisory; the other
resolved version, 0.12.1, is patched. This appears to be a version-range false
positive, but no suppression or scan bypass has been added. Resolve the advisory
data discrepancy or use a reviewed compatible dependency update before merge.

## Remaining release requirements

1. Record the remaining included allowance and confirm no automatic renewal;
   account identity, Pro expiry, reseller permission and API content-retention
   confirmation have been obtained. The operator key passes live probes.
2. Reproduce the front enclave PCR0 from approved source. Review its enforced
   downstream i02 worker release, GPU verification and model identity review and
   local positive/negative encrypted probes are recorded above. Independent
   front reproduction remains in progress, not yet an approved result.
3. Embed the SDK or hardened proxy **inside** the measured image. The standalone
   upstream proxy has a process-wide cache root; add TR workspace isolation.
   Preserve sandboxed process supervision, immutable pins and redacted failures.
   AWS needs an allowlisted TLS/vsock path for the SDK, not host-side decryption.
4. Reconcile actual Maple credit debits, including failed/partial responses and
   cached tokens. Published rates are USD 0.65/0.13/1.45 per million uncached
   input/cached input/output tokens; the offer adds whole-credit rounding and a
   USD 0.001 minimum. The exact rounding rule still needs confirmation.
5. Run all cloud build/test variants and the normal coordinated rollout with
   region-by-region health/attestation/inference checks. Provision cloud-local
   secrets without replacing unrelated entries. Keep a healthy holdback cloud.
6. Only after those gates, activate the control-plane model and qualified badges.

References: [proxy](https://maple.ai/docs/proxy),
[pricing](https://maple.ai/pricing), [terms](https://maple.ai/terms),
[privacy](https://maple.ai/privacy),
[wire contract](https://github.com/MaplePrivacyLabs/Maple/blob/c668d817dceec5c2e7390de7c68a581c88ea2eea/services/opensecret/docs/transport-v2-protocol.md),
[worker pins](https://github.com/MaplePrivacyLabs/Maple/blob/c668d817dceec5c2e7390de7c68a581c88ea2eea/services/opensecret/src/maple_inference.rs).
