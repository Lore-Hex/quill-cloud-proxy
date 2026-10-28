# Maple pilot qualification

**Not deployed or customer-routable.** This change adds a qualification client,
not a serving adapter. The paired control-plane provider remains internal-only,
with Credits, BYOK, ZDR and confidential/E2EE eligibility all disabled.

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
```

Only `probe` uses the account key and paid inference: one discovery, one JSON
and one SSE synthetic PONG request, each capped at 1,024 output tokens. Inference
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
- Both completed responses reported zero cached input. Cache-hit behavior,
  account-debit reconciliation and the complimentary grant remain unverified.
- Local Claude CLI Opus review was attempted but OAuth refresh failed. No private
  Claude API key was substituted and no successful review is claimed.

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

1. Confirm the dedicated account identity and non-renewing complimentary Pro grant.
   The operator's key now passes the live discovery/inference probes. Confirm reseller terms
   and strict API content-retention terms; the public terms alone do not establish them.
2. Reproduce the front enclave PCR0 from approved source. Review its enforced
   downstream i02 worker release, GPU verification and model identity. Validate
   changed-pin and wrong-key rejection, then real encrypted inference.
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
