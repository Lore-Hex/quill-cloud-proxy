# Maple pilot qualification

**Not deployed or customer-routable.** This change adds a qualification client,
one-shot encrypted adapter, measured-image build stages, dispatch and cloud-local
secret coordinates. No cloud image, secret bundle or public catalog is activated.
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

`enclave-go/maple-transport` source-pins Maple's Rust SDK at
`c668d817dceec5c2e7390de7c68a581c88ea2eea` and locks its dependencies. The
`prepare-sdk.sh` step verifies the full source archive SHA-256 before extracting
the SDK and applying `sdk-dependencies.patch`: only HKDF 0.12 to 0.13 and SHA-2
0.10 to 0.11 change. Transport, attestation and cryptographic protocol source is
unchanged. It uses
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
The downloaded EIF's GitHub/Sigstore attestation now verifies with both the exact
source digest and the expected release workflow identity constrained. This
authenticates the published artifact provenance, not an independent source rebuild.

An independent ARM64 Linux Nix build at the exact source and locked inputs
completed successfully, but produced PCR0
`8ce7b06eee78c7b067cf8657c72f826ebe5ef3a80d4f341e55e9449d795b4d88e9cbc4ecf5fef5243a670b9118724329`
and EIF SHA-256
`1f6ea511e63a211cf247190af75df27208e11a68a685a1ca2b1a49b3d89da242`.
PCR1 and PCR2 differ too. Both evaluations select the same Nix output path
`/nix/store/x4p7gxc5jmagz41l5pxgd699ni7m0z72-opensecret-eif-prod`;
the vendor workflow restored it from FlakeHub while the independent run built it.
The independent container used upstream Nix rather than the vendor's pinned
Determinate Nix 3.23.3, so this is a reproducibility discrepancy requiring
investigation, not proof of a malicious image. Do not substitute the new PCR0
for the live pin or claim independent reproduction passed.

The discrepancy was subsequently traced to Nix silently falling back to an
unsandboxed build when Docker refused its nested `/proc` mount. Checking only
`sandbox=true` was insufficient: `sandbox-fallback=true` embedded temporary
build paths instead of the vendor's `/build`. The new isolated builder uses
the exact pinned Determinate version, `sandbox=true`, `sandbox-fallback=false`,
and a preflight derivation that proves its build directory is `/build`.
No Maple/FlakeHub output cache is enabled. Its complete user initramfs now
matches the published artifact byte-for-byte at SHA-256
`dd6edd1895a87f425025f4ce4ff0f037a1ef4534ba3ea9b5a32979c6bef28234`.
The enforced-sandbox build completed on 2026-10-29. Its full 233,941,161-byte
EIF matches the published artifact byte-for-byte: SHA-256
`9702de6b825bb024d843fb840bf1c638ca7443bbd6ba49f93d14f6e6dfc60e23`.
PCR0 matches the approved pin above; PCR1 is
`a91689e37a54303051f68263010f397ddfa92d66e17df7a03a6777c33ff1e4fc12b69bbbe786894d43dcba1cf6d60aaa`
and PCR2 is
`a48fbff25a1920a7e982aa421cdfd94dd189e2c024b075048ad3f0b93b0fd67b82187d8c26d6e75e35772e742de05ed6`.
The independent kernel also matches at SHA-256
`06d3b4c1a7b3b0a9253a50c0baea3bc4ba0f791deb2e24abfdb752a1f3022740`.
The vendor's outer packaging script stopped after exporting the valid image and
measurements because the test container lacked `jq`; independent JSON parsing,
EIF structural/CRC validation and whole-file SHA-256 comparison verified the
exported artifacts. This is a successful image reproduction, not a successful
exit of that packaging wrapper. Neither result implies a TR production rollout.

```sh
sh enclave-go/maple-transport/prepare-sdk.sh
cargo test --locked --manifest-path enclave-go/maple-transport/Cargo.toml
cargo run --locked --manifest-path enclave-go/maple-transport/Cargo.toml -- attest
cargo run --locked --manifest-path enclave-go/maple-transport/Cargo.toml -- reject-pin
cargo run --locked --manifest-path enclave-go/maple-transport/Cargo.toml -- reject-key
# Supply MAPLE_API_KEY from the operator secret loader, never as a command argument.
cargo run --locked --manifest-path enclave-go/maple-transport/Cargo.toml -- probe
cargo run --locked --manifest-path enclave-go/maple-transport/Cargo.toml -- cache
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

## Bundled proxy source comparison

The front image also contains a checked-in `continuum-proxy` executable.
`flake.nix` copies it rather than compiling it, and `entrypoint.sh` starts it
in the enclave. Reproducing the EIF alone therefore does not establish the
source of every executable in that image.

The pinned public submodule is
[`4b72dcbbd58940835b5ba32502c1e247721b9584`](https://github.com/edgelesssys/privatemode-public/tree/4b72dcbbd58940835b5ba32502c1e247721b9584).
Two independent local `nix build --no-update-lock-file .#privatemode-proxy.bin`
runs produced the same SHA-256:
`0d6e3df6333045d61a7bfeaea480304ed2aae22b4d847deab2e543d0f8124790`.
The checked-in executable is
`e87aaefe7dfcddd46446d7a41874ed422aeee9ccdc2f75d4c69c22dbd36157ec`.
Both are static Linux ARM64 builds using Go 1.26.4 with identical reported
dependency versions and build settings. The raw hashes **do not match**.

ELF section comparison found identical executable `.text` (SHA-256
`bf1fc8ab424b10de8f5be57bd8f18909fd8e4cc5211218ec99c7fd72d3e3337d`),
runtime tables, build information and initialized data at the same addresses.
Differences in `.rodata` are limited to three Nix store hashes for
`tzdata-2026b`, `mailcap-2.1.54` and `iana-etc-20251215`; their path suffixes
are unchanged. The shipped binary also has Go/GNU build IDs and different
symbol stripping. This narrows the discrepancy to build metadata and data-file
paths in the inspected sections; it is not a byte-for-byte binary reproduction
or a replacement for completing the full front-image comparison.

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
All three multi-provider image recipes now source-build the static helper with
a locked dependency graph, and dispatch enters it before BYOK or generic HTTP.
These images are **not deployed**. The Go supervisor in `enclave-go/internal/maple`
adds:

- Credentials and request bodies over bounded stdin pipes, no command-line
  secrets or inherited provider environment; redacted subprocess failures.
- An explicit child-launch flag, dropped per-request UID/GID (65200-65231),
  cleared supplementary groups, no privilege gains and disabled core dumps.
  Ordinary startup never probes or closes inherited descriptors.
- At most 32 live children, a ten-minute request bound, cancellation/reaping and
  release of capacity only after the child exits. No automatic replay.
- Domain-separated cache roots from the server-authorized workspace scope;
  missing scopes use fresh independent roots.
- A second terminal gate withholding `[DONE]` until the authenticated helper
  stream ends and its process exits successfully.
- An AWS CONNECT tunnel allowing only `enclave.trymaple.ai:443`, forwarding
  opaque TLS through parent vsock port 8136. The deployment template includes
  this tunnel; ports 8132-8135 are reserved by the separate Bedrock
  Runtime work. No parent-host decryption is implemented.

The registered LLM adapter rejects BYOK, unpinned model
IDs, unsupported service tiers, embeddings and decision requests. Generic chat
and embedding helpers also reject Maple before any network request, including
provider overrides; resolving an ordinary HTTP client is forbidden. It preserves total input, cached subset and
output usage; and rejects missing finish/usage/terminal frames. Focused race
tests, the full LLM regression suite, and the AWS-tagged supervisor tests in a
network-isolated Linux container pass. A separate read-only scratch-image harness
with the actual launcher and static helper passed a live authenticated 401 using
a deliberately fake credential, with all capabilities dropped except SETUID and
SETGID and no privilege gains. This exercises the real per-request privilege drop
and attestation path, but is not a production rollout or a live AWS vsock test.

The same isolated Linux harness then completed one credentialed synthetic PONG
with 36 input and 4 output tokens in 1.50 seconds. Its API key arrived only on
stdin, the request used a fresh cache namespace, and completion required the
real helper's authenticated terminal frame and successful exit. Full race-enabled
Go suites pass for `cloud_gcp,llm_multi`, `cloud_aws,llm_multi` and
`cloud_azure,llm_multi`; 12 AWS parent bootstrap tests and the secret-source,
Azure bundle and vsock-map checks pass. These results do not assert production
deployment. The independent EIF discrepancy is resolved by the enforced-sandbox
reproduction above.

## Dependency-scan repair

The initial CI scan flags `block-buffer 0.10.4` under
[GHSA-qwgh-2vcv-g2f7](https://github.com/RustCrypto/utils/security/advisories/GHSA-qwgh-2vcv-g2f7).
The primary advisory lists the affected range as `>=0.11.0,<0.12.1`, whereas
the scanner's advisory data includes earlier versions. The SDK's SHA-2/HKDF
dependencies require the 0.10 line. Inspection of 0.10.4 shows a separate
`pos: u8` field, not the inline cursor targeted by the advisory; the other
resolved version, 0.12.1, is patched. No suppression or scan bypass has been added.
The candidate instead applies a two-line dependency-only patch to the exact SDK
source, selecting HKDF 0.13 and SHA-2 0.11, removing block-buffer 0.10 entirely.
The isolated upgraded SDK passed 122 unit tests, including backend key/record
vectors and tampered-attestation rejection; one upstream integration test remains
ignored because it requires the vendor's disposable backend. The workspace uses
one lockfile and runs SDK library tests alongside the TR relay tests. Required CI
and live encrypted regression results still govern promotion of this candidate.

## Remaining release requirements

1. Account identity, Pro expiry, reseller permission and API content-retention
   confirmation have been obtained. The operator key passes live probes. The
   unavailable remaining-allowance export is not an operator-approval blocker;
   do not purchase credits, renew a subscription or change payment settings.
2. Independent reproduction of the approved front enclave is complete, including
   exact EIF bytes and all three PCRs. The enforced downstream i02 worker release,
   GPU verification and model identity review and local positive/negative
   encrypted probes are recorded above. Preserve these immutable release pins.
3. Qualify all measured image builds and AWS TLS/vsock egress. The helper,
   explicit child entrypoint, dispatcher and deployment templates are wired;
   verify workspace isolation and process supervision in each exact release image.
   Preserve immutable pins and redacted failures.
4. Bill actual reported token usage at published rates: USD 0.65/0.13/1.45 per
   million uncached input/cached input/output tokens. On October 28 the operator
   instructed shipping without waiting for a debit export. Do not invent a
   rounding fee or USD 0.001 minimum on customer requests. The earlier pilot
   offer mentioned those provider debit rules, but the public rate page does not;
   provider-debit reconciliation remains unverified, not a user-input gate.
   Preserve normal billing-oracle, partial/error settlement and cache tests.
5. Run all cloud build/test variants and the normal coordinated rollout with
   region-by-region health/attestation/inference checks. Provision cloud-local
   secrets without replacing unrelated entries. Keep a healthy holdback cloud.
   Azure bundle `8df3ba4381d74315b2d1c696e63e839d` was sealed/uploaded on
   October 29, preserving all 83 names from `f397b1b83b324c11abf12a561296c02e`
   and adding only Maple (84 total). No serving container has switched to it.
   For the Maple rollout pin
   `QUILL_AZURE_BUNDLE_VERSION=8df3ba4381d74315b2d1c696e63e839d` and set
   `QUILL_MAPLE_SECRET=trustedrouter-maple-api-key`. Keep Hixtube, Privatemode,
   Telluvian and both System1 optional-secret settings; a dry run without
   Hixtube would omit an existing entry. Recheck for a newer bundle before use.
   `QUILL_MAPLE_SECRET` still defaults empty until this explicit measured opt-in.
6. Only after those gates, activate the control-plane model and qualified badges.

References: [proxy](https://maple.ai/docs/proxy),
[pricing](https://maple.ai/pricing), [terms](https://maple.ai/terms),
[privacy](https://maple.ai/privacy),
[wire contract](https://github.com/MaplePrivacyLabs/Maple/blob/c668d817dceec5c2e7390de7c68a581c88ea2eea/services/opensecret/docs/transport-v2-protocol.md),
[worker pins](https://github.com/MaplePrivacyLabs/Maple/blob/c668d817dceec5c2e7390de7c68a581c88ea2eea/services/opensecret/src/maple_inference.rs).
