# NEAR AI GLM 5.3 Flash re-pin review, November 16, 2026

## Decision

Approve gpu03 (instance `19aea169...`) exactly as observed on November 16:
compose `c900dc7304663b73b623cd5d941fbdab6f02858017b371ae28de445a16d2e2d0`
(unchanged), pinned file `prod/GLM-5.3-Flash-SGL-TP2x4-W4AFP8-V12Q8.yaml` at
`7d62ec67` (`08a56ab2...`, NEAR tag v0.0.593), complete history `6a66ec22...`
(280 actions). The November 12 history `e196ae72...` (271 actions) is
superseded.

The verifier code is unchanged. No wildcard, fallback, automatic acceptance or
relaxed check is added. Other NEAR models are untouched.

## Root cause

QCP #755 pinned gpu03's 271-action history, and quill-router #2546 released
the route to the GCP fleet at about 00:30 UTC on November 13. At 00:52 UTC NEAR
began redeploying the proxy and registrar on gpu03 (again on November 14), so
the quoted history stopped matching and every request failed closed with
"deployment history is outside the reviewed policy". The gateway answers
HTTP 502 for that route: Sentry QUILL-ROUTER-6S, with no successful
configured-route probe in either monitor region since.

| | Pinned (Nov 12) | Observed (Nov 16) |
| --- | --- | --- |
| Instance | `19aea169...` | unchanged |
| dstack OS | `91fd5d69...` | unchanged |
| MRTD / RTMR0 / RTMR1 / RTMR2 | `df4d77c8...` / `bc122d14...` / `4ae60980...` / `bd67ab75...` | unchanged on both quotes |
| `info.app_name` | `dstack-nvidia-0.5.11` | unchanged |
| Compose and app-compose bytes | `c900dc73...` | unchanged (byte-identical) |
| Runtime event log (RTMR3 replay) | 30 events | byte-identical: no reboot |
| History | `e196ae72...` (271) | `6a66ec22...` (280; the first 271 are byte-identical) |
| Pinned commit | `dfbb641f` (`2d10ba2c...`) | `7d62ec67` (`08a56ab2...`) |

## Evidence

Six reports were collected on November 16 from both DNS-advertised addresses,
three rounds each, each with its own random 32-byte nonce, Ed25519 signing and
the connection's SHA256 certificate SPKI. The attestation endpoint was called
without credentials. Every connection reached gpu03 with the same history; the
unreviewed small-models member noted on November 12 was not observed.

- On `main`'s policy, `TestLiveNearAIEvidence` fails all six reports with
  "NEAR AI deployment history is outside the reviewed policy", and
  `TestLiveNearAIPlatformEvidence` passes all six (Intel TDX quote chain and
  TCB, H200 NRAS proofs, nonce and TLS binding).
- On this policy, `TestLiveNearAIEvidence` passes all six.

## New deployment-log entries

The nine new actions (Nov 13 00:52Z to Nov 14 02:28Z) were each reviewed. Each
file was fetched from
[nearai/cvm-compose-files](https://github.com/nearai/cvm-compose-files) by
commit and hashes to its attested `file_sha256`:

| Tag | Commit | SHA256 | Actions |
| --- | --- | --- | --- |
| v0.0.581 | `77775074` | `39bacef1...` | stage, registrar down, `proxy-glm53` up, registrar up, `proxy-glm53` up |
| v0.0.593 | `7d62ec67` | `08a56ab2...` | stage, registrar down, `proxy-glm53` up, registrar up |

No engine, `otelcol-contrib`, nginx or downloader action was taken, and no
image other than the proxy changed in a redeployed service.

Serving state after the last action:

- `proxy-glm53` and `model-proxy-registrar` run `7d62ec67` (the pin).
- r1-r4 and `otelcol-contrib` run `dfbb641f` (`2d10ba2c...`), reviewed on
  November 12.
- nginx and `model-downloader` run `5a5119f7` (`309c07af...`).
- `rotate-token` and `glm53-soak-relay` are down.

## File diffs from the reviewed `2d10ba2c...`

Structural comparison of the parsed compose files:

- **v0.0.581 (`39bacef1`):** the only change is the proxy image, to
  `vllm-proxy-rs@sha256:60d08c20...`.
- **v0.0.593 (`08a56ab2`):**
  - The proxy image changes to `vllm-proxy-rs@sha256:c57cd9ea...`.
  - The proxy environment drops `FUSION_ENABLED` and
    `FUSION_INTERNAL_BEARER_TOKEN` (the Fusion feature is removed upstream).
    Every other proxy variable, including `VLLM_BACKEND_URLS` (only the four
    local replicas), is unchanged.
  - The engine anchors gain `cap_drop: [ALL]` and
    `no-new-privileges:true` and drop `HF_TOKEN`; their labels gain
    `-restricted-env`. Engine image, argv and weights are unchanged. These
    engine changes are not deployed: no engine action follows them.
  - The verification-profile `glm53-soak-relay` service is removed. It has
    been down since October 19.
  - Most of the file's comments are removed.

## Image provenance

Each new proxy image was checked with `cosign verify` and `cosign
verify-attestation --type slsaprovenance1` (cosign v3.1.4), requiring a
Fulcio certificate from a `github.com/nearai` workflow and the GitHub Actions
OIDC issuer:

- `nearaidev/vllm-proxy-rs@sha256:c57cd9ea8374fa9134b9b79ede199f21d134dd710826ac94dead4bbf381f57df`
  (serving)
  - Built by `nearai/inference-proxy` `.github/workflows/build.yml` on
    `refs/heads/main`, push event, GitHub-hosted runner.
  - Source `3f7e979827065848bd26b71a85a40f29c2d27a60`, run 43520236074.
- `nearaidev/vllm-proxy-rs@sha256:60d08c207b285697f39e134533081eac7006739ec5019c89c2f4c67869062f45`
  (superseded; served November 13 to 14)
  - Same workflow.
  - Source `ac1ef48bebd2f2d5edb7df89e2884256a05119f5`, run 43294286081.

Same repository, workflow, branch and issuer as the reviewed `e2893ff4...`
(source `73a0d882`). These remain signed provider builds, not independently
reproduced images.

## Proxy source review

The eleven commits from the reviewed `73a0d882` to `3f7e9798`:

- dependency updates, including the crypto majors, with libsodium wire vectors
  for Ed25519 signing and X25519/XChaCha20-Poly1305 decryption (#348), and a
  patched `quinn-udp` (#373);
- SSE and assembled responses decode a UTF-8 character split across chunks
  instead of failing or replacing it (#360, #361);
- one metadata log line per request that otherwise has none: request id,
  tenant ids already on the completion line, route template, status, sizes
  and timings. No body, prompt or path text (#368);
- a request guard that bounds sampling fields, media URL schemes and
  structured-output regexes and removes engine-internal keys before the
  engine (#369), and refusal of unknown multipart fields (#372);
- direct API keys require complete billing identity and billable usage;
  rerank limits; the server-side Fusion path and its configuration are
  removed (#374);
- CI and contributor-policy changes in NEAR's repository (#357, #359, #370).

The E2EE changes reject small-order Ed25519 client keys and fail a request
whose encrypted field or tool parameters do not decrypt, instead of passing
ciphertext through. Error logs drop raw error text in favor of fixed kinds.
No new outbound host was added. The signing and attestation routes change only
in comments and test vectors.

## Tests

- A new fixture binds the complete 280-action history. The event log and
  app-compose fixtures from November 12 still apply (no reboot), so the pool
  harness reads boot evidence from the November 12 fixture and history from
  the November 16 one.
- The reviewed-sources test checks each serving service against its exact
  reviewed source, and that `rotate-token` and `glm53-soak-relay` stay down.
- Regression tests reject the November 12 history, plus the existing
  November 6, cross-host, October and appended-action histories.
- Reverting any one of the three pin values (commit, file hash, history hash)
  to its November 12 value makes the NEAR suite fail.
- Sidecar `go vet` and `go test -race` pass with `cloud_aws`, `cloud_gcp`,
  `cloud_azure` and no tags.

Not run: `TestLiveNearAIDirectAttestedPong`. It needs a NEAR inference key,
and this review used none.

The history pin stays deliberately strict: any further action on gpu03 fails
closed again until reviewed.
