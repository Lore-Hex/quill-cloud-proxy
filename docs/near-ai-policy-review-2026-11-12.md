# NEAR AI GLM 5.3 Flash re-pin review, November 12, 2026

## Decision

Approve gpu03 (instance `19aea169...`) exactly as observed on November 12:
compose `c900dc7304663b73b623cd5d941fbdab6f02858017b371ae28de445a16d2e2d0`,
pinned file `prod/GLM-5.3-Flash-SGL-TP2x4-W4AFP8-V12Q8.yaml` at `dfbb641f`
(`2d10ba2c...`, NEAR tag v0.0.567), complete history `e196ae72...` (271
actions). Retire the November 6 composes `a0e3c6f4...` (gpu03) and
`5f7ebd85...` (gpu04). Instance `7bb9af0a...` (gpu04) no longer answers on the
domain.

The verifier code is unchanged. No wildcard, fallback, automatic acceptance or
relaxed check is added. Other NEAR models are untouched.

## Root cause

QCP #720 pinned gpu03's 226-action history. On November 8 NEAR resumed
deploying to gpu03, so the quoted history stopped matching and every request
failed closed with "deployment history is outside the reviewed policy". On
November 12 gpu03 also booted a new base manifest, which changed its compose
hash. TrustedRouter re-held the route in quill-router #2517.

| | Pinned (Nov 6) | Observed (Nov 12) |
| --- | --- | --- |
| dstack OS | `91fd5d69...` | unchanged |
| MRTD / RTMR0 / RTMR1 / RTMR2 | `df4d77c8...` / `bc122d14...` / `4ae60980...` / `bd67ab75...` | unchanged on both quotes |
| `info.app_name` | `dstack-nvidia-0.5.11` | unchanged (`vm_config.image` is `dstack-nvidia-0.5.12`) |
| gpu03 compose | `a0e3c6f4...` | `c900dc73...` |
| gpu03 history | `4f6a87d4...` (226) | `e196ae72...` (271; the first 226 are byte-identical) |
| gpu03 pinned commit | `5a5119f7` (`309c07af...`) | `dfbb641f` (`2d10ba2c...`) |
| gpu04 | `5f7ebd85...` | not observed |

The VM shape is unchanged: 64 vCPU, 2 TiB, 8 GPUs, 4 NVSwitches, QEMU 9.2.1
and `pre202505` OVMF. The KMS key-provider public key is unchanged. The
`mr-kms` runtime event changed from `6a64e679...` to `22a6652c...`; it also
changed between October and November 6, it is replayed into RTMR3 like every
runtime event, and it is not a policy pin.

## Unreviewed pool member

The DNS name now also routes some connections to a different CVM: instance
`a8a25faa...`, compose `e8416a02...`, `app_name` `dstack-nvidia-0.5.12`, with a
156-action history whose active file is `prod/small-models.yaml`. It is a
shared small-models host that runs a `proxy-glm53` service among other models.
It is not reviewed, is not pinned and fails closed with "workload identity is
outside the pinned policy". The client already treats a mixed pool this way:
it discards that connection and re-attests a new one with a fresh nonce
before sending any prompt. A regression test keeps `e8416a02...` ineligible.

## Evidence

Reports were collected from both DNS-advertised addresses (`160.72.54.150` and
`40.160.65.237`), each with its own random 32-byte nonce, Ed25519 and the
connection's SHA256 certificate SPKI. The attestation endpoint was called
without credentials. Six capture rounds between 16:43Z and 16:52Z returned
the same gpu03 history every time it answered (8 of 12 connections). The
other 4 reached the unreviewed member below. The fixtures in
`testdata/near-ai-2026-11-12/` are the public action log, event log and
app-compose.

## Hardware root and OS build

- `TestLiveNearAIEvidence` and `TestLiveNearAIPlatformEvidence` pass on fresh
  gpu03 reports with this policy. They check the Intel TDX quote chain and
  TCB, all eight H200 NRAS proofs, model, nonce, signing key and TLS binding,
  the compose-manager quote, the boot pins and RTMR3 replay.
- The same gpu03 reports fail on `main`'s policy with "workload identity is
  outside the pinned policy". The small-models report fails on this policy
  with the same error.
- MRTD and RTMR0-2 are identical to the values recomputed for the November 6
  review, so the OS archive analysis there still applies.
- RTMR3 replays from a fresh boot: the standard dstack events, compose hash
  `c900dc73...` and OS image `91fd5d69...`. No replica-key event has been
  recorded since this boot.

## Base manifest

`sha256(tcb_info.app_compose)` equals `c900dc73...`, and the quote's
`mr_config_id` binds it. The November 6 manifest was not archived, so a byte
diff is not possible; this one is archived as `c900dc73-app-compose.json`.
Its contents:

- `INSTANCE_LABEL=gpu03`, KMS enabled, local key provider and gateway
  disabled, `public_logs=false`.
- compose-manager defaults to
  `nearaidev/compose-manager@sha256:a0c073085684...`. That is the November 4
  image (`c7fbaaf5`) that the November 6 review already verified and that the
  launcher was already running. The pre-launch override branch is disabled.
- compose-manager-launcher `079a14b4...` still restricts swaps to cosign
  identities from `nearai/compose-manager` workflows.
- `otelcol-management` runs
  `otel/opentelemetry-collector-contrib@sha256:85ac41c2...`, the same digest
  as the reviewed `otelcol-contrib` service. Its measured config exports only
  the compose-manager, launcher and dns-cloudflare logs, plus host and Docker
  metrics, to `telemetry.infra.near.ai`. The model files already exclude this
  service from their own pipelines. Engines keep `--log-requests-level 0`.
- certbot images are digest-pinned. Every image in the manifest is pinned by
  digest.

## New deployment-log entries

The 45 new actions (Nov 8 02:01Z to Nov 12 08:55Z) were each reviewed. Every
file was fetched from
[nearai/cvm-compose-files](https://github.com/nearai/cvm-compose-files) by
commit and hashes to its attested `file_sha256`:

| Tag | Commit | File | SHA256 | Services |
| --- | --- | --- | --- | --- |
| v0.0.541 | `5a5119f7` | V12Q8 | `309c07af...` (Nov 6 pin) | dry, registrar, nginx, proxy, model-downloader |
| v0.0.550 | `132912c5` | rotate-compose-manager-token | `3154095b...` | rotate-token up then down |
| v0.0.553 | `4d64477b` | V12Q8 | `e88b040e...` | proxy-glm53, registrar |
| v0.0.554 | `fe7493ee` | V12Q8 | `e88b040e...` | r1-r4, registrar, proxy, otel |
| v0.0.554 | `fe7493ee` | rotate-compose-manager-token | `3154095b...` | rotate-token up then down |
| v0.0.564 | `121706c2` | V12Q8 | `5f25d2fb...` | r4 canary, otel |
| v0.0.567 | `dfbb641f` | V12Q8 | `2d10ba2c...` | r1-r4, otel, proxy-glm53 |

The remaining actions are `docker_restart` of nginx and three
`compose_manager_started` events. All three report the reviewed
`a0c07308...` image. Two follow the token rotation and one follows the
November 12 boot.

The token rotation file runs `docker:27-cli@sha256:851f91d2...` with no
network, all capabilities dropped and a read-only root. It rewrites
compose-manager's `BEARER_TOKEN` and recreates the same compose-manager
container. It changes no image.

Serving state after the last action:

- r1-r4, `otelcol-contrib` and `proxy-glm53` run `dfbb641f` (the pin).
- `model-proxy-registrar` runs `fe7493ee` (`e88b040e...`).
- nginx and `model-downloader` run `5a5119f7` (`309c07af...`).
- `rotate-token` is down.

## File diffs from the reviewed `309c07af...`

- **v0.0.553 / v0.0.554 (`e88b040e`):**
  - The proxy image changes to `vllm-proxy-rs@sha256:7a295d6f...`.
  - The proxy `TOKEN` also accepts `PROXY_TOKEN_NEXT`, for token rotation.
- **v0.0.564 (`5f25d2fb`):**
  - The proxy image changes to `vllm-proxy-rs@sha256:e2893ff4...`.
  - The r4 canary moves to `nearaidev/sglang@sha256:050b1adf...` (SGLang
    v0.5.23), with the same argv plus `--cuda-graph-backend-prefill
    disabled`.
- **v0.0.567 (`2d10ba2c`):**
  - All four engines move to `050b1adf...` with that argv.
  - The proxy enables inline media: it downloads remote image and audio URLs
    and forwards `data:` URLs. Video parts are refused.
  - The ghost aggregator stays on the reviewed v12 image `da8d4e4b...`.

Weights `graphistry/GLM-5.3-Flash-W4AFP8@99f1fa70`, chat template `3f1971b7`,
`--log-requests-level 0` and in-CVM backends (`VLLM_BACKEND_URLS` names only
the four local replicas) are unchanged. Compared with `309c07af`, the only new
image digests in the file are the engine and proxy below.

## Image provenance

Each image was checked with `cosign verify` and `cosign verify-attestation
--type slsaprovenance1` (cosign v3.1.4). The checks require a Fulcio
certificate from a `github.com/nearai` workflow and the GitHub Actions OIDC
issuer:

- `nearaidev/sglang@sha256:050b1adf961c8621264d14696d24645f70d1a675509ad400a72ccfb1a3fddcb2`
  - Built by `nearai/cvm-compose-files` `.github/workflows/publish-glm53-v0523.yaml`
    on `refs/heads/main`.
  - Source `2cf337c2c5fc3fa78570a5ae0e3dd432abaefde8`, run 43123926071.
- `nearaidev/vllm-proxy-rs@sha256:e2893ff46404d112bc39c9e77de6c20f6a889227f99a49f7190bff5b2063d441`
  (serving)
  - Built by `nearai/inference-proxy` `.github/workflows/build.yml` on
    `refs/heads/main`.
  - Source `73a0d882cdc5c3acb1ce5c583fbd1ea6a8e412c0`, run 43104109670.
  - The six commits since the reviewed `53d79441`:
    - gateway list mode (#340);
    - restricting OHTTP inner requests to inference routes (#342);
    - logging rejected OHTTP requests without the raw path (#344);
    - workflow hardening (#347);
    - inline remote image and audio (#349);
    - GitHub-hosted runners (#358).
- `nearaidev/vllm-proxy-rs@sha256:7a295d6f746e7434c6f05a02a68fed171f320a3d57cbaedef38d1a9465bb327e`
  (superseded; it served between November 8 and 12)
  - Same workflow.
  - Source `7924418b5eacb396a12ada208b0f2f0c82ec6d1d`, run 42519871092.

These remain signed provider builds, not independently reproduced images.

## Tests

- New fixtures bind the complete gpu03 history and check each serving service
  against its reviewed source.
- Regression tests reject:
  - the November 6 gpu03 history (superseded);
  - the November 6 gpu04 history (cross-host);
  - the October history;
  - an appended telemetry-only action;
  - the retired November 6 and October composes, and the unreviewed
    small-models compose;
  - the 0.5.11 OS hash;
  - `app_name` `dstack-nvidia-0.5.12`;
  - 0.5.11 RTMR1 or RTMR2 on either quote.
- Replica-key rules are exercised by appending this instance's two November 6
  replica-key events and re-binding RTMR3.
- The tests were checked by mutating the pinned commit, the history hash and
  the app name, and watching them fail.
- Sidecar `go build`, `go vet` and `go test -race` pass with `cloud_aws`,
  `cloud_gcp`, `cloud_azure` and no tags.

Not run: `TestLiveNearAIDirectAttestedPong`. It needs a NEAR inference key,
and this review used none.

The history pin is deliberately strict. NEAR deployed four times on November
12 alone, so any further action on gpu03 before or after rollout fails closed
again.
