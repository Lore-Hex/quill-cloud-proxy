# NEAR AI GLM 5.3 Flash re-pin review, November 6, 2026

## Decision

Approve the two current GLM 5.3 Flash pool members exactly as observed on
November 6: gpu03 compose `a0e3c6f4...` and gpu04 compose `5f7ebd85...`, both
booted on `dstack-nvidia-0.5.12`. Retire the October composes `55db164f...`
and `c82b1a2e...`. Their instances still exist but no longer report them.

The verifier is unchanged. No wildcard, fallback, automatic acceptance or
relaxed check is added. Other NEAR models and holds are untouched.

## Root cause

TrustedRouter has held `near-ai` / `z-ai/glm-5.3-flash` since October 15. On
October 12, NEAR deployed the v0.0.484 KDA canary to gpu03 r4. That appended an
action to the quoted deployment history. Every request then failed closed with
"deployment history is outside the reviewed policy".

The drift then grew well beyond one appended action:

| | Pinned (Oct 9) | Observed (Nov 6) |
| --- | --- | --- |
| dstack OS | 0.5.11, `a6eafc5f...` | 0.5.12, `91fd5d69ccee3e5ea4f2aeb8c9b632c4358c4ecfc29ba1aa6fb1e402af209829` |
| MRTD / RTMR0 | `df4d77c8...` / `bc122d14...` | unchanged |
| RTMR1 | `ff61e68f...` | `4ae609807c765916a31d724786ed74bcb97e168a9d937b04936aeef2015c907eba5ac352c6bcd749c246fd62ffb659ec` |
| RTMR2 | `4d662c04...` | `bd67ab7554dc27ab03a077bc1447a1a67d0624ff547c4c809a8626f12d6a89712f8ec60e781e99b98208574065d21a71` |
| gpu03 compose / history | `55db164f...` / `232ae6c9...` | `a0e3c6f4f21a60ea3f5c96bc7ef319b03a184ca2049605399275fbcea74e8c5f` / `4f6a87d47b9584343a5484bb456ca1dfe8d678379855fead236caf8e0289d82e` |
| gpu04 compose / history | `c82b1a2e...` / `281432886...` | `5f7ebd85cf1f480a118f75dd10fd0cb277e4ddbb23845f1c20d8ea0f1e87efa6` / `641a324566305d1771de6784003e3967dad18988c74274b974066573e3b9af49` |

The instance IDs are the same as in October: `19aea169...` for gpu03 and
`7bb9af0a...` for gpu04. `info.app_name` is still `dstack-nvidia-0.5.11`. That
field is the app-compose `name`, not the OS. `vm_config.image` reports
`dstack-nvidia-0.5.12`. The VM shape is unchanged: 64 vCPU, 2 TiB, 8 GPUs,
4 NVSwitches, QEMU 9.2.1 and `pre202505` OVMF.

## Evidence

Fresh reports were collected from both DNS-advertised addresses
(`160.72.54.150` and `40.160.65.237`). Each used its own random 32-byte nonce,
Ed25519 and the connection's SHA256 certificate SPKI. The attestation endpoint
was called without credentials. Two captures about ten minutes apart had
identical histories. The fixtures in `testdata/near-ai-2026-11-06/` are those
public action logs and event logs.

## Hardware root and OS build

- `TestLiveNearAIEvidence` passes for both members with this policy. It checks
  the Intel TDX quote chain and TCB, all eight H200 NRAS proofs, model, nonce,
  signing key and TLS binding, the compose-manager quote, the boot pins and
  RTMR3 replay. It fails on `main`'s policy with "workload identity is outside
  the pinned policy".
- The OS archive came from the
  [meta-dstack v0.5.12 release](https://github.com/Dstack-TEE/meta-dstack/releases/tag/v0.5.12):
  `dstack-nvidia-0.5.12.tar.gz`, SHA256 `b89d7875...`, matching the GitHub asset
  digest. Every file matches `sha256sum.txt`. SHA256 of `sha256sum.txt` is
  `91fd5d69...`, the reported `os_image_hash`. `metadata.json` declares
  `is_dev=false`, git revision `7f7b2762d4353943eb2c004d89025977794d7d24` and
  `ovmf_variant: pre202505`.
- RTMR1 and RTMR2 were recomputed offline from that archive's `bzImage`,
  `initramfs.cpio.gz` and cmdline. The computation reimplements dstack-mr
  v0.5.12 (`dstack-mr/src/kernel.rs`, `util.rs`): QEMU kernel patching,
  Authenticode SHA384 and the UTF-16 cmdline with `initrd=initrd`. Both
  registers match the quotes exactly, and the old 0.5.11 values do not. RTMR0
  needs the patched-QEMU ACPI dumper, so it was not recomputed. MRTD and RTMR0
  equal the values independently calculated in September, which pins the same
  firmware and VM shape. The release says OVMF, cmdline and RTMR layout are
  unchanged.
- RTMR3 is still replayed from the event log. The only post-boot events are the
  reviewed `nearai-replica-report-key-v1` events.

## Workload

Both base manifests were recomputed from `tcb_info.app_compose`. They differ
from each other only in `INSTANCE_LABEL=gpu03` versus `gpu04`. Every image is
pinned by digest. The default compose-manager image is
`6e035c8f...` (`nearai/compose-manager` `8cf272a6`). The October manifests were
not archived, so the base-manifest delta itself cannot be diffed.

The launcher swapped compose-manager to images signed by
`nearai/compose-manager` workflows, with SLSA provenance:

- `a320bb48...` from `be649f88`, on October 29.
- `a0c07308...` from `c7fbaaf5`, on November 4.

That launcher dates from May 2026, and the September histories already contain
such a swap (`bc44e44e...`). Commits between `8cf272a6` and `c7fbaaf5` cover
TLS on the API port, eMudhra distrust, multi-token auth and input hardening.
None of them changes action-log semantics. The history stays continuous across
the swaps.

Every deployment file in the post-October-9 histories was fetched by commit
from [nearai/cvm-compose-files](https://github.com/nearai/cvm-compose-files).
Each one hashes to the attested `file_sha256`. These are the serving sources:

- **gpu03:** engines r1-r4 and OTel run
  `prod/GLM-5.3-Flash-SGL-TP2x4-W4AFP8-V12Q8.yaml@7ee4a4c7` (`904054f5...`).
  `proxy-glm53` runs the same file at `5a5119f7` (`309c07af...`). This is the
  policy pin. nginx and the registrar run the V8KdaCanary file at `8977a0e8`.
  DCGM and the ghost aggregator come from the V8KdaCanary whole-file up at
  `6b8c3b19`. That file differs from the reviewed v7 file only in its
  proxy image and its later-replaced r4 image.
- **gpu04:** r1-r3 run V12Q8@`7ee4a4c7`. The long-context replica `l4`,
  `proxy-glm53`, `proxy-glm53-long`, nginx, the registrar and OTel run
  `prod/GLM-5.3-Flash-SGL-TP2x4-W4AFP8-V12Q8-gpu04-3B1L.yaml@410345d5`
  (`6ce091c9...`). This is the policy pin. Base r4 is stopped. The rest comes
  from the reviewed v7 bytes (`a49d9c15...`).

Compared with the October 9 v7 file:

- The engine image changes from `fa730e6e...` to
  `nearaidev/sglang@sha256:da8d4e4b5ec667499b58a21e56050aae9bcfc4df9669b3ac27e2e20af033d681`.
  It has a Sigstore signature and SLSA provenance from
  `nearai/cvm-compose-files` `publish-glm53-admission-reserve.yaml`, source
  `79de066b`, run 39987811670.
- `--dsa-prefill-backend` changes from `flashmla_kv` to `flashmla_sparse_q8`.
- The proxy changes to
  `nearaidev/vllm-proxy-rs@sha256:0be4ee8f40a2bf71a6e2fab1e780ad1a6e738ffb2085553f1ed4b85fcb944207`
  (`nearai/inference-proxy` `53d79441`, run 41651768480). The superseded
  `e4a42b32...` was built from `f18298f4`. Both have verified signatures and
  provenance. The 33 commits since the reviewed `0f37728a` cover gateway tiers,
  priority, usage-report transport (SQS/HTTP), RustSec, eMudhra and E2EE reply-key
  authentication.
- gpu04 adds the l4 long-context replica. It uses the same weights and template
  revisions, 16K chunks and HiCache through the reviewed in-CVM host-memory
  `direct` path, with no storage backend. It is served on a separate
  `glm-5-3-flash-long` vhost. This policy does not pin that domain.
- Weights `graphistry/GLM-5.3-Flash-W4AFP8@99f1fa70`, chat template `3f1971b7`,
  `--log-requests-level 0` and local-only backends are unchanged. These remain
  signed provider builds, not independently reproduced images.

## Tests

- New fixtures bind both complete histories and check each serving service
  against its reviewed source.
- Regression tests reject:
  - every October history for either host and cross-host histories;
  - an appended telemetry-only action;
  - the retired composes;
  - the 0.5.11 OS hash;
  - 0.5.11 RTMR1 or RTMR2 on either quote.
- Sidecar `go build`, `go vet` and `go test -race` pass with `cloud_aws`,
  `cloud_gcp`, `cloud_azure` and no tags.

Not run: `TestLiveNearAIDirectAttestedPong`. It needs a NEAR inference key, and
this review used none. Run it as the release-qualification step.

The history pins are deliberately strict. Any further NEAR action on either
host before rollout fails closed again. Re-capture right before merging, and
re-run `TestLiveNearAIEvidence`.
