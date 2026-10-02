# NEAR AI policy review, October 2, 2026

## Incident and scope

GLM 5.3 Flash changed its deployment history, engine, proxy and pool membership.
The September policy correctly rejected the unreviewed identities. A second
compatibility failure remained after updating those identities: the new proxy
extends RTMR3 with `nearai-replica-report-key-v1` after `system-ready`, which our
replay rejected. This release recognizes only that reviewed post-boot event;
it validates its public-key/ID/UUID payload and replays every byte into RTMR3.
Both signed CPU quotes must still match the complete event log.

No wildcard trust, automatic acceptance of discovered deployments, ordinary
HTTPS fallback, or changes to CPU/GPU verification are introduced. Other NEAR
model holds are untouched. The default Ethereum signing address in the provider
email is not used: our protocol requests Ed25519 plus live TLS SPKI binding.

## Evidence checked

Fresh reports used independent 32-byte nonces and the actual connected TLS
certificate's SHA256 SPKI fingerprint. Two observed instances:

| Instance | Compose SHA256 | Entire action-history SHA256 |
| --- | --- | --- |
| `19aea1693533dc2d529db03e3f725f20bde8d66d` | `55db164f4f8c6a837c2217c601c21bba4758f908536a6cd5b2978550205a9179` | `2dcf72f83422f8dc0d4994023eacf1637a95a26f52eb27989840b6d448652533` |
| `7bb9af0ac5b0e22dde3903218f58e56f743164a1` | `c82b1a2eaf6996154a5f39ae621643f034b082d5e51edd3d2ba6009273881d86` | `1e4aa300bb9f6c4d6665affbfd978fe1fffc04b29a9181febe2a5a03e0baf13b` |

Both manifest hashes were independently recomputed from `tcb_info.app_compose`.
Their base manifests differ only by `INSTANCE_LABEL=gpu03` versus `gpu04`.
Both retain the previously independently calculated dstack 0.5.11 boot pins in
[the September review](near-ai-policy-review-2026-09-11.md).
The retired `533e43fd...` compose is removed, not retained as another fallback.

The provider's email was already stale at capture time. Both signed histories
now end on `prod/GLM-5.3-Flash-SGL-TP2x4-W4AFP8.yaml` at
`ddec8d8c4f637d16884ca949e43c51582d8ed858` (v0.0.463), file SHA256
`5745db6b0d3e4a4f1ff6872acbf90da254ef83ca834c0bfd4cffb86f540ff781`.
gpu04 deployed all four engines at 2026-10-01 18:02 UTC from v0.0.462 with that
same file hash, followed by registrar/telemetry-only changes. gpu03's full
compose-up was 2026-10-02 04:52 UTC, after a brief GLM 5.2 rollback. Exact full
histories are retained as public test fixtures; later partial updates remain
review-gated even if the latest inference YAML is unchanged.

## Workload and provenance

Reviewed [deployment source](https://github.com/nearai/cvm-compose-files/blob/ddec8d8c4f637d16884ca949e43c51582d8ed858/prod/GLM-5.3-Flash-SGL-TP2x4-W4AFP8.yaml):

- Four local TP2 engines; no third-party inference backend.
- Weights: `graphistry/GLM-5.3-Flash-W4AFP8` revision
  `99f1fa70408c52b007d4fd69e02e5a522422e755`. This changes quantization from the
  former FP8 deployment; it is not merely a renamed compose file.
- Chat template revision `3f1971b7b5f7a528c9c4ef6212c8785298a8c24a`, 1,048,576
  context, offline model loading, request logging level zero.
- Engine: `nearaidev/sglang@sha256:47aff791090003a37f893e998c44794c410d3f7bdfc7fdd2dfab5eb5592b30bb`.
  Sigstore signature and GitHub build provenance verified against
  `nearai/cvm-compose-files`. [Build 36210851936](https://github.com/nearai/cvm-compose-files/actions/runs/36210851936)
  ran workflow revision `b996e382492b0b19e801d70b8d357e2c9d8160d1` with build
  context `aff61fca1798512dcaec8cc88756ee0f83bb78be`, also recorded in the image
  config and BuildKit provenance. These are signed provider builds on
  self-hosted runners, not independently reproduced images.
- Proxy: `nearaidev/vllm-proxy-rs@sha256:d61357da39918a57126864a451eaf054f06a6989c03fe9a1666f7e6374ba6907`.
  Signature and source-digest-constrained provenance verified against
  `nearai/inference-proxy` revision `0f37728af5387d4805a12db133662d769a679373`.
  The YAML comment referring to `2834196` is not its current build revision.
- HiCache uses the reviewed CUDA-owned host-memory path inside the CVM, with
  `SGLANG_HICACHE_RAM_BUDGET=325GiB` per replica. This budgeted path rejects an
  external storage backend; no disk/object-store cache backend is configured.
- The optional Redis publisher's reviewed report schema contains load counts,
  capacities and public host/key identifiers, not prompt or completion content.
  Its public telemetry key is separate from the inference response-signing key.
- Existing nginx/DCGM/OTel image digests remain unchanged. Diagnostic stack
  dumps report stacks, not local-variable values. The base management collector
  filters to management-service logs; inference request logging remains off.

## Verification and regression coverage

Local full-evidence checks passed for both instances: Intel production chain
and TCB, all eight NVIDIA H200 proofs, fresh nonce, TLS/signing-key binding,
compose-manager quote, independently pinned MRTD/RTMR0/1/2, replayed RTMR3, and
the exact reviewed deployment histories.

Eight real same-TLS-connection streaming PONG calls passed with the production
adapter and local real sidecar, covering both pool members. Observed end-to-end
test durations were 4.16-13.16 seconds, including verification and inference;
these are not throughput or TTFT measurements.

Offline fixtures test both histories, cross-host history rejection, future
telemetry-only deployment rejection, retirement of the old compose, malformed
telemetry keys, unknown/early/reordered/dropped post-boot events, and altered
RTMR3 on either CPU quote. Unit tests use explicit crypto doubles; only the
opt-in live tests establish actual cryptographic validity and inference.

Local gateway tests passed for `cloud_aws,llm_bedrock`, `cloud_aws,llm_multi`,
`cloud_azure,llm_multi`, `cloud_gcp,llm_vertex`, and `cloud_gcp,llm_multi`.
Full sidecar race tests passed with default, `cloud_aws`, and `cloud_gcp` tags;
sidecar `go vet ./...` also passed.

## Future updates

NEAR should provide exact source commits, immutable image digests, deployment
files, and signed histories for every pool member before it receives traffic.
We must review and test those identities, then deploy the verifier policy before
NEAR promotes the pool. A compose hash or shared signing key alone is insufficient.
Discovery and alerts can be automated; approval of new measured code must not be.
