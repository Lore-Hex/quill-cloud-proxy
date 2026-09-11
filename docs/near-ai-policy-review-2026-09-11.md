# NEAR AI policy review, September 11, 2026

Public source: https://github.com/nearai/cvm-compose-files

The release adds two exact GLM 5.3 Flash pool members, not an authority to accept
arbitrary reports or provider-asserted verification. Both use production
`dstack-nvidia-0.5.11`; its digest was independently read from the official
[dstack release archive](https://github.com/Dstack-TEE/meta-dstack/releases/tag/v0.5.11):
`a6eafc5f007f642d8ea90c7fa8881f1e6715720ccb531941a28218f4f26d7b02`.
The archive metadata declares `is_dev=false`, git revision
`ce04e924e17e3cb9d38d258338cbe71e8c08d575`.

## Reviewed workload

- File: `prod/GLM-5.3-Flash-SGL-TP4.yaml` at
  `e14107901d202215ab44eb027eb4792047d5ec83`, SHA256
  `2878b9c4c6db512a7538dc4e8981fd5acae72cdaace7794509f48161bcce08e3`.
- Both engines last deployed from `676532b98f9a01da5d43f98299af297b573d242d`;
  source-file hash `e5d80ab6e1a1188fdf8cd3e7bc2f74da5d4767da15b0644acf07dad08a3b461b`.
  Image `nearaidev/sglang@sha256:a7b7136abcf5e07522289d96e96fec9b42a1a30f9dfda57e957f142680d2d67b`.
- Weights revision `84c6a6aa9497188e15a635ba793b0f95a79b1033`, chat-template
  revision `3f1971b7b5f7a528c9c4ef6212c8785298a8c24a`; offline loading enabled,
  1,048,576 context, request logging disabled in the serving command.
- Proxy image `nearaidev/vllm-proxy-rs@sha256:98b57ad7aa4f9afd8ffff3ac9f4773303997f667e1d221be076c2f064e4a1284`.
  Backends are the two local model services, not third-party inference URLs.
- nginx image `sha256:1d13701a5f9f3fb01aaa88cef2344d65b6b5bf6b7d9fa4cf0dca557a8d7702ba`;
  TLS terminates in the measured workload. CPU quotes bind the live TLS SPKI and nonce.
- Both compose identities and their independently quoted action histories are
  pinned in `near_ai_policy.json`. Pinning just the latest file action was
  insufficient: it could update only telemetry while older engines remained.

## Verification

Fresh direct evidence passed Intel production chain/TCB verification, eight H200
NVIDIA proofs, model/key/nonce/TLS binding, compose-manager quote and deployment
pins. Three real streaming PONG tests passed through the unchanged same-TLS-
connection adapter, covering both GLM pool members: 3.65, 7.23, 4.23 seconds.

DeepSeek's captured CPU/GPU evidence and migration deployment passed, but later
TLS handshakes failed; the control-plane manifest keeps it held. Three Qwen
hosts report an `OutOfDate` TDX module and remain blocked, not repinned.

The action-history pin is deliberately strict: later changes must be reviewed.
The companion control-plane release adds sustained-failure and catalog-expiry
Sentry alerts so fail-closed drift is actionable instead of silent.
