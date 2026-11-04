# Privatemode v1.62 deployment review

Status: independently reproduced policies and security-component images; local
encrypted qualification passed. Operator approval and regional production
deployment are still required. Approval of Chutes does not approve this update.

## Root cause and scope

The provider replaced immutable deployment `continuum-e8a714` with
`continuum-012cc6`. The production v1.61 manifest rejects the new deployment
with HTTP 401 and the fixed diagnostic `attestation_manifest_mismatch` before
inference. The credential is valid. No plaintext fallback, runtime pin refresh,
OCSP exception, or hardware-policy relaxation is proposed.

The earlier GLM warning retained only `upstream_4xx`. Do not retroactively
attribute all historical events to this later manifest change. A separately
reproduced adapter defect rejected GLM reasoning-off settings locally; its
eight red-before/green-after regression cases accompany the candidate.

## Immutable inputs

- Public source v1.62.0: `6b643fcec2145842745d0baf7df1176b5f0e65a5`.
- Archive SHA-256: `f18d23309dcacfb4d6322b0bf6b899392437c4ebfc1a419109f04a5483c9d608`.
- Proposed manifest SHA-256: `ac2bb4c5dc2aba45bdff1a7f44b8e9ad2f2b4666c5957f54d9a821ac596dca40`.
- Previous manifest: `cb8fe2f3b8973b8d12f99c3340d4102c642e6be40e26c2a9070e1a630e420bab`.
- Contrast v1.26.0 CLI: `fe4fcac0cd81e7385a59b923a20dc41fdd1e01cbd2073caa45b6038bf91dbae3`.
- Go 1.27.3 builder index: `sha256:d9b6a1beb9474adc2a1ce842573639b44b2a0dd49b6669f51d3821baf9ec37c9`.
- Hardened Linux amd64 client: `50056ded28f2b0b60904b1146587c1173c3bd9967a0bc26dc5adda42b7578d5f`.

Only the Privatemode client build stage moves to Go 1.27, required by upstream.
The gateway build toolchain is unchanged. The client retains the bounded
control-plane patch, explicit checksum-verified x/net override, module checksum
verification, and MIT license. It is built from source, not a vendor binary.

## Independent reproduction

Policy build `456b0c12-78a9-4d4b-842f-349b143d500f` used the same pinned Contrast
command and adjustment procedure documented for v1.61, with the secret-service
SANs changed to namespace `continuum-012cc6`. All eight generated policies match
the live manifest exactly. After excluding the unserved Milan reference entry,
the generated document matches except for deployment-specific
`SeedshareOwnerPubKeys`. No generated hash was copied from the live manifest.

- Raw generated manifest: `2cb3ac20f9b105e64782d89ec2941dc100f7af063495fc3da2a2c2c2f583b22c`.
- Adjusted manifest: `a4d32aa84077fb8ff241f226d5e4524896a93b1cb1a9ac6086a01fb1e2539380`.
- Public-source build evidence: `gs://44325983244.cloudbuild-logs.googleusercontent.com/privatemode-policy-audit/456b0c12-78a9-4d4b-842f-349b143d500f/`.

Image build `cd73239a-484f-434a-8bb6-e76bc418941e` used pinned Nix 2.31.2,
disabled vendor flake-cache configuration, and allowed only cache.nixos.org.
All five deployed security-component image digests reproduce exactly:

| Component | OCI SHA-256 |
| --- | --- |
| attestation-agent | `d11ffc5803e3038732ae028dfbba0a2e6891d182c1e8babd7eb673fc11a24969` |
| disk-mounter | `f66f2ea5feb4a39ec4f8ec1e464e7d911ee2f67ef468603cb80fbcbf341ec931` |
| inference-proxy | `caec5dc38b21090b04edcea5353598ab36da388832016df0a18cea42e210b4ae` |
| kernel-log | `5fcfe330f423e8affe61826875dd046ee31aa69905dc90a9b3434f9ea9042869` |
| secret-service | `d1273ce2d400dd9ab63897839734270e2615b2c1c973bc062417e9abf1171f50` |

The upstream client OCI digest is
`b2d564aa5f51dfc3cee60424108ca3de1ed0b5349d67e7eac7efe17e62d68d5b`;
its Nix binary hash is
`42d4652576067ae02eba8e3231bc04d055cd9d31c750eaeb38b8114a4f1eb0b8`.
These are independent provenance artifacts, not the hardened client above.
Image evidence is retained under the same bucket's `privatemode-image-audit/`
prefix and build ID.

## Security and privacy review

The hardware reference values are byte-for-byte structurally unchanged from
the previous manifest. Workload mutation owners remain absent, with exactly
one immutable coordinator. The recovery public identity changed and is included
explicitly in the approval scope; it is not reproducible from public source.

The public code adds strict I-JSON validation before gjson-based mutation and
updates the XML-signature fork to include upstream validation and bounded
canonicalization fixes. The secret-manager and attestation-client logic remain
unchanged. Deployment paths and namespace changed; hash checks still precede
execution of mounted serving patches and templates. The serving engine remains
pinned vLLM 0.31.0. This is not a full reproduction of proprietary drivers,
model weights, or vendor serving patches absent from the public tree. Existing
OTLP and custom stat-logger limitations from the v1.61 review still apply.

Source-mode govulncheck v1.9.0 with Go 1.27.3 reports zero reachable
vulnerabilities and zero affected imported packages in the client. One advisory
exists in a required module outside the imported path; do not claim every
dependency is advisory-free.

## Local qualification

- Source-build tests passed for HTTP limits, refresh deadlines, server, encrypted
  bodies, and OCSP policy handling. Race-enabled gateway adapter tests passed.
- Altering the coordinator policy returns 401 before inference.
- Packaged encrypted GPT OSS 120B, GLM 5.3, and GLM 5.3 Flash streams returned
  PONG and final billable usage.
- Both GLM models returned PONG with reasoning explicitly off and zero reasoning
  tokens. Unsupported GPT OSS reasoning-off remains rejected.
- Encrypted embeddings passed at 1,024 and 2,560 dimensions; synthetic OCR passed.
- UID/GID 65532, no effective capabilities, no_new_privs, disabled core dumps,
  immutable sealed descriptors, and memory-only temporary storage remain active.

Local tests are not production deployment evidence. Merge only after approval
of this exact manifest and CI, then use guarded serial regional deployment,
signed trust publication, fresh hardware attestation, and provider-only tests.

References: [public source](https://github.com/edgelesssys/privatemode-public/tree/6b643fcec2145842745d0baf7df1176b5f0e65a5),
[policy reproduction](https://docs.privatemode.ai/cookbook/verify-source/),
[Go release metadata](https://go.dev/dl/?mode=json).
