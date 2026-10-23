# Privatemode v1.60 deployment review

Status: local encrypted tests passed; remote policy reproduction and production
rollout are still pending. Do not treat this document as production evidence.

## Incident

Privatemode replaced its v1.59 deployment on October 22. Our immutable manifest
still described `continuum-7a3b43`, while the provider serves `continuum-551e7c`.
The provider's client reports manifest mismatch as HTTP 401 during secret
initialization. This is not an invalid API key or insufficient balance. Rejecting
that changed deployment before releasing content was the correct behavior.

## Immutable inputs

- Public source: `317d813671769c16238b8e93245e5e2e06060a92` (v1.60.0).
- Source archive SHA-256: `1ce54898001c959449be0109a0afc0e9f4d4d206b566ac2013418895a921f7a0`.
- New manifest SHA-256: `b47473de3d4246903490bcb2e9aa99e9d296d12c2c357b5aa4f438fb3e655e9f`.
- Previous manifest SHA-256: `9f5ac6bf38431fb073c2185bd9b344140e776b4f7c32eee595716e9456bdec2a`.
- Contrast: v1.25.1. Checksummed Darwin CLI: `19a26e95d0fdf514053547c6b6fcf2a5d368d27b13cf38550b0499e9a0afc1a7`.
- Vendor proxy OCI index: `sha256:ea044948f9ee427ba8eff07a489e1105f20170e3e8c42b9800d8adaf065b24b3` (audit only, not shipped).
- Source-built Linux amd64 client SHA-256: `d1098b7b09218b83a75c85293fd0298df9be65815f93dcc22e6cb8e785da91ff`.

## Reviewed differences

All eight workload policies changed with the release. Contrast changed from
1.25.0 to 1.25.1; the new SNP measurement and TDX RTMR2 match that release's
published reference values. Minimum TCB, non-debug policy, hardware allowlists,
and immutable-update restrictions are not relaxed. The recovery/seed-share
owner key rotates with the deployment; it is a provider-controlled identity,
not something reproducible from source.

The source diff preserves nonce-bound attestation, exact expected-manifest
matching, mesh-certificate and secret-exchange signature verification. Changes
include optional extra headers, proxy timeout settings, anonymous-chat support,
and redacted forwarding errors. Our authenticated path does not enable anonymous
chat. Vendor stdout/stderr remain discarded by the gateway.

GLM 5.3 changes to NVIDIA's mixed NVFP4/FP8 weights at revision
`e3b8f9f2fad29727dfa95e766c5cac18ea1414bf`, with model-volume verity root
`df66c4cfc7f34c4f7aefd710795a511cde8384677cd041220a04b55541a07d75`.
The canonical model and upstream ID stay unchanged. Catalog precision evidence
must point at this revision, not the previous LibertAIDAI build. This is
published serving-configuration evidence, not a per-response model-identity proof.

## Local client hardening

The vendor binary was compiled with Go 1.26.8. A binary scan reported twelve
standard-library advisories, including GO-2026-6809 (certificate distrust).
The production image instead builds the MIT client with pinned Go 1.26.10 and
bounded control-plane HTTP reads/deadlines. Secret refresh is bounded while its
mutex is held. Inference streams retain their existing timeout behavior.

Launcher flags explicitly disable request dumping and insecure upstream TLS,
and require strict NVIDIA OCSP. The child keeps its dedicated UID/GID,
`no_new_privs`, no capabilities, sealed configuration FDs and pinned loopback TLS.
Both soft and hard core-file limits are zero before exec.

This does not establish a complete sandbox against a malicious client: the
child still shares its measured workload's memory budget and network namespace.
Do not describe UID isolation as per-child egress or resource isolation.

## Verification so far

- Independent container and production-stage builds produced identical client
  SHA-256 values listed above.
- Upstream command tests plus the new response-size, cancellation, secret-refresh
  and error-redaction tests pass during the build.
- `govulncheck v1.9.0`, source mode with Linux amd64, Go 1.26.10 and
  `contrast_unstable_api`, found zero reachable vulnerabilities and zero affected
  imported packages. Binary mode conservatively reports GO-2026-5932 in
  `x/crypto/openpgp`; that package is not imported by this client. Do not report
  the binary scan as completely clean.
- Packaged Linux streaming returned nonempty PONG output and usage for
  GPT OSS 120B (76 input / 21 output), GLM 5.3 (21 / 4), and GLM 5.3 Flash
  (21 / 11). These synthetic checks are not customer requests.
- Removing the coordinator policy returned HTTP 401 before inference. The
  negative control locates the coordinator by its role rather than a stale hash.
- Sealed-FD mutation, required launch flags, UID/capability/no-new-privileges,
  and zero core-file-limit checks passed.

## Remaining release gates

1. Reproduce all eight policies from the exact public deployment with the
   checksummed Contrast CLI, apply the documented vendor manifest adjustments,
   and compare policies/reference values. Review deployment-specific owner keys
   separately; never copy live trust configuration to make a comparison pass.
2. Complete current full-suite and CI checks.
3. Deploy through coordinated measured-image rollouts and verify real pinned
   Privatemode requests in each serving cloud. Leave unrelated provider failures
   separate from platform health.

References: [public release source](https://github.com/edgelesssys/privatemode-public/tree/317d813671769c16238b8e93245e5e2e06060a92),
[policy reproduction](https://docs.privatemode.ai/cookbook/verify-source/),
[Contrast release](https://github.com/edgelesssys/contrast/releases/tag/v1.25.1),
[incident #578](https://github.com/Lore-Hex/quill-cloud-proxy/issues/578).
