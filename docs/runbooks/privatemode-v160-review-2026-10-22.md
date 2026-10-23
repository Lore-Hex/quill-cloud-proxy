# Privatemode v1.60 deployment review

Status: local encrypted tests, independent policy/image reproduction, and
production-origin verification passed. The repaired image has been deployed to
GCP, AWS and both Azure regions. Production results below are distinct from the
local qualification evidence.

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
- Contrast Linux CLI SHA-256: `953dfb319992e323afaf2109aef13c3e5395f712235969619cd7af2a7d63a6b4`.
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

- Cloud Build `abfa8900-e456-481b-b1ac-b0f66c0d3dd8` succeeded on October 23 UTC
  (October 22 Pacific). All eight policies, SANs, workload secret IDs, roles,
  and SNP/TDX reference values exactly match after the public release's manifest
  adjustments. The only remaining difference is `SeedshareOwnerPubKeys`.
  No generated policy hash or reference value was copied from the live manifest.
- Raw generated manifest SHA-256:
  `65b611c8395b74b31333335cb9f7fdc0c7c7229d5ad7041c5bda0dd24741dabb`.
  Adjusted manifest SHA-256:
  `639ffa3485cccde4d54618bea008378022551119564adf22cffd2d2852f85109`.
  Evidence prefix:
  `gs://44325983244.cloudbuild-logs.googleusercontent.com/privatemode-policy-audit/abfa8900-e456-481b-b1ac-b0f66c0d3dd8/`.
  `manifest.json`, `deployment.yaml`, and `layers-cache.json` are retained build
  outputs. The adjusted hash is reproducible using the transformations below;
  its upload was not permitted, so it is not claimed as a retained cloud object.
- Reproduction command: `contrast generate --disable-updates
  --reference-values=metal-qemu-snp-gpu
  --reference-value-patches=scripts/snp-guestpolicy-patch.json
  --collateral-proxy=http://collateral-proxy.continuum-infra.svc deployment.yaml`.
  Then run the pinned source's `scripts/adjust-manifest.sh` with namespace
  `continuum-551e7c` for the two secret-service DNS names, and remove the Milan
  SNP entry as specified for the deployed Genoa fleet. Recovery ownership is
  reviewed as a deployment-specific public identity, not reproduced from source.
- An independent Nix rebuild from the exact public source reproduced the vendor
  client byte-for-byte (SHA-256 `7bd77fb6d9fb7b1a87970898a3af3a7c8cb73e4d692238ac1a33d8f3f67cc3b4`).
  It also reproduced every open-source security-component OCI digest in the
  deployment: attestation-agent, disk-mounter, inference-proxy, kernel-log and
  secret-service. Only `cache.nixos.org` was used; no vendor binary cache was
  trusted. The upstream Go 1.26.8 client is audit evidence, not our shipped client.
- The Nix build used `legacyPackages.x86_64-linux.privatemode-proxy.bin` and
  `privatemode-container-images.oss-oci-images` in
  `nixos/nix:2.31.2@sha256:29fc5fe207f159ceb0143c25c19c774062fee02ce5eda118f3067547b3054894`.
  This establishes reproducibility of those components, not every closed-source
  GPU driver or every inference engine dependency.
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
- Packaged encrypted OCR, Qwen embeddings (1,024 and 2,560 dimensions), Whisper
  JSON and verbose JSON with segment timestamps, and Voxtral Mini JSON passed.
  The synthetic audio fixture was 3,457 ms. No customer content was used.
- Full gateway tests passed for GCP, AWS and Azure multi-provider builds;
  parent tests passed (42), manifest checker tests passed (3), and rollout-safety
  tests passed (59). CI checks the Linux test helper and cross-compilation-stage
  assertions before merge.

## Production verification, October 23

- GCP: all eight serving instances across four regions passed fresh hardware
  attestation, exact image matching, nonce and TLS channel binding, and direct
  pinned Privatemode streaming. The final image is
  `sha256:dcfef2b9db88562816e993439dc57b7f09f98e725538fb2d7b3b7cea5cd326fc`.
  Stage D sequence 1223 accepts only that image. Final pins were published in
  [PR 586](https://github.com/Lore-Hex/quill-cloud-proxy/pull/586).
- AWS: all four serving instances in Paris and Dublin passed the corresponding
  Nitro attestation and pinned inference checks. The image is
  `sha256:5fed3daa469855bfc48d529c6b94402144e6441417674740d0075b805892ab92`.
  Final pins were published in
  [PR 585](https://github.com/Lore-Hex/quill-cloud-proxy/pull/585).
- Azure: Dubai and Sydney both passed exact HOSTDATA, pinned MAA issuer, JWT
  signature, nonce, TLS certificate/exporter bindings and non-debug checks.
  Both run image
  `sha256:4cb87fa983893f81d3e8165685faad52ec128737c34a489c682cd31d3be510bb`,
  built from `2573d2314b0b5f097639a2e749635038e53aa9ac`. The sealed bundle remains
  `2e721965adec4b0f8c258c7b0ff50d2a`; all 103 existing environment variables were
  preserved. Dubai's new HOSTDATA is
  `70a6879700815e6951241d6eb04b86ed05ab8c1a6fb35610b105f55ba1b4bd97`;
  Sydney's is `2f439c09e80dfc7eb92fd22863ad61a42ae3192e81b34e3574df000dbc1d0f4c`.
- On both Azure origins, GPT OSS 120B, GLM 5.3, GLM 5.3 Flash,
  `trustedrouter/trusted` and `nyte/trusted` returned HTTP 200, nonempty PONG,
  final usage and stream completion with Privatemode as the selected provider.
  Tests used synthetic prompts with fallbacks disabled, not customer content.
- The Azure rollout reserved the shared coordinator with AWS as its healthy
  holdback. Traffic Manager drained one region at a time. Each old Key Vault
  measurement stayed available for rollback until the replacement attested;
  completing the rollout requires `verify`, `narrow` and a clean `audit` for
  each region, plus both endpoints Online. The transition record is
  [PR 587](https://github.com/Lore-Hex/quill-cloud-proxy/pull/587).
- Public Azure records are verified byte-for-byte and against the exact
  `publish-trust-azure.yml@refs/heads/main` signing identity before a replaced
  region returns to traffic. Local DNS briefly retained a retired origin IP;
  capture used Azure's current origin IPs while preserving the API hostname,
  certificate-chain validation and full attestation verification.
- The separate diagnostic false alarm was fixed in
  [quill-router PR 1995](https://github.com/Lore-Hex/quill-router/pull/1995).
  Health probes now parse the bounded JSON response instead of requiring an
  exact byte string. All 16 latest cold/reused regional probe combinations
  were up at 14:33 UTC; reused-path checks reported actual connection reuse.

Provider errors remain separate from platform health. For a later upstream
manifest change, repeat the review and reproduction rather than widening pins
to an unreviewed deployment.

References: [public release source](https://github.com/edgelesssys/privatemode-public/tree/317d813671769c16238b8e93245e5e2e06060a92),
[policy reproduction](https://docs.privatemode.ai/cookbook/verify-source/),
[Contrast release](https://github.com/edgelesssys/contrast/releases/tag/v1.25.1),
[incident #578](https://github.com/Lore-Hex/quill-cloud-proxy/issues/578).
