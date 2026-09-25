# Privatemode encrypted inference

## Boundary

The vendor proxy runs inside the measured enclave image, as UID/GID 65532,
without effective capabilities and with `no_new_privs`. The enclave talks to it
over ephemeral, certificate-pinned loopback TLS. The proxy verifies the remote
CPU/GPU workloads and encrypts inference before bytes leave the enclave.
Ordinary provider HTTPS is used only for metadata discovery, never inference.

The embedded manifest is immutable (`WorkloadOwnerKeyDigests=[]`). No runtime
CDN refresh is permitted. Invalid attestation, changed measurements, certificate
revocation, an absent proxy, or an unreviewed native model fails closed. There
is no plaintext or BYOK fallback. Only chat inference is enabled; embeddings
and decision APIs explicitly reject this provider before network access.

Pins reviewed on 2026-09-25:

- Public source: `edgelesssys/privatemode-public` tag `v1.57.0`, commit
  `9995223e02461fef93742fe9921dc03f7cc4f1a7`.
- Proxy OCI index:
  `sha256:77e8f378d5151d6abf36e02c7b8622996dcc4ded09b4ef4860b538a5dcc557c6`.
- Embedded manifest SHA-256:
  `928724d7a536442715aed927d9fb9fc8718c1d67a77ce888dca8f0ea9078bb39`.
- Contrast verifier: `v1.24.1`; Linux CLI SHA-256
  `257601578d45622889eabf8963dc5983e607671ce22b5fc7749a81dcd66c96dd`.
- Native models: `gpt-oss-120b`, `glm-5.3`, `glm-5.3-flash` only.

Pins are not themselves proof that a deployment passed: preserve independent
policy reproduction results and regional inference results with the release.

## Isolation, Usage, And Operations

The child receives no inherited API keys or cloud credentials. Its request key
arrives only in Authorization over pinned loopback TLS. Cert/key/manifest use
sealed memfds. The temporary directory holds only public attestation collateral.
Vendor stdout/stderr are discarded. Lifecycle events contain version, manifest
hash, exit code, and restart delay, not prompt, response, thinking, or keys.

`privatemode.proxy_listening` is local readiness, not an attestation-success
claim. The supervisor removes dead clients and restarts with 1-60 second
backoff. Other providers do not wait for it. Alert on repeated proxy exits and
existing provider synthetic failures; never auto-promote a new manifest to
recover a failed probe.

Prompt-cache salt is derived from the authorized workspace scope. Different
workspaces never deliberately share a salt; missing scope uses the vendor's
fresh-per-request default. Usage, cached input and reasoning follow the shared
streaming and settlement pipeline. Missing usage or a truncated stream cannot
produce a successful terminal event. GLM accepts low/high/max effort; GPT OSS
accepts low/medium/high. Unsupported explicit settings return an error rather
than silently using maximum effort.

## Rollout Gate

1. Reproduce the release workload policies with the pinned Contrast CLI and
   public `deployment.yaml`; compare every generated policy hash to the pinned
   manifest. Review source changes, model-volume verity roots, TCB reference
   values, and secret-release policy. Do not enable E2EE with unproven results.
2. Run full tests for `cloud_gcp,llm_multi`, `cloud_aws,llm_multi`, and
   `cloud_azure,llm_multi`, plus parent/tool tests and local Claude CLI Opus review.
3. Build the real scratch image. Run Linux tests tagged `live_provider_wave`:
   `TestLivePrivatemodePackagedStreaming` and
   `TestLiveManifestMismatchFailsClosed`. The latter must reject the changed
   manifest before inference. Use synthetic inputs and metadata-only evidence.
4. Provision `trustedrouter-privatemode-api-key` independently from the local
   operator source into each cloud. AWS uses `sync-secrets-to-aws.sh` with its
   regional replica; Azure uses `azure-sync-secrets.sh` and its sealed bundle.
   Azure's `QUILL_PRIVATEMODE_SECRET` stays empty until that bundle is sealed.
5. Deploy measured images through the reviewed regional drain/health/attestation
   workflows. AWS also needs its four allowlisted TLS tunnels. Verify real
   encrypted requests in every serving region; a successful local Docker probe
   is not a Nitro/Confidential Space/ACI deployment test.
6. Only then remove quill-router's `ROLLOUT_HOLD`, set its Privatemode
   `provider_e2ee=True`, regenerate the priced manifest and provider OG, deploy
   the catalog, and smoke the public confidential filter with pinned providers.

The catalog is deliberately dark until step 6. Do not make it an ordinary
plaintext provider to work around a failed verification or unavailable cloud.

## Pin Updates

New discovery results do not extend the encrypted model allowlist. Repeat the
review/reproduction/probe gates for every vendor release, update Docker pins,
the embedded manifest and its tests together, and roll the enclave before
publishing newly eligible models. Existing pins failing against a vendor update
are an availability incident, not authorization to bypass attestation.

Primary references: [source and releases](https://github.com/edgelesssys/privatemode-public),
[verification](https://docs.privatemode.ai/security/attestation/overview/),
[encryption](https://docs.privatemode.ai/security/encryption/),
[model controls](https://docs.privatemode.ai/models/overview/).
