# Privatemode encrypted inference

## Boundary

The vendor proxy runs inside the measured enclave image, as UID/GID 65532,
without effective capabilities and with `no_new_privs`. The enclave talks to it
over ephemeral, certificate-pinned loopback TLS. The proxy verifies the remote
Contrast deployment and encrypts inference before bytes leave the enclave.
The pinned remote attestation agent verifies its GPUs; its inference proxy
enforces our MAC-authenticated policy accepting only good NVIDIA OCSP status.
Those NVIDIA OCSP/RIM fetches occur at the remote workload, not in our proxy,
so the client does not need NVIDIA egress tunnels. This is deployment-level
attestation, not a per-response cryptographic assertion of model identity.
Ordinary provider HTTPS is used only for metadata discovery, never inference.

Encryption does not hide all routing metadata. Privatemode's API edge sees
model/account information, estimated input length, and cache-sharding headers.
Scoped caching creates a stable workspace pseudonym (a truncated hash, not the
workspace ID) and shared-prefix structure for long inputs. Request contents
remain encrypted; do not claim traffic unlinkability or hidden token lengths.

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

Independent reproduction passed for all nine policy hashes in Cloud Build
`f291e343-c4a0-4580-b90c-6ea549ba5046` (2026-09-25, us-central1). The public
generated manifest is retained at
`gs://44325983244.cloudbuild-logs.googleusercontent.com/privatemode-policy-audit/f291e343-c4a0-4580-b90c-6ea549ba5046/generated-manifest.json`.

## Isolation, Usage, And Operations

The child receives no inherited API keys or cloud credentials. Its request key
arrives only in Authorization over pinned loopback TLS. Cert/key/manifest use
sealed memfds. The temporary directory holds only public attestation collateral.
Vendor stdout/stderr are discarded. Lifecycle events contain version, manifest
hash, exit code, and restart delay, not prompt, response, thinking, or keys.
Do not forward raw vendor errors: they may incorporate untrusted upstream
response bodies. Request-stage HTTP failures preserve the status for fallback
and retry but replace the body with a fixed provider error.

`privatemode.proxy_listening` is local readiness, not an attestation-success
claim. Upstream attestation happens lazily when a request supplies credentials;
the local readiness check does not wait for a collateral fetch. The supervisor
allows 60 seconds for the listener, removes dead clients, and restarts with 1-60 second
backoff. Other providers do not wait for it. Alert on repeated proxy exits and
existing provider synthetic failures; never auto-promote a new manifest to
recover a failed probe.

Once per enclave boot, three fixed synthetic requests verify the encrypted
path for each pinned model, including real usage and PONG output (allowing
case, quotes and trailing punctuation).
Each is capped at 1,024 output tokens and 180 seconds, with no retries; these
are operator costs, never customer settlements. They run asynchronously and
do not block other providers. Only `privatemode.encrypted_probe` metadata
(model, success, fixed-vocabulary reason, HTTP status, input/output counts)
is logged, never content. The same bounded results are available as
`privatemode_probes` on `/health`, including on non-debug Nitro. Health reads
only this in-memory snapshot; it never triggers a provider call. Its `status`
remains enclave liveness, not provider readiness. Check each new instance and
its attestation/image identity, not an arbitrary load-balanced health response.
This is intentionally public operational metadata about public vendor model IDs,
not a secrecy boundary. "Dark" means not selectable/billable in the catalog;
it does not hide the open-source integration or its synthetic health evidence.
Require fresh success events for the new image in each serving region while
the public routes remain dark. A proxy restart does not repeat paid probes.
These costs apply per instance, not per region. Once regional evidence is
captured, `QUILL_PRIVATEMODE_BOOT_PROBE=off` in the measured deployment disables
future boot probes; this does not change request-time encryption or verification.

Prompt-cache salt is derived from the authorized workspace scope. Different
workspaces never deliberately share a salt; missing scope uses an explicit
cryptographically random per-request salt. Usage, cached input and reasoning follow the shared
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
   The staged Azure bundle is `44f442fa31e84e2b853a7c84a3b1a546` (67 entries,
   all previous names preserved). Set `QUILL_AZURE_BUNDLE_VERSION` to that
   immutable version and `QUILL_PRIVATEMODE_SECRET=trustedrouter-privatemode-api-key`
   for its measured deployment; retain existing provider bindings including
   `QUILL_TELLUVIAN_SECRET=trustedrouter-telluvian-api-key`. Rebind the SKR policy
   through the deploy tool after rendering the new measured environment.
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

### 2026-09-25 AWS And Azure Rollout Evidence

Enclave source `3c0cb55932768a4ee78ad512e6da71c380465f3e` was deployed
before catalog activation. Each replacement host returned successful encrypted
boot probes for all three pinned models with nonzero input/output usage.

- AWS Paris: instance refresh `bf72fe33-9831-4da5-805b-bc9440445ed6`
  completed; hosts `i-0ca2894db26b3ee70` and `i-013f86cbdd7007491` passed.
- AWS Dublin: instance refresh `f0f4c291-bbf4-4d65-8dff-bfaa8f0202de`
  completed; hosts `i-0e836fc468f1e11a7` and `i-0d659cbcee0a5a82f` passed.
  Six fresh, nonce/channel-bound Nitro attestation samples through each
  regional load balancer accepted only the new PCR0. Both active ECS monitor
  pins were narrowed to that PCR0 after the rolls completed.
- Azure Dubai and Sydney: stable container groups passed encrypted probes and
  nonce/channel-bound MAA attestation. Traffic Manager targets are the stable
  groups; Sydney's direct regional DNS is restored to its stable group. The
  bootstrap key-release policy now accepts only the two new regional hostdata
  values, preserving each region's issuer binding.

The AWS and Azure trust records hold the exact resulting measurements.
This evidence does not assert catalog activation or completion of the separate
GCP workflow, and does not bypass the control-plane cross-cloud bake gate.

### 2026-09-26 Public API Verification

GCP enclave workflow `36176398643` and catalog deployment `36195743126`
completed successfully. The catalog change is quill-router PR #1336.
All three pinned models passed real streaming and non-streaming requests to
`api.trustedrouter.com`, with `provider.only=["privatemode"]`,
`allow_fallbacks=false`, and `min_privacy="confidential"`. All three
non-streaming generation records matched the returned token counts and settled
cost exactly. Streaming responses included usage, selected-provider metadata,
and `[DONE]`.

Three repeated synthetic GPT OSS requests used 7,102 input tokens. The second
and third reported 7,088 cached tokens; their total charges were 411 and 409
microdollars, versus 3,863 microdollars on the first request. These are bounded
smoke results, not throughput or uptime guarantees.

The subsequent Confidential AI credential rotation resealed the Azure bundle
without changing its 67 secret names or the enclave image. The only change to
the 85 measured environment values is `QUILL_AZURE_BUNDLE_VERSION`. Isolated
Dubai and Sydney replacements passed pinned MAA signature, non-debuggable
workload, nonce, and TLS-channel checks before publication of their transition
measurements. Both also passed real Confidential AI inference, including a
streaming Sydney request. This key rotation does not change Confidential AI's
provider E2EE eligibility.

New discovery results do not extend the encrypted model allowlist. Repeat the
review/reproduction/probe gates for every vendor release, update Docker pins,
the embedded manifest and its tests together, and roll the enclave before
publishing newly eligible models. Existing pins failing against a vendor update
are an availability incident, not authorization to bypass attestation.

Primary references: [source and releases](https://github.com/edgelesssys/privatemode-public),
[verification](https://docs.privatemode.ai/security/attestation/overview/),
[encryption](https://docs.privatemode.ai/security/encryption/),
[model controls](https://docs.privatemode.ai/models/overview/).
