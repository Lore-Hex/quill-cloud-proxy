# Hixtube Standard-TLS Pilot

The `hixtube` direct-provider registry entry targets only
`https://api.hixtube.com/v1`. It uses the existing OpenAI-compatible adapter and
cloud-local provider key resolution. It does not use any attestation adapter.
Do not add it to confidential or ZDR eligibility based on this integration.

The selected checkpoint is
`dealignai/deepseek-v4.1-flash-1017-uncensored-fp8`; preserve that identity rather
than presenting it as the original DeepSeek checkpoint. The tested eager profile
declares 8,192 context tokens and 256 output tokens. The adapter remains
model-neutral, including the earlier Qwen CPU pilot; only the live catalog and
successful authenticated canaries establish eligible routes. The provider's own
cloud project must remain separate from TrustedRouter infrastructure.

Credential mapping: `HIXTUBE_API_KEY` -> `trustedrouter-hixtube-api-key` ->
`QUILL_HIXTUBE_SECRET`. Secret values never enter source or public release data.

## Activation

1. Verify the independently hosted pilot using the provider checker, including
   a valid public certificate, authentication, SSE, usage and bounded output.
2. Deploy cloud-local copies of the provider key through the normal secret tools.
   Azure must have the sealed bundle before opting into `QUILL_HIXTUBE_SECRET`.
3. Use the existing reviewed rollout workflows. AWS's explicit TLS-passthrough
   tunnel is port 8117 and permits only `api.hixtube.com:443`.
4. Publish the corresponding control-plane catalog only after the gateways and
   real provider canary are ready. Do not let fallback hide missing credentials.
5. Smoke forced-provider chat and streaming, verify usage/settlement, and verify
   that a confidential privacy floor excludes this non-confidential pilot.
6. Keep the catalog's retirement deadline at or before the finite server's
   admission cutoff. Withdraw the route before resource release unless a
   separately verified replacement is ready. Runtime expiry fails closed; it
   does not provide continuous service or restart the provider.

No production activation or attestation success is implied by registry source
changes. Ordinary inference through a pinned test certificate has passed, but
public DNS/CA trust, conformance and production settlement remain activation
gates. Keep this integration held until those gates are satisfied. Future
confidential hardware requires a separately reviewed verifier.

## Azure Sealed-Bundle Rollout

The October 25 follow-up pins the generated 83-entry manifest to immutable
bundle `db37a1ad4cc64cd18a40b49dc88c9ec5`. It preserves all 82 names from
`b9a9040d8e694dd18c6d4899929aaea6` and adds only
`trustedrouter-hixtube-api-key`. The incomplete earlier candidate was not
selected. Uploading this bundle or merging this change does not replace either
running gateway; the previous bundle remains their pin until an approved rollout.

Carry these names through both `print-env`/resealing and the subsequent guarded
rollout. Bare `print-env` omits the four existing optional providers; their
defaults deliberately remain unchanged. No secret values belong in these vars.

```bash
export QUILL_AZURE_BUNDLE_VERSION=db37a1ad4cc64cd18a40b49dc88c9ec5
export QUILL_HIXTUBE_SECRET=trustedrouter-hixtube-api-key
export QUILL_PRIVATEMODE_SECRET=trustedrouter-privatemode-api-key
export QUILL_SYSTEM1MODELS_GLOBAL_SECRET=trustedrouter-system1models-global-api-key
export QUILL_SYSTEM1MODELS_EU_SECRET=trustedrouter-system1models-eu-api-key
export QUILL_TELLUVIAN_SECRET=trustedrouter-telluvian-api-key
```

Hixtube now has a sealed-key default; an explicit `QUILL_HIXTUBE_SECRET=""`
still disables it. Preserve each region's complete current non-secret deploy
environment, not just these six values: regional identity/MAA, image and sidecar
pins, resource limits, shared and regional SNI, Azure-local ACME cache, canonical
billing authority, timeouts, and all remaining provider bindings. Compare the
rendered environment with that region's recorded live environment; only the
reviewed bundle pin and Hixtube binding should change. Image/source and resulting
CCE measurements change separately through the normal release process.

Follow the [Azure rollout runbook](azure-enclave.md), including cloud rollout
reservation, healthy-peer/shared-SNI checks, one-region drain, measurement
rebinding, attestation verification and final narrowing. There is no automatic
Azure deployment on merge. GCP/AWS rollout configuration and trust records are
unchanged by this follow-up; no confidential eligibility is added for Hixtube.
