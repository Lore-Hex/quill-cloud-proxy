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
