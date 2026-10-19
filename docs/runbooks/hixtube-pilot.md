# Hixtube Standard-TLS Pilot

The `hixtube` direct-provider registry entry targets only
`https://api.hixtube.com/v1`. It uses the existing OpenAI-compatible adapter and
cloud-local provider key resolution. It does not use any attestation adapter.
Do not add it to confidential or ZDR eligibility based on this integration.

The pilot model is `qwen/qwen3-0.6b`; its upstream ID is identical. The initial
context/output limits are 4,096/256. The provider's own cloud project must remain
separate from TrustedRouter infrastructure.

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

No production activation or attestation success is implied by registry source
changes. Future confidential hardware requires a separately reviewed verifier.
