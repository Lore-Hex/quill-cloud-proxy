# Abliteration.ai

This is a separate provider from Abliterate.ai. It uses
`https://api.abliteration.ai/v1` and `ABLITERATION_API_KEY`, not the Abliterate
credential, endpoint, or estimated-usage billing exception.

The control plane discovers priced, available chat models from authenticated
`GET /models`. It keeps native IDs and input, output, and cache-read rates.
New routes require a canary with real usage and a nonempty assistant response.
Ordinary chat is ZDR under the provider's published data-handling policy;
optional paid web tools are not integrated. This is not confidential compute.

## Cloud-local Secrets

- GCP: `trustedrouter-abliteration-api-key`, accessible to `quill-workload`
  and `tr-deploy`; measured env override `QUILL_ABLITERATION_SECRET`.
- AWS: `quill/trustedrouter-abliteration-api-key`, with HTTPS to
  `api.abliteration.ai` via parent vsock port 8131.
- Azure: seal the same logical secret into the cloud-local bootstrap bundle,
  preserving all current entries. Pin that bundle during the measured rollout.

The 2026-10-23 Azure bundle is `b9a9040d8e694dd18c6d4899929aaea6`.
It preserves all 81 entry names from `2e721965adec4b0f8c258c7b0ff50d2a`
and adds only Abliteration. Set `QUILL_AZURE_BUNDLE_VERSION` to that version
when following the Azure enclave runbook. Preserve the existing Privatemode,
Telluvian and System1 EU/global optional-provider environment settings.

Provision secrets before gateway deployment. Do not publish active control-plane
routes until the relevant serving gateways support them. Preserve the normal
CI, attestation, rolling-release and cloud bake gates.
