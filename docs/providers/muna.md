# Muna

Muna uses `https://inference.muna.ai/v1` with its dedicated `MUNA_API_KEY`.
The control plane discovers chat models and exact token/cache prices from
`https://inference.muna.ai/integrations/trustedrouter/catalog`, not the broader
native catalog. Preserve upstream model IDs when invoking the provider.

These are Standard routes, not confidential or strict ZDR. Muna's published
policy permits incidental customer-content fragments in error logs for up to
30 days. Its US-only serving-location declaration is not attested.

## Cloud-local credentials

- GCP: `trustedrouter-muna-api-key`, with accessor bindings for `quill-workload`
  and `tr-deploy`. The measured image permits `QUILL_MUNA_SECRET`.
- AWS: `quill/trustedrouter-muna-api-key` in eu-west-1, replicated to eu-west-3.
  HTTPS uses the parent tunnel at vsock port 8130, retaining end-to-end TLS.
- Azure: Muna is included in bootstrap bundle
  `2e721965adec4b0f8c258c7b0ff50d2a`, sealed on 2026-10-22. It preserves all 80
  entry names from `6b4b87aebf6742c58cc0b349c9dbff2f` and adds only Muna.
  Pin `QUILL_AZURE_BUNDLE_VERSION=2e721965adec4b0f8c258c7b0ff50d2a` when
  following `docs/runbooks/azure-enclave.md`; preserve the current fleet's
  optional-provider environment settings. Uploading the bundle does not
  update a running enclave or its attestation policy.

Do not publish active control-plane routes before the serving gateway supports
the provider. Follow each cloud's normal CI, attestation, and rolling-release
gates. A passed upstream probe is not evidence of production deployment.
