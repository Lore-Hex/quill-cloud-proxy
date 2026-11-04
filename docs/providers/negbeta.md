# Negbeta

Negbeta uses `https://inference.negbeta.com/v1`, with exact native model IDs
from the managed account's Contract v2 `/models` catalog. The router owns
pricing, discovery, lifecycle, privacy and activation holds.

- GCP: `trustedrouter-negbeta-api-key`, `QUILL_NEGBETA_SECRET`; accessor
  bindings belong to the workload and deployment identities only.
- AWS: `quill/trustedrouter-negbeta-api-key` in each gateway region. The
  parent tunnel at vsock port 8137 carries TLS to `inference.negbeta.com`.
- Azure: `QUILL_NEGBETA_SECRET` references the same secret name in a new
  sealed bundle that must preserve all existing entries and current pins.
  Its deploy default remains empty until that bundle is sealed and verified;
  the production bundle manifest is not hand-edited to claim provisioning.

This change wires the secret coordinates; it does not provision credentials,
seal a bundle or deploy a gateway. Follow each cloud's normal CI, attestation,
coordinator, holdback and rollout gates. Do not enable control-plane routes
before actual serving gateway support is verified.

These are Standard routes. No confidential compute or provider-side E2EE is
offered. The data policy permits future disk-backed prompt caching, so strict
ZDR is held pending clarification. EU serving is a provider-declared agreement
for TrustedRouter's managed key, not attested residency or EU-only TLS transit.
See https://negbeta.com/inference/data-policy/ and
https://inference.negbeta.com/docs (reviewed November 4, 2026).
