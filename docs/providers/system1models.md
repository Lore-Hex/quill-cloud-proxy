# System1 Models

System1 serves typed decisions, not chat completions. The integration reuses
the TypeSafe SystemOne wire adapter and the existing `/v1/decide`
authorization, reservation, verification, settlement, and refund path.

## Routes and Isolation

| Provider | Model prefix | Tier header | Local credential |
| --- | --- | --- | --- |
| System1 Global | `system1models/` | `S1-Region: global` | `SYSTEM1MODELS_GLOBAL_API_KEY` |
| System1 EU | `system1models-eu/` | `S1-Region: eu` | `SYSTEM1MODELS_EU_API_KEY` |

Each tier supports `s1-fast`, `s1-pro`, and `s1-vision`. There is no cross-tier
fallback and no BYOK route. System1's response model, tier header/body, and
integer usage must match the authorized contract before settlement. The
provider does not qualify for confidential/E2EE routing.

```json
{
  "model": "system1models-eu/s1-fast",
  "state": "Mia owns a red bicycle.",
  "questions": {
    "color": {
      "type": "choice",
      "instructions": "Which color is the bicycle?",
      "criteria": {"red": null, "blue": null}
    }
  }
}
```

Send to `POST /v1/decide` with a TrustedRouter bearer key. Exactly one question
is accepted. State is limited to 16 KiB serialized JSON, with additional
upstream tokenizer limits. There is no streaming. Vision additionally accepts
one `images` entry containing an inline PNG/JPEG/WebP data URL, at most 4 MiB
decoded and 2 megapixels. Remote images are rejected before authorization.

## Pricing and Discovery

The control plane refreshes both tariffs from the public
[`GET /v1/models`](https://api.system1models.ai/v1/models) response, with real
canaries for newly discovered or unhealthy routes. It requires exact USD
per-million-input-token pricing, with output explicitly free. Customer pricing
uses the existing markup function; inference settles reported input tokens
(including image tokens), with zero output-token charges. Do not interpret
`S1-Charge-Nanos` as USD: the operator account currently reports EUR.

Official contracts: [API](https://system1models.ai/openapi.json),
[models and regions](https://system1models.ai/models),
[privacy](https://system1models.ai/legal/privacy).

## Deployment Order

1. Provision GCP secrets `trustedrouter-system1models-global-api-key` and
   `trustedrouter-system1models-eu-api-key` from the restricted local keyfile.
   The gateway needs read access; pricing refresh needs `tr-deploy` read access.
   Creating a secret container does not grant version-upload permission.
2. Sync the same two logical names to independent AWS Secrets Manager copies
   using `tools/sync-secrets-to-aws.sh --apply --secret <name>`. The existing
   eu-west-1 primary replicates to eu-west-3.
3. Azure bundle version `067afecf200f4272afa3a96418df32ba` contains both new keys
   and all 68 previous names. It is sealed in Azure Key Vault, but is NOT an
   assertion that any running enclave has adopted it. At rollout set
   `QUILL_SYSTEM1MODELS_GLOBAL_SECRET=trustedrouter-system1models-global-api-key`,
   `QUILL_SYSTEM1MODELS_EU_SECRET=trustedrouter-system1models-eu-api-key`, and
   `QUILL_AZURE_BUNDLE_VERSION=067afecf200f4272afa3a96418df32ba`, preserving all
   current optional secret references. Follow the Azure runbook's
   drain/policy/bind/verify sequence.
4. Deploy gateway code through the shared cloud-admission guard before enabling
   the control-plane catalog. Never publish routes against an old gateway.
5. Deploy the companion control-plane changes and confirm all six models accept
   `/v1/decide`, reject chat, bill once, and never cross tiers. The pricing
   workflow requires both GCP secrets; do not merge it before provisioning.

## Live Tests

`TR_RUN_SYSTEM1_LIVE=1 go test -tags cloud_gcp,llm_multi ./internal/llm -run
'^TestSystem1Live$' -count=1 -v` performs small paid probes. Supply the two key
environment variables securely; do not print them or include them in arguments.
It covers all three models, both tiers, all question types, and vision images.
