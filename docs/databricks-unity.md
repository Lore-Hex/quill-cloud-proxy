# Databricks Unity Gateway

The two operator credentials have different audiences within the same pinned
workspace. Keep `DATABRICKS_TOKEN` for legacy serving endpoints and provision
`DATABRICKS_UNITY_TOKEN` separately as `trustedrouter-databricks-unity-token`.
Use the Databricks `ai-gateway` scope for inference. Do not enable workspace-wide
Unity enforcement while legacy workloads remain.

Public model IDs and prices do not change. The measured adapter sends only the
catalog-authorized IDs in `databricksUnityModel` to `/ai-gateway/mlflow/v1`,
using the fully qualified `system.ai` model service. Other routes, or deployments
without the optional Unity binding, keep their previous endpoints. A failed
Unity request is not replayed by this adapter against legacy.

Before promoting a service, inspect its FULL configuration: a single matching
Databricks-hosted destination, no payload table, and no alternate destination.
Verify a synthetic streaming completion and billable usage. The workspace
advertises services that can return model-specific 403s or deprecation errors.
On November 17, 2026, Kimi K3 and DeepSeek Flash 1017 were restricted, and
unversioned DeepSeek V4.1 Flash was deprecated. Do not infer access from listing.

On GCP the normal measured rollout binds the separate secret if provisioned.
Set `QUILL_DATABRICKS_UNITY_SECRET` explicitly empty when building a rollback
template. On AWS and Azure, seal the additional secret using the normal measured
bundle release. Leave the Azure binding empty until its immutable bundle contains
the secret. Never disable release-policy checks or add a name by hand to the
sealed manifest. Preserve the previous credential and bundle for rollback.

For a bounded synthetic test through the actual adapter, inject only the workspace
host and Unity token into the process environment and run, from `enclave-go`:

```sh
TR_LIVE_DATABRICKS_UNITY=1 go test -tags cloud_gcp,llm_multi,live_provider_wave ./internal/llm -run '^TestLiveDatabricksUnity$' -count=1
```
