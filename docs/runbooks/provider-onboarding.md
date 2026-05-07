# Adding a new upstream LLM provider

The end-to-end playbook for wiring a new provider (Fireworks,
DeepInfra, Groq, etc.) into TR. Together AI was the test case for
this runbook — the steps below are exactly what we did.

Plan for ~3 hours of work end-to-end, of which ~2 are deploy/wait
cycles. The actual code is small.

## Decision before you start

Two questions:

1. **Direct API or OR-canonical names?** If the provider's API uses
   the same model ids as OpenRouter (e.g., `deepseek/deepseek-v4-flash`)
   then no name translation is needed. If it uses its own naming
   (Together: `meta-llama/Llama-3.3-70B-Instruct-Turbo`) then you
   need to add a translation table.
2. **OpenAI-compatible chat completions?** Most providers are. If
   yes, you can reuse `openAICompatibleClient`. If not, you need a
   new client (see `kimi.go`/`zai.go` for examples — they only differ
   from openai-compat in payload shape).

## Step 1: Get the API key

Add to `~/.quill_cloud_keys.private`:

```
NEWPROVIDER_API_KEY=sk-...
```

## Step 2: Wire control plane (quill-router)

| File | Change |
|---|---|
| `src/trusted_router/catalog.py` | Add `"newprovider"` to `PROVIDERS` and `GATEWAY_PREPAID_PROVIDER_SLUGS` |
| `src/trusted_router/providers.py` | Add to `OPENAI_COMPATIBLE_PROVIDERS` if applicable: `"newprovider": (("NEWPROVIDER_API_KEY",), "https://api.newprovider.com/v1")` |
| `src/trusted_router/secrets.py` | Add to `KEY_ALIASES` with any common synonyms |
| `src/trusted_router/routing.py` | Add to `_PROVIDER_ALIASES` (slug variants) and `_THROUGHPUT_RANK` |
| `src/trusted_router/sentry_config.py` | Add `"newprovider_api_key"` to `SENSITIVE_STRING_FRAGMENTS` |
| `scripts/deploy/secrets.sh` | Add `ensure_secret_from_env_file "NEWPROVIDER_API_KEY" "trustedrouter-newprovider-api-key" ...` |
| `scripts/deploy/rollout.sh` | Add `add_secret_env_if_exists "NEWPROVIDER_API_KEY" "trustedrouter-newprovider-api-key"` |
| `scripts/ingest_openrouter_catalog.py` | Add to `PROVIDER_NAME_TO_SLUG`: `"NewProvider": "newprovider"` |

Run `pytest -x` — should still be green.

## Step 3: Wire enclave gateway (quill-cloud-proxy)

| File | Change |
|---|---|
| `enclave-go/internal/types/types.go` | Add `NewProviderAPIKey string` to `BootstrapData` |
| `enclave-go/internal/llm/multi.go` | Add `newprovider` to `multiClient` struct + dispatch switch |
| `enclave-go/internal/llm/byok.go` | Add case to `directBaseURL`. If model-name translation needed, add a per-provider map and consult it in `directModelID` (see `togetherModelMap`) |
| `enclave-go/Dockerfile.enclave.gcp.multi` | Add `QUILL_NEWPROVIDER_SECRET` to the `tee.launch_policy.allow_env_override` LABEL |
| `enclave-go/internal/bootstrap/bootstrap_gcp.go` | Add secret-fetch + populate `BootstrapData.NewProviderAPIKey` |
| `tools/deploy-gcp-mig.sh` | Add `QUILL_NEWPROVIDER_SECRET` to the `tee-env-...` metadata string |
| `tools/deploy-gcp-bootstrap.sh` | Add `NEWPROVIDER_SECRET` to the for-loop that grants workload SA access |

Run `go test -tags 'cloud_gcp,llm_multi' ./...` — still green.

## Step 4: Push secret

```bash
bash scripts/deploy/secrets.sh   # creates trustedrouter-newprovider-api-key in Secret Manager
```

**Critical:** also grant the workload SA access (the bootstrap script
covers this on first run, but on subsequent provider adds you need
to do it manually OR re-run bootstrap):

```bash
gcloud secrets add-iam-policy-binding trustedrouter-newprovider-api-key \
  --project=quill-cloud-proxy \
  --member="serviceAccount:quill-workload@quill-cloud-proxy.iam.gserviceaccount.com" \
  --role=roles/secretmanager.secretAccessor
```

This is the #1 thing that's silently missed when adding a provider.
See [enclave-deploy-debugging.md §6](./enclave-deploy-debugging.md).

## Step 5: Refresh catalog snapshot

```bash
uv run python scripts/ingest_openrouter_catalog.py
git add src/trusted_router/data/openrouter_snapshot.json
git commit -m "Refresh catalog snapshot: pick up <newprovider>-hosted models"
```

## Step 6: Push & let GHA deploy

Push to main. Both workflows trigger:

- `quill-router/.github/workflows/deploy.yml` ships the control plane
  (staged regional, 10/50/100 traffic)
- `quill-cloud-proxy/.github/workflows/deploy-enclave-gcp.yml` ships
  the enclave (staged regional, MIG rolling)

Watch for the watchdog passing on both. Total ~25 min if everything's
clean.

## Step 7: Live-test

```bash
KEY=$(cat ~/.quill_device_trusted_router.key | tr -d '\n')
curl -s "https://api.quillrouter.com/v1/chat/completions" \
  -H "authorization: Bearer $KEY" \
  -H "content-type: application/json" \
  -d '{"model":"<newprovider-served-model>","messages":[{"role":"user","content":"PONG"}],"max_tokens":5}'
```

Expect a 200. If 502, see
[enclave-deploy-debugging.md §8](./enclave-deploy-debugging.md).

## Step 8: Add model-name translations (if needed)

If the provider 404s with `Unable to access model`, the model id TR
sent doesn't match the provider's catalog. Add a translation table:

```bash
# Build the mapping by intersecting your snapshot with the provider's catalog
# (see the Together onboarding commit for the exact pattern)
```

Edit `enclave-go/internal/llm/byok.go`:

```go
var newproviderModelMap = map[string]string{
    "or-canonical-id": "newprovider-native-id",
    ...
}
```

And in `directModelID`, consult this map when `provider == "newprovider"`.

Push. The next deploy ships it.

## Common gotchas

1. **The workload SA binding is per-secret.** Adding the provider
   to `tools/deploy-gcp-bootstrap.sh` covers the FIRST deploy after
   that script runs. Subsequent provider adds need manual grants.
2. **Dockerfile `allow_env_override` label is on the IMAGE, not the
   VM.** A new env var requires a new image build before it's
   accepted. You can't just add the env to the VM metadata and
   restart.
3. **`REGION_SHORT` defaults can collide with existing MIG names.**
   The deploy MIG script defaults `REGION_SHORT` to dashes-stripped
   region (`uscentral1`). Existing prod uses `us`/`eu`. The GHA
   workflow already sets `REGION_SHORT: us`/`eu` — don't change
   without checking the LB-attached MIG name.
