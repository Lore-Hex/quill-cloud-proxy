# Tencent Cloud TokenHub

Canonical provider slug: `tencent`. The OpenAI-compatible prepaid and BYOK
paths share the compiled Singapore/global endpoint:

`https://tokenhub-intl.tencentcloudmaas.com/v1/chat/completions`

Verified against the official [API usage instructions](https://www.tencentcloud.com/document/product/1300/78941)
and [chat protocol](https://www.tencentcloud.com/document/product/1300/82345)
on 2026-09-29. This is the standard TokenHub API, not Token Plan's `/plan/v3`
subscription endpoint. Keys must belong to the selected site; neither callers
nor secret values can override the hostname.

The control plane supplies the native `/v1/models` ID as `endpoint_model_id`
(the enclave's authorized `UpstreamModel`). Preserve it, including case,
namespace, and suffix; do not prepend `tencent/`, strip an author, or use the
public model alias. Pricing and catalog activation belong to quill-router.

## Existing cloud wiring

| Boundary | Coordinate / source |
| --- | --- |
| Operator source | `TENCENT_API_KEY` in `tools/quill_secret_sources.py` |
| Shared registry | `enclave-go/internal/directproviders/providers.go` |
| GCP | `QUILL_TENCENT_SECRET=trustedrouter-tencent-tokenhub-api-key`; `tools/deploy-gcp-bootstrap.sh` grants workload secret access; `tools/deploy-gcp-mig.sh` discovers the optional secret and preflights IAM; the image allows the variable in `enclave-go/Dockerfile.enclave.gcp.multi` |
| AWS | `quill/trustedrouter-tencent-tokenhub-api-key` via `tools/sync-secrets-to-aws.sh` and `parent/src/quill_parent/bootstrap_server.py`; `enclave-go/internal/llm/http_client_aws.go` and `tools/deploy-aws-nitro.sh` agree on CID 3 / port 8083 and the official hostname |
| Azure | `tools/deploy-azure-aci.sh` forwards `QUILL_TENCENT_SECRET`, default empty; `tools/azure-seal-bundle.py` binds it into the cloud-local encrypted bundle |

Secret provisioning uses independent cloud-local copies. Do not read GCP
secrets to populate AWS or Azure. BYOK uses the existing encrypted per-workspace
key path and does not require the operator Tencent secret.

## Rollout order

1. Merge and release gateway support while catalog routes remain disabled.
2. Provision the operator key through the approved secret process. Verify the
   GCP workload service account's secret access and AWS regional replication.
   The checked-in Tencent secret pointers and AWS tunnel already exist.
3. For Azure prepaid activation, name `QUILL_TENCENT_SECRET` during sealing and
   deployment. Use `tools/azure-sync-secrets.sh` to produce a new bundle,
   regenerate `tools/azure-bundle.manifest`, and pin its immutable
   `QUILL_AZURE_BUNDLE_VERSION`. Do not hand-edit the manifest or turn on the
   provider against an older bundle. It stays dark until this is done.
4. Follow `.github/workflows/deploy-enclave-gcp.yml`,
   `tools/release-aws-enclave.sh`, and `tools/deploy-azure-aci.sh` for measured
   releases and transition trust sets. Keep attestation and durable billing
   gates; a generic deploy pass does not prove Tencent model success.
5. Separately authorize paid, provider-pinned prepaid and BYOK canaries using
   native IDs. Verify text, tools, reasoning controls, usage, settlement/refund,
   and error attribution before the router owner publishes catalog routes.

No deployment, bundle rotation, or credential provisioning is performed by
this source change. Cloud configuration coverage is offline and uses fixtures.

## Wire and tests

Both paths use Bearer authentication and request streaming usage. Explicit
reasoning on/off maps to `thinking.type`; effort maps to `reasoning_effort`.
Unspecified controls preserve native defaults. MiniMax M3 maps On to `adaptive`;
its native `enabled` value is invalid. GLM-5.3, GLM-5.3-Flash,
GLM-5.3-FlashX and Kimi K2.7 Code/HighSpeed do not support Off, so QCP
rejects it before an upstream call instead of silently enabling thinking.
Kimi K3 and K2.8 Preview are also always-thinking: On maps to native effort
(preserving an explicit effort), while Off and native `thinking` are rejected.
K3 uses the documented `max_completion_tokens` field; this is not a claim that
the legacy `max_tokens` alias is rejected. K2.8 uses `max_tokens`. Tencent's
Kimi model-differences table documents fixed sampling for K3, K2.8 Preview and
K2.7 Code/HighSpeed; QCP omits those sampling overrides. See the official
[GLM guide](https://www.tencentcloud.com/document/product/1300/80634) and
[Kimi guide](https://www.tencentcloud.com/document/product/1300/80635), plus the
chat protocol linked above. Model support is not inferred from the author
of the public alias. HY uses the same protocol controls; no user identifier
is injected or forwarded (the common protocol marks `user` optional).

The stream parser rejects TokenHub error frames (including errors after
partial output), malformed chunks, missing terminal frames, and missing
billable usage. SSE error text is not echoed. Reasoning tokens are a
subtotal of output, not an additional Regolo-style charge.

Focused offline coverage:

```sh
cd enclave-go
go test -tags 'cloud_gcp,llm_multi' ./internal/directproviders ./internal/bootstrap ./internal/llm -run 'TestTencent|TestResolveDirectProviderSecret|TestCloudConfigurations|TestOpenAICompatibleBYOKProviders'
go test -tags 'cloud_azure,llm_multi' ./internal/bootstrap -run TestTencent
```

Run `go test -race -tags '<cloud>,llm_multi' ./...` for `cloud_gcp`,
`cloud_aws`, and `cloud_azure`. The existing cloud-parity, vsock-port,
secret-source, GCP IAM, and Azure bundle/deploy tests pin the deployment
contract without accessing credentials or contacting cloud services.

## Operator-only stream smoke

`enclave-go/internal/llm/tencent_live_test.go` is excluded from ordinary CI by
the `live_tencent` build tag and additionally requires `TR_LIVE_TENCENT=1`.
With an already-exported `TENCENT_API_KEY`, run locally from `enclave-go`:

```sh
TR_LIVE_TENCENT=1 go test -tags 'cloud_gcp,llm_multi,live_tencent' ./internal/llm -run '^TestLiveTencentStreaming$' -count=1 -v
```

This makes exactly two paid streaming requests, one each for `glm-5.3-flash`
and `mimo-v2.6-flash`, through QCP's chat projection, BYOK invoker and response
adapter. It uses native default thinking and an explicit 128-token output cap.
Set `TR_LIVE_TENCENT_MAX_TOKENS=256` for a separately authorized larger run;
no other cap is accepted and there are no application retries or failovers.
The test reads the key only inside the process, uses the fixed official URL,
disables redirects and environment proxies, and logs only metadata, PONG and
usage counts. It fails on missing usage, non-PONG or nonterminal output without
logging raw errors, response bodies or reasoning. This is an adapter smoke,
not an attestation/settlement test. The source change does not run it.

To validate the smoke harness with fixtures and verify the live gate skips,
leave `TR_LIVE_TENCENT` unset and run the same build tags with
`-run '^(TestTencentSmokeOffline|TestLiveTencentStreaming)$' -count=1 -v`.
