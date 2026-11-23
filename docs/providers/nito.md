# Nito: ordinary chat staged; Confidential not qualified

Nito's ordinary API and its client-encrypted protocol are distinct. The
ordinary OpenAI-compatible client can use the provider-native `:confidential`
chat ID only. The suffix is not a TrustedRouter privacy classification.
Never translate `:encrypted` to that sibling or use the customer's plaintext
in place of an encrypted request. Do not admit Nito to ZDR, Trusted or
Confidential on the basis of catalog metadata.

The November 22 direct catalog had nine priced chat models in two variants
each. GPT-OSS streaming returned the requested ID and usage. Its ordinary
JSON request with a 128-token limit and low reasoning returned content and
consistent usage within the cap. Keep the earlier HTTP 400
`output_token_limit_exceeded` results: 12-token DeepSeek and 32-token
GPT-OSS ordinary JSON. These are direct upstream results, not production
gateway or all-model verification.

For evidence inspection, run `tools/check_nito_binding.py <exact :encrypted ID>`
with Python, cryptography and `NITO_API_KEY` in the environment. This
read-only check uses a fresh challenge and authenticates the v2 sealed
binding; it does not authenticate the silicon. On the sampled encrypted
DeepSeek abliterated route, the NEAR-format binding opened, but its native
model was absent from the reviewed direct NEAR model policy. Even a match
would not qualify a relayed encrypted request: the direct verifier pins the
TLS connection to the upstream, whereas Nito's relay requires the client to
verify and bind the encryption key used for the payload.

To qualify a specific route, review the workload pins independently, validate
the relevant hardware evidence and freshness, verify the model and transport
key, and exercise encrypted requests/responses plus negative tests through
the actual gateway. An invalid, changed, expired or missing proof must stop
the request before any prompt leaves. Other evidence formats need their own
verifiers; a passing model cannot grant an account-wide badge.

## Encrypted route qualification, November 23, 2026 (UTC)

Fresh v2 bindings on all nine encrypted routes selected three different
verification procedures. None is production-qualified.

| Routes | Independently checked | Still missing |
| --- | --- | --- |
| DeepSeek V4.1 Flash (standard), Gemma 4 31B, GLM 5.3, GPT-OSS 120B, Kimi K3.1 Pro, Llama 3.3 70B | All six EHBP bundles verified against the [published Tinfoil router release v0.0.179](https://github.com/tinfoilsh/confidential-model-router/releases/tag/v0.0.179) and independent native model list. Checked Sigstore, AMD SEV-SNP, build measurements, enclave certificate, HPKE key, and a fresh direct TLS connection matching the attested public key. Five substituted-key/host/digest controls rejected. | Nito returned HTTP 403 to one encrypted GPT-OSS request and one Kimi request; Kimi reported `forbidden`. Neither yielded an authenticated inference response. No inference on the other four. |
| DeepSeek V4.1 Flash 1017 abliterated | NEAR reports matched the challenge, native ID and proposed signing key. The selected deployment YAML's SHA-256 matched the [independent NEAR source](https://github.com/nearai/cvm-compose-files/blob/30fbba879f83dcd046f1b5e5f47c827e57dfdc1c/prod/deepseek-v4.1-flash-1017-vllm-dep4x2.yaml). | Native model not in reviewed policy; neither model report had the TLS fingerprint required by our direct verifier. Need independently reviewed workload and hardware verification that binds the relayed field-encryption key. |
| Gemma 4 26B A4B uncensored, Qwen 3.8 27B uncensored | RedPill evidence named a gateway source commit and a downstream TLS binding; the image digest and image provenance fields were null in both. | Establish accepted evidence for the running build, key custody and downstream inference. The [backend design](https://github.com/Dstack-TEE/private-ai-gateway/blob/3147f87151bb1960349a30022187108b2cbdfc70/docs/attested-confidential-inference.md) distinguishes gateway verification from provider-side privacy. No hardware pass or inference is claimed here. |

For EHBP, build `./cmd/nito-bundle-check` from `enclave-go/sidecar`.
Run `tools/check_nito_ehbp.py <exact-model:encrypted> --verifier <binary> --release-digest <digest>`
with `NITO_API_KEY`. Obtain the digest via the configured Tinfoil router
repository's current release, never from Nito's evidence. This is read-only
unless `--canary` is supplied. That flag uses `tinfoil-ehbp==0.6.0` and
allows **one** synthetic JSON request after verification, to Nito only;
there are no redirects or retries. A provider denial is not a failed hardware
signature, proof of an empty balance, or permission to use ordinary chat.
Even a successful direct canary would still need a fail-closed gateway
integration, real JSON/streaming and usage checks before labeling that route.

The ordinary key maps to `trustedrouter-nito-api-key`; configuration and
catalog discovery do not deploy or enable it. Verify each actual serving
cloud and provider-pinned inference/billing before removing catalog holds.

Sources: [Nito verification procedure](https://docs.trynito.ai/privacy/tee-attestation/verify-yourself-recipe),
[attestation contract](https://docs.trynito.ai/api/api-reference/attestation/public-contract),
[encrypted requests](https://docs.trynito.ai/api/api-reference/chat-and-text/encrypted).
