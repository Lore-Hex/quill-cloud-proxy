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

The ordinary key maps to `trustedrouter-nito-api-key`; configuration and
catalog discovery do not deploy or enable it. Verify each actual serving
cloud and provider-pinned inference/billing before removing catalog holds.

Sources: [Nito verification procedure](https://docs.trynito.ai/privacy/tee-attestation/verify-yourself-recipe),
[attestation contract](https://docs.trynito.ai/api/api-reference/attestation/public-contract),
[encrypted requests](https://docs.trynito.ai/api/api-reference/chat-and-text/encrypted).
