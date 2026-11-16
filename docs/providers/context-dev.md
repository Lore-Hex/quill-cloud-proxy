# context.dev hosted web search

Status: the initial GCP implementation passed production acceptance on
2026-11-16. The canonical-engine change and AWS/Azure activation still require
full CI, measured releases and per-cloud production acceptance. Do not advertise
those pending changes as live until the checks below have passed.

The hosted-search flow accepts `engine: "context.dev"` only. The former bare
`"context"` name is rejected before any provider invocation. Omitting `engine`,
or choosing `auto`, still selects Exa.
There is no fallback between engines and no automatic search retry.

Chat Completions and Responses use:

```json
{
  "type": "web_search",
  "engine": "context.dev",
  "search_context_size": "medium"
}
```

The Chat `openrouter:web_search` form puts `engine` inside `parameters`.
The `web` plugin also accepts it. Existing tool-call budgets, domain filters,
country-only location, citations, streaming, and untrusted-result isolation
are unchanged. The context.dev client allows 1-500 query characters and at
most 25 results. It requests highlights, not separately billed Markdown pages,
with a 20,000-character highlight limit and a ten-second partial-result deadline.

## Billing

The operator approved a conservative **$0.006 per reported provider credit**
tariff on 2026-11-15. It is twice the highest published top-up rate of
[$0.003 per credit](https://www.context.dev/pricing), not a verified actual
operator dollar cost or an assumption about the account's plan.

The reserve is two credits per ten requested results, rounded up, per allowed
search call. Only validated integer `key_metadata.credits_consumed` is settled;
an optional `X-Credits-Used` header must agree. Unused reservation is released
by the existing settlement contract. Invalid/missing/over-bound usage fails
closed, without inference replay. Model token charges remain separate.

For five requested results the maximum search charge is $0.012 per call.
Usage reports the engine, credit count, 6,000-microdollar credit tariff and
`conservative_credit_tariff` pricing basis. It does not report that amount as
`operator_web_search_cost_microdollars`.

## Privacy and keys

Search queries may contain prompt-derived data. The provider's
[privacy policy](https://www.context.dev/privacy) permits retention and use
for training unless applicable ZDR terms are enabled. No ZDR entitlement or
Confidential claim is made here. All existing ZDR, Confidential, E2E and EU
hosted-search restrictions stay enforced.

The operator key is read from `CONTEXT_DEV_API_KEY` in the local keyfile and
provisioned as `trustedrouter-context-dev-api-key` using the normal secret
tools. Do not print values or put them in workflow inputs. Bootstrap carries
`context_dev_api_key` only into the enclave. GCP/Azure select that secret with
`QUILL_CONTEXT_DEV_SECRET`. GCP defaults to the logical secret name; setting it
explicitly empty disables it. Azure remains disabled by default until a fresh
complete sealed bundle is provisioned and pinned before rendering the measured
deployment. GCP's bootstrap IAM provisioning accepts
`CONTEXT_DEV_SECRET`. AWS uses its existing optional
bootstrap field; Azure includes the key in its sealed bundle. Never put this
credential in a control-plane request body or forward it on HTTP redirects.

The production client uses the shared compiled provider egress guard, with only
`api.context.dev` added as an exact HTTPS/443 destination. Proxy environment
variables, private/reserved DNS answers, redirects, subdomains and alternative
ports remain rejected. AWS maps the exact host through CID 3, port 8138; its
parent vsock allowlist and listener use the same destination and port. TLS and
the provider credential remain inside the enclave. Provisioning must follow
the current AWS secret-release policy, not a legacy plaintext fallback.

GCP provisioning on 2026-11-16 UTC created only version 1 of this new secret,
verified an exact in-memory readback, and confirmed the sole resource-level
accessor is the existing `quill-workload` service account, matching Exa.
No serving workload was changed by provisioning; AWS/Azure copies are pending.

Azure preflight on 2026-11-16 found that bundle version
`8df3ba4381d74315b2d1c696e63e839d` was created on 2026-10-29, before Context's
name was added to the checked-in manifest on 2026-11-15. That name alone is not
evidence that the immutable bundle contains the credential. Generate and verify
a complete replacement bundle, preserve every existing provider binding, and
commit its generated manifest and immutable version before enabling Context.
Do not hand-edit a manifest to assert the contents of an old bundle.

The public documentation section is
[`/docs/web-search#context-dev`](https://trustedrouter.com/docs/web-search#context-dev).
Publish its canonical-engine and cloud-availability copy only after the
corresponding production checks pass.

## Release checks

1. Run the full build, vet, lint and test matrices plus parent/bootstrap guards.
2. Provision native secret copies and access through the normal tooling; verify
   presence without printing values, and enable only in reviewed deployment config.
3. Complete the measured gateway build, CI, signed trust and guarded rollout.
4. Verify stable serving images, regional attestation and unchanged negative controls.
5. Make bounded Chat/Responses JSON/SSE searches, checking actual credits,
   tariff metadata, exact-once settlement, privacy rejection and no fallback.
6. Publish user documentation only after the selected engine is serving.

Reference: [search API](https://docs.context.dev/api-reference/web-scraping/search).
