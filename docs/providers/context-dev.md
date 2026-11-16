# context.dev hosted web search

Status: implementation pending full CI, measured release and production acceptance.
Do not advertise as live until the checks below have passed.

The existing hosted-search flow accepts `engine: "context"` (alias
`"context.dev"`). Omitting `engine`, or choosing `auto`, still selects Exa.
There is no fallback between engines and no automatic search retry.

Chat Completions and Responses use:

```json
{
  "type": "web_search",
  "engine": "context",
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
`QUILL_CONTEXT_DEV_SECRET`. GCP defaults to the provisioned secret; setting it
explicitly empty disables it. Azure defaults to disabled until its native
sealed bundle is provisioned. GCP's bootstrap IAM provisioning accepts
`CONTEXT_DEV_SECRET`. AWS uses its existing optional
bootstrap field; Azure includes the key in its sealed bundle. Never put this
credential in a control-plane request body or forward it on HTTP redirects.

GCP provisioning on 2026-11-16 UTC created only version 1 of this new secret,
verified an exact in-memory readback, and confirmed the sole resource-level
accessor is the existing `quill-workload` service account, matching Exa.
No serving workload was changed by provisioning; AWS/Azure copies are pending.

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
