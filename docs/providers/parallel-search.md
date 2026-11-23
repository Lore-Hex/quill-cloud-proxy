# Parallel Search

The hosted search selector `engine: parallel` uses Basic mode at the fixed
Parallel v1 search endpoint. Omitting the selector still uses Exa. Search
options are validated before dispatch, the secret never follows a redirect,
and a missing credential does not select a substitute. The normal hosted
search privacy restrictions apply.

Reserve $0.005 per permitted call; settle the search charge only for a
successful response identifying exactly one `sku_search` unit. This is the
published list tariff, not a provider invoice. Reject unknown units instead
of treating them as free. Limit each search to at most 10 results and do not
enable paid extraction. Use top-level `max_chars_total`; the live API warns
that nested `max_chars_per_result` is ignored. Also bound each returned excerpt
locally. See [API](https://docs.parallel.ai/api-reference/search/web) and
[pricing](https://parallel.ai/pricing).

Provision `PARALLEL_API_KEY` as `trustedrouter-parallel-api-key` per cloud
before enabling it. GCP bootstrap IAM uses `PARALLEL_SECRET`, and GCP launch
and Azure sealing use `QUILL_PARALLEL_SECRET`. Do not change an immutable
Azure bundle manifest by hand. AWS uses the optional bootstrap field and an
exact HTTPS tunnel at parent CID 3, port 8139. Validate Chat Completions and
Responses billing on each serving gateway before advertising it as live.
