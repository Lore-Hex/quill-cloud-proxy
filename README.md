# quill-cloud-proxy

[![CI](https://github.com/Lore-Hex/quill-cloud-proxy/actions/workflows/ci.yml/badge.svg)](https://github.com/Lore-Hex/quill-cloud-proxy/actions/workflows/ci.yml)
[![Deploy enclave GCP](https://github.com/Lore-Hex/quill-cloud-proxy/actions/workflows/deploy-enclave-gcp.yml/badge.svg)](https://github.com/Lore-Hex/quill-cloud-proxy/actions/workflows/deploy-enclave-gcp.yml)
[![Publish trust page](https://github.com/Lore-Hex/quill-cloud-proxy/actions/workflows/publish-trust-page.yml/badge.svg)](https://github.com/Lore-Hex/quill-cloud-proxy/actions/workflows/publish-trust-page.yml)
[![Verifiable trust](https://img.shields.io/website?url=https%3A%2F%2Ftrust.trustedrouter.com&label=trust)](https://trust.trustedrouter.com)
[![JavaScript SDK](https://img.shields.io/npm/v/@lore-hex/trusted-router?label=JS%20SDK&logo=npm)](https://www.npmjs.com/package/@lore-hex/trusted-router)
[![Python SDK](https://img.shields.io/pypi/v/trusted-router-py?label=Python%20SDK&logo=pypi)](https://pypi.org/project/trusted-router-py/)
[![License: BUSL-1.1](https://img.shields.io/badge/License-BUSL--1.1-blue.svg)](LICENSE)

The prompt-handling proxy for Quill Cloud. The workload runs inside **AWS Nitro
Enclaves** or **GCP Confidential Space**, depending on the deployment target.
Open source. Zero data retention. The signed workload image is the boundary.

## What this repo is

Two binaries that ship together:

| Package        | Language | Where it runs                | What it does                                                |
|----------------|----------|------------------------------|-------------------------------------------------------------|
| `enclave-go/`  | Go       | inside Nitro/CSP workload    | Authenticates bearer hashes, calls the configured LLM provider, terminates workload TLS, serves `/attestation`, and streams OpenAI-format chunks back. AWS builds use vsock; GCP builds use Confidential Space ingress/egress. |
| `parent/`      | Python   | on the EC2 host (AWS only)   | Operator/admin HTTP endpoints, legacy HTTP-over-vsock relay, raw TCP pump for enclave-terminated TLS, heartbeat, DynamoDB usage, and bootstrap-RPC vsock server. |

`enclave-go/internal/byokcache` decrypts TrustedRouter BYOK envelopes inside
the attested gateway. It unwraps each per-secret DEK with Cloud KMS, decrypts
the provider key with AES-256-GCM, and keeps the plaintext provider key only in
short-lived process memory keyed by the control plane's non-secret
`byok_cache_key`. BYOK rotation changes that key; BYOK delete stops returning an
envelope from authorization and stale cache entries expire by TTL.

Plus operator tools (`tools/`) and a static trust page (`trust-page/`).

## Production release coordination

Gateway and control-plane deployments share a two-cloud limit: at most two
clouds may change while a third stays healthy and unchanged. One cloud cannot
run two independent deployments. GCP's workflow owns its reservation through
regional verification and final trust publication. Manual AWS/Azure tools
require an outer reservation across all deploy and attestation phases; they do
not automatically release between phases or on failure.

`tools/cloud-rollout.py` loads the control-plane coordinator from the immutable
commit and SHA256 in `tools/cloud-rollout-source.json`. See the
[activation and recovery runbook](https://github.com/Lore-Hex/quill-router/blob/main/docs/design/two-cloud-rollouts.md)
before a production rollout. Never delete or expire the shared journal to
bypass an interrupted deployment.

## Trust property

On AWS, the KMS keys needed to decrypt the device-key list are released only to
an enclave whose `PCR0` measurement matches the published value. On GCP, Secret
Manager access is gated by Confidential Space image attestation. Change a single
line of workload code → new measurement/image digest → secret access fails.
Anyone can rebuild from this repo and check the published measurement.

> **Verify any deployed AWS Quill in <2 min:**
> ```bash
> ./tools/verify-pcr0.sh
> ```
> Rebuilds the enclave deterministically and compares to the value at
> [`trust-page/pcr0.txt`](trust-page/pcr0.txt) and at
> <https://trust.quill.lorehex.co/pcr0.txt>.
>
> **Verify the current GCP production build:**
> compare the live Confidential Space JWT's
> `submods.container.image_digest` claim to
> [`trust-page/image-digest-gcp.txt`](trust-page/image-digest-gcp.txt).
> The device service does this automatically before sending prompt traffic.

## What gets retained

| Type                                          | Retained? |
|-----------------------------------------------|:--:|
| Prompt content (request body)                 | ❌  |
| Completion content (response body)            | ❌  |
| Bearer tokens, key hashes                     | ❌  |
| IPs of clients (beyond ALB access log 24h TTL)| ❌  |
| Per-request timestamps tied to a device       | ❌  |
| Per-device daily aggregate counts (req, tokens, errors), 90-day TTL | ✅ |
| Hourly across-all-devices request count (heartbeat)               | ✅ |

The aggregate counts are the audit/billing trail — they show
"device q-002 made N calls today" with no path to which prompts those were.

## Repo layout

```
quill-cloud-proxy/
├── enclave-go/   # workload binary for AWS Nitro or GCP Confidential Space
├── parent/       # AWS parent host process
├── tools/        # operator scripts (seal-keys, revoke-key, verify-pcr0)
├── trust-page/   # static site at trust.quill.lorehex.co
├── parent/tests/ # pytest for parent process
└── docs/         # architecture, threat model, build verification
```

## Local dev

```bash
cd quill-cloud-proxy
make sync           # uv sync both packages
make check          # ruff + mypy --strict + pytest
make run-mock       # boots parent + a mock-enclave subprocess on localhost
```

`make run-mock` swaps the vsock transport for a Unix socket so you can hit
the proxy on `localhost:8443` from a laptop without a Nitro host. The mocks
are clearly fenced off from production code paths.

## Deployment

Provisioned by [`Lore-Hex/quill-cloud-infra`](https://github.com/Lore-Hex/quill-cloud-infra)
(Terraform). See that repo's README for the bootstrap.

GCP releases use a formal image tag and committed trust files:

```bash
make gcp-release
git diff trust-page/
```

That writes `image-reference-gcp.txt`, `image-digest-gcp.txt`, and
`gcp-release.json`.

Publishing and signing are separate from that write, and it is worth being
precise about which surface gets what, because a previous version of this
paragraph was wrong in a way that mattered:

* `trust.trustedrouter.com` (GitHub Pages) is the surface the trust page links
  to. `publish-trust-page.yml` deploys it and signs nothing: each plane's
  files are signed by that plane's `publish-trust-{gcp,aws,azure}.yml`, which
  commits the bundles, and Pages publishes them unchanged.
* `trust.quill.lorehex.co` (S3 + CloudFront) is the mirror.
  `publish-trust-s3.yml` publishes it after each Pages publish, one run at a
  time from a checkout of main, and nothing else writes to it.
  `gh workflow run publish-trust-s3.yml --ref main` runs it on demand.

Both publishers refuse a tree in which a file published at `trust-page/<name>`
and `trust-page/trust/<name>` differs between the two
(`tools/check-trust-copies.py`).
They also refuse a tree in which any bundle does not sign the document beside
it under its plane's identity (`tools/check-trust-signatures.py`). A commit that
changes a document still carries its previous bundle, so that commit's
publish stops there and the last good site stays live; the plane's signer
re-signs it, and the signer's completion publishes the document and its new
bundle together.
Pages replaces the whole site in one deployment. The S3 sync uploads object
by object, so while it runs a changed document can sit beside its old bundle;
`publish-trust-s3.yml` then compares each record and its bundle on the mirror
with main and fails if they differ.

AWS and Azure records are produced separately by
`tools/capture-plane-measurements.py` from live attestations, and signed by
`publish-trust-{aws,azure}.yml` under their own identities.

## Routing

The GCP OpenRouter workload accepts OpenAI-compatible `model`, `models`, and
`provider` request fields. It retries the next model candidate before streaming
if OpenRouter returns `429` or `5xx`, forwards provider preferences such as
`order`, `only`, `ignore`, `allow_fallbacks`, `sort`, `max_price`,
`require_parameters`, and `zdr`, and
keeps `provider.data_collection` pinned to `deny` for the hosted no-retention
claim even if a caller asks for a weaker setting.

The request boundary is allowlist-based. Unknown request/provider/plugin fields
return `400` with the exact field in `error.param`; known OpenRouter controls
that this release cannot honor return `501 not_supported_in_alpha` before
authorization. This prevents compatibility fields from becoming silent no-ops.

## Web search and citations

The attested `POST /v1/chat/completions` path supports OpenRouter's current
`openrouter:web_search` server tool and deprecated `plugins: [{"id":"web"}]`
surface. Search runs through Exa inside the enclave. Current tool parameters
include mode, per-call and total result limits, search-call limits, context
size, exact character limits, and domain filters. Unknown parameters return a
field-specific `400`; known engines or controls that are not implemented return
`501 not_supported_in_alpha`.

```python
from openai import OpenAI

client = OpenAI(
    api_key="sk-tr-...",
    base_url="https://api.trustedrouter.com/v1",
)

completion = client.chat.completions.create(
    model="google/gemini-3.5-flash",
    messages=[{"role": "user", "content": "What changed in Python this week?"}],
    tools=[{
        "type": "openrouter:web_search",
        "parameters": {
            "engine": "exa",
            "max_results": 5,
            "max_uses": 3,
            "allowed_domains": ["python.org"],
        },
    }],
)
print(completion.choices[0].message.annotations)
```

Search-native providers such as Perplexity may return top-level `citations` and
`search_results`. TrustedRouter preserves both and also emits OpenRouter-style
`choices[0].message.annotations`, including numbered references such as `[3]`.
Streaming sends the provenance chunk before the terminal finish chunk and
`[DONE]`.

The attested `POST /v1/responses` path supports OpenAI-compatible hosted web
search with `web_search` and the legacy `web_search_preview` alias. TrustedRouter
executes searches through Exa from inside the enclave, then gives bounded,
untrusted search evidence back to the selected model. Queries and result text do
not pass through the control plane or durable logs.

```python
from openai import OpenAI

client = OpenAI(
    api_key="sk-tr-...",
    base_url="https://api.trustedrouter.com/v1",
)

response = client.responses.create(
    model="openai/gpt-5.5",
    input="What changed in Python this week? Cite primary sources.",
    tools=[{"type": "web_search", "search_context_size": "low"}],
    include=["web_search_call.action.sources"],
    store=False,
)
print(response.output_text)
```

Search is intentionally unavailable for ZDR, E2E/confidential, and EU-pinned
requests until the search provider is contractually approved for those privacy
tiers. Unsupported hosted tools and advanced search controls fail explicitly;
they are never silently ignored.

## License

Business Source License 1.1. See [`LICENSE`](LICENSE). The source is public
so anyone can read, build, and verify the trust surface published at
https://trust.trustedrouter.com. Non-production use (security review, audit,
local evaluation) is free. Production use requires a commercial license from
Lore Hex Corp: licensing@trustedrouter.com. Each version converts to the
Apache License 2.0 four years after publication. Code published before
July 3, 2026 remains Apache-2.0.

### Enclave insufficient-credit backoff

`QUILL_BILLING_402_BACKOFF_MS` defaults to `5000`; `0` disables it. Invalid,
negative or overflowing values use the default. The shared Go control-plane
client reads this setting in every cloud. GCP deployments pass it through
Confidential Space's environment allowlist; Azure ACI passes it as a container
environment variable. On AWS Nitro, set the Docker build argument of the same
name before building the measured EIF (runtime parent environment cannot change
an enclave's environment).

A synchronous inference request denied by `/internal/gateway/authorize` with
HTTP 402 and `error.type=insufficient_credits` opens a fixed window for its
credential lookup digest and a SHA-256 digest of the method, route and exact
request body bytes plus canonical parsed header inputs, each length-prefixed.
These cover attribution, receipt opt-in and nonce, Host and effective
confidential routing. Observational client telemetry is excluded: it is forwarded
only to settle/refund, and malformed telemetry is dropped rather than rejecting
inference. Requests equivalent on these billing and validation inputs reuse the
ordinary error renderer, including the original request-ID headers and
Retry-After. Connection headers still follow the current connection's keep-alive
policy. Header or body
`idempotency_key` requests bypass reads and writes; other billing errors, auth
errors, metadata/discovery routes and job polling retain their ordinary handling.
The credential guard runs before billing reuse: a known credential rejection
wins and keeps its ordinary audit lines. Definitive credential rejections drop
that credential's billing entries through a per-credential index. An unobserved
revocation can remain stale for at most one fixed backoff window; balance top-ups
have the same delay for an identical request. Different bodies, models, routes or keyed header inputs
can still reach authorize during that window. The cache holds at most 4,096
entries and retains only digest/audit identifiers and public error fields, never
prompts or raw API keys. Hits and concurrent denials cannot extend the window. Expired
entries are evicted before live entries; capacity pressure closes the oldest
window early.

Suppressed requests skip authorize, audit identity lookup, and all three
`enclave.request_accept/start/end` lines, as well as client-context diagnostics
and other per-request stderr output. Connection request counts, response byte
counts and keep-alive limits still advance normally. Log-derived request totals
must add the `suppressed` counts in the summary below to ordinary request-end
counts. Authorize-attempt counts correctly exclude suppressed requests. A summary
is emitted once when an expired window is next encountered (including by another
credential), or when capacity pressure or credential invalidation closes it.
Summaries are written after unlocking and only for windows that suppressed
something; inactive windows need no timer:

```
enclave.billing_402_backoff credential_id="<existing audit ID>" credential_fingerprint="<lookup digest>" suppressed=49 window_ms=5000
```

The fingerprint remains available if the ordinary audit identity lookup fails.
Summaries are lazy and may be lost at process termination. Their counts cannot
fully reconstruct route/workspace breakdowns, latency distributions, byte totals
or abuse metrics.
Merging to main deploys this enclave-only change to the fleet; no control-plane
changes or new control-plane state are required.
