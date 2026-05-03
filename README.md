# quill-cloud-proxy

The prompt-handling proxy for Quill Cloud. The workload runs inside **AWS Nitro
Enclaves** or **GCP Confidential Space**, depending on the deployment target.
Open source. Zero data retention. The signed workload image is the boundary.

## What this repo is

Two binaries that ship together:

| Package        | Language | Where it runs                | What it does                                                |
|----------------|----------|------------------------------|-------------------------------------------------------------|
| `enclave-go/`  | Go       | inside Nitro/CSP workload    | Authenticates bearer hashes, calls the configured LLM provider, terminates workload TLS, serves `/attestation`, and streams OpenAI-format chunks back. AWS builds use vsock; GCP builds use Confidential Space ingress/egress. |
| `parent/`      | Python   | on the EC2 host (AWS only)   | Operator/admin HTTP endpoints, legacy HTTP-over-vsock relay, raw TCP pump for enclave-terminated TLS, heartbeat, DynamoDB usage, and bootstrap-RPC vsock server. |

Plus operator tools (`tools/`) and a static trust page (`trust-page/`).

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
`gcp-release.json`. The deploy workflow signs those files with keyless cosign
and publishes the files plus `.bundle` proofs to `trust.quill.lorehex.co`.

## Routing

The GCP OpenRouter workload accepts OpenAI-compatible `model`, `models`, and
`provider` request fields. It retries the next model candidate before streaming
if OpenRouter returns `429` or `5xx`, forwards provider preferences such as
`order`, `only`, `ignore`, `allow_fallbacks`, `sort`, and `max_price`, and
keeps `provider.data_collection` pinned to `deny` for the hosted no-retention
claim even if a caller asks for a weaker setting.

## License

Apache 2.0. See [`LICENSE`](LICENSE).
