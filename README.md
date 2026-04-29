# quill-cloud-proxy

The prompt-handling proxy for Quill Cloud, runs **inside an AWS Nitro Enclave**.
Open source. Zero data retention. The signed binary is the boundary.

## What this repo is

Two binaries that ship together:

| Package        | Language | Where it runs                | What it does                                                |
|----------------|----------|------------------------------|-------------------------------------------------------------|
| `enclave-go/`  | Go       | inside the Nitro Enclave     | Receives HTTP over vsock, hashes the bearer, calls Bedrock via a vsock-tunneled HTTPS client (TLS terminates inside the enclave), streams OpenAI-format chunks back. No disk, no logging, no network except vsock. Static-PIE binary on a `scratch` base image so the EIF/PCR0 surface is one auditable file. |
| `parent/`      | Python   | on the EC2 host (outside)    | HTTPS listener on `:8443`, byte-pump relay between client TLS and the enclave, hourly heartbeat, DynamoDB usage flush, operator `/admin/usage`, and the bootstrap-RPC vsock server (port 9000) that hands the enclave the device-key list + AWS credentials at startup. |

Plus operator tools (`tools/`) and a static trust page (`trust-page/`).

## Trust property

The KMS keys needed to (a) decrypt the device-key list and (b) call Bedrock
are released **only** to an enclave whose `PCR0` measurement matches the
published value. Change a single line of enclave code → new PCR0 → KMS denies
→ service breaks. Anyone can rebuild from this repo and check the hash.

> **Verify any deployed Quill in <2 min:**
> ```bash
> ./tools/verify-pcr0.sh
> ```
> Rebuilds the enclave deterministically and compares to the value at
> [`trust-page/pcr0.txt`](trust-page/pcr0.txt) and at
> <https://trust.quill.lorehex.co/pcr0.txt>.

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
├── enclave/      # runs inside the Nitro Enclave
├── parent/       # runs on the EC2 host
├── tools/        # operator scripts (seal-keys, revoke-key, verify-pcr0)
├── trust-page/   # static site at trust.quill.lorehex.co
├── tests/        # pytest, runs locally + in CI (mocks vsock + NSM)
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

## License

Apache 2.0. See [`LICENSE`](LICENSE).
