# Plan: Quill Cloud on GCP Confidential Space

A second-region (and second-vendor) deployment of the same trust property
we just shipped on AWS. GCP's [Confidential Space](https://cloud.google.com/confidential-computing/confidential-space/docs/confidential-space-overview)
is the closest analogue to AWS Nitro Enclaves; the architecture is in
several ways *simpler*.

Status: planning. Not yet started. We don't ship anything until the
multi-cloud trust story is documented + we have time to maintain two
deploys.

## TL;DR

| AWS | GCP equivalent |
|---|---|
| Nitro Enclave + NSM | Confidential Space (AMD SEV-SNP + vTPM) |
| EIF (kernel + initramfs + binary) | OCI container image (just the binary) |
| `nitro-cli build-enclave` → PCR0 | `docker push` → image digest |
| `kms:RecipientAttestation:PCR0` condition | KMS condition on attestation-token claims |
| NSM CBOR attestation document | Google-issued OIDC JWT (vTPM-rooted) |
| Bedrock | Vertex AI (Anthropic Claude is available there) |
| ALB + NLB + parent + vsock-proxy | Confidential Space VM + GLB. No parent. No vsock. |

The big simplification: **no parent process, no vsock-to-tcp pump, no
EIF build dance.** Confidential Space VMs have direct network egress, so
the workload talks to Vertex AI straight from inside the attested
container. PCR0 → image digest → trivially reproducible: `docker
manifest inspect <image>` and you're done.

## What's reusable from `enclave-go/`

Almost all of it. The Go binary, the OpenAI ↔ Anthropic adapter, the
`/attestation` handler, the cert-pinning trust setup, the `enclavetls`
self-signed cert generator — all of these are platform-agnostic. The
parts that need rewriting are tiny:

| Currently | On GCP |
|---|---|
| `internal/bootstrap` (vsock dial to parent) | direct env vars + Vertex AI credentials via Workload Identity |
| `internal/vsockhttp` (vsock-tunneled HTTPS to Bedrock) | standard `net/http` to Vertex AI endpoint |
| `internal/attestation` (NSM ioctl → CBOR doc) | `attestation_verifier`-style HTTP call to the local attestation server, returns a JWT |
| `internal/entropy` (NSM RNG → kernel pool seed) | drop — Confidential Space VMs don't have the same boot-entropy problem |
| `internal/bedrock` (SigV4 + bedrockruntime SDK) | replace with Vertex AI's Anthropic-on-Vertex API client |
| Dockerfile.enclave (FROM scratch + EIF wrap) | `FROM scratch` stays; just push the OCI image to Artifact Registry |

The `cmd/enclave/main.go` flow — bootstrap → listen TLS → handle
`/v1/chat/completions` and `/attestation` — is unchanged in shape.

## Architecture

```
                client
                   ↓ TLS, hostname pinned
        GCP Global LB (TCP passthrough, port 443)
                   ↓ TCP, no decryption
       Confidential Space VM (AMD SEV-SNP)
        ┌─────────────────────────────────┐
        │ Workload container (image       │
        │ digest = published value)       │
        │                                 │
        │ • TLS termination               │
        │ • bearer auth                   │
        │ • OpenAI ↔ Anthropic adapter    │
        │ • /attestation → Google JWT     │
        │ • Vertex AI: Claude Opus 4.7    │
        └─────────────────────────────────┘
                   ↓ Workload Identity Federation
              KMS releases credentials only when
              attestation token's `image_digest`
              claim matches the published value
                   ↓
              Vertex AI / Anthropic-on-Vertex
```

Direct network egress means the workload itself calls Vertex AI. No
"parent as TCP pump" is needed — the workload IS in the network path.
That removes a whole class of complexity (vsock, vsock-proxy daemon,
parent-side bootstrap RPC).

## Trust property

The same four-binding chain holds, with GCP-flavoured pieces:

1. Workload image digest is published (analogue of `pcr0.txt`).
2. KMS attestation policy releases the Vertex AI service-account
   credentials only when the attestation token's `image_digest` claim
   matches that published digest.
3. `/attestation` endpoint returns the live attestation JWT, which has
   signed claims `image_digest`, `image_reference`, `image_signatures`,
   plus an embedded TLS public key (we set this in our workload start).
4. The TLS cert presented to clients matches the public key in the JWT.

Everything else in the trust page (signed PCR0 in Sigstore Rekor) maps
cleanly: instead of signing `pcr0.txt`, sign `image-digest.txt`. Same
cosign-keyless flow.

## Phased plan

### Phase 0 — feasibility (½ day)

- Confirm Anthropic Claude Opus 4.7 is available on Vertex AI in a
  region that supports Confidential Space. (US-Central1, US-East4 are
  current options; Anthropic-on-Vertex availability varies — check.)
- Confirm pricing: Vertex Anthropic-on-Vertex pricing vs. Bedrock for
  the same model. Confidential VMs are ~10–15% premium over standard
  VMs; cheaper than enclave hosting overhead today.
- Verify GCP credits cover at least one month of running.

### Phase 1 — port `enclave-go` to a Confidential-Space-ready container (1–2 days)

- New top-level dir `enclave-gcp/` mirroring `enclave-go/` structure.
- Replace `internal/bedrock` → `internal/vertex` (Vertex AI SDK in Go
  exists; or bypass and call the REST API directly with SigV4-equivalent
  IAM tokens). Anthropic-on-Vertex's response stream IS Anthropic-native
  SSE, so the existing adapter logic translates 1:1.
- Replace `internal/bootstrap` → load device list + Vertex SA creds from
  KMS-encrypted Secret Manager secret, decrypted via Workload Identity.
- Replace `internal/attestation` with a thin client to the local
  attestation HTTP server (Confidential Space exposes
  `http://metadata.google.internal/v1/instance/`) for fetching the
  attestation token.
- Drop `internal/entropy`, `internal/vsockhttp`, `internal/bootstrap`'s
  vsock client.
- Same `cmd/enclave/main.go` flow with the swapped imports.

### Phase 2 — infra (1 day)

- `quill-cloud-infra-gcp/` (or a `gcp/` subdir of the existing repo).
- Terraform with the GCP provider:
  - Artifact Registry repo for the workload image
  - KMS key with attestation-condition policy on the workload
  - Secret Manager secret for the device-key blob
  - Confidential Space VM template + MIG
  - GLB with TCP passthrough on :443
  - Cloud DNS for `api-gcp.quill.lorehex.co` (or fold it under a
    region-aware hostname)
- Same Sigstore signing for the image digest.

### Phase 3 — multi-cloud trust page (½ day)

- Trust page lists BOTH AWS PCR0 and GCP image digest.
- Verify recipes for each.
- Optional: device-side attestation logic chooses one or both providers
  per request (round-robin, failover, or user pick).

### Phase 4 — cutover dance, same shape as AWS (½ day)

- Provision GCP, point `api-gcp.quill.lorehex.co` at the GLB.
- Smoke `verify-attestation.py` (with a Google-OIDC-aware verify path).
- Once verified, optionally migrate `api.quill.lorehex.co` to
  round-robin DNS across AWS NLB + GCP GLB. Both are zero-retention,
  both are attested, both publish their measurements.

## What's harder vs. AWS

1. **Anthropic on Vertex** is real (Claude is offered there) but the
   model catalogue lags Bedrock by weeks. If we want to use the latest
   Opus the day it ships, AWS may be ahead.
2. **GCP attestation tooling is younger.** Sigstore-style verification
   exists but the public docs are thinner than AWS's. We'll write more
   glue.
3. **Confidential Space is GA-but-evolving.** Workload image format and
   attestation JWT claims have iterated over the past year. Pin against
   a specific Confidential Space launcher version.

## What's easier vs. AWS

1. **OCI image digest as the measurement** — every Docker user can
   compute it; `docker pull <image>@<digest>` is the entire
   "reproduce" step.
2. **No vsock, no parent, no EIF.** The workload runs as a normal
   container. Logs, networking, debugging — all ordinary tooling.
3. **Attestation token is a JWT** — verifiable with any standard JWT
   library. No CBOR/COSE.
4. **Network egress is direct.** No "vsock-proxy daemon on the parent"
   to relay TLS to Vertex; the workload calls Vertex straight. The
   "trust the parent doesn't see plaintext" concern doesn't even come
   up because there's no parent.

## Recommended next step

Phase 0 first — confirm Vertex has Opus 4.7 in a Confidential-Space-
supported region with our GCP credits before we sink time into Phase 1.
If yes, Phase 1 is mostly a swap of two `internal/*` packages plus a
fresh Terraform module. ~3 days of focused work to a working second
deploy.

If no (Vertex doesn't have the model we want yet), park this until it
does. The plan ages well; the AWS deploy keeps serving meanwhile.
