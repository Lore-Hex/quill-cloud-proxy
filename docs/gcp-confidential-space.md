# Quill Cloud on GCP Confidential Space

A second-vendor deployment of the same trust property we just shipped on
AWS. GCP's [Confidential Space](https://cloud.google.com/confidential-computing/confidential-space/docs/confidential-space-overview)
is the closest analogue to AWS Nitro Enclaves; the architecture is in
several ways *simpler*.

**Status:** the unified-codebase refactor landed in PR #16. The same
`enclave-go/` source builds either cloud:

```bash
go build -tags aws ./cmd/enclave   # AWS Nitro + Bedrock (default)
go build -tags gcp ./cmd/enclave   # GCP Confidential Space + Vertex AI
```

CI exercises both targets. Code-side, the GCP path is **6.3 MB** (smaller
than the AWS 7.1 MB — fewer transitive deps; the Vertex client is hand-
rolled `net/http` rather than the SDK).

What's *not* yet shipped on GCP:

- **Infrastructure**: Terraform module for Artifact Registry + KMS +
  Secret Manager + Confidential Space MIG + GLB. No GCP project is
  deployed yet.
- **Trust page** doesn't show the GCP image digest yet (waiting on first
  GCP build to publish).
- The other `internal/*` packages (`attestation`, `bootstrap`, `entropy`)
  are still AWS-specific behind their default-aws build tag. A real GCP
  deploy needs equivalents (vTPM attestation, env-based bootstrap,
  no-op entropy).

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

## What's already shared (unified codebase as of PR #16)

| Package | Status |
|---|---|
| `internal/adapter` (OpenAI ↔ Anthropic) | shared, no build tag |
| `internal/auth` (bearer hash) | shared |
| `internal/enclavetls` (self-signed cert + TLS server wrap) | shared |
| `internal/llm/iface.go` (Client interface) | shared |
| `internal/llm/aws.go` (Bedrock impl) | `//go:build !gcp` |
| `internal/llm/gcp.go` (Vertex impl, hand-rolled net/http) | `//go:build gcp` |
| `cmd/enclave/main.go` | shared; uses `llm.Client` interface |

The `internal/llm` swap is what makes "deploy to either cloud" a one-flag
build. The hand-rolled Vertex client uses Workload Identity from the GCE
metadata server — no oauth2 lib, no Google API transport, no gRPC. ~150
lines of `net/http`.

## What still needs the same treatment

These are AWS-specific today behind a default-aws import; a real GCP
deploy needs `gcp.go` siblings:

| Package | Currently | On GCP |
|---|---|---|
| `internal/bootstrap` (vsock dial to parent) | AWS only | direct env vars + Workload Identity |
| `internal/attestation` (NSM ioctl → COSE/CBOR) | AWS only | HTTP call to Confidential Space's local attestation server, returns Google-signed OIDC JWT |
| `internal/entropy` (NSM RNG → kernel pool seed) | AWS only | drop — Confidential Space VMs don't have the same boot-entropy starvation |
| `internal/vsockhttp` (vsock-tunneled HTTPS to Bedrock) | AWS only | not needed — Confidential Space has direct egress |

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

### Phase 0 — feasibility ✅ done

- Anthropic Claude Opus 4.7 is GA on Vertex AI as `claude-opus-4-7` —
  confirmed via [Anthropic's docs](https://platform.claude.com/docs/en/api/claude-on-vertex-ai).
  Available on global / `us`-multi-region / regional endpoints.
- Confidential Space supports `us-central1`, `us-east4`, `europe-west4`;
  intersects with Vertex regional availability cleanly.

### Phase 1 — port `enclave-go` ✅ done in PR #16

- `internal/llm` package with build-tag-gated AWS + GCP impls.
- Hand-rolled Vertex client (no Google SDK; just `net/http` + the
  metadata server). 6.3 MB binary.
- CI matrix builds + tests both `[aws, gcp]` targets.
- `Dockerfile.enclave.gcp` produces an amd64 OCI image suitable for
  Confidential Space.

### Phase 2 — fill in the remaining `internal/*` GCP siblings (~½ day)

- `internal/bootstrap/gcp.go` (`//go:build gcp`): load device list from
  Secret Manager via Workload Identity. No vsock; the env arrives as a
  baked-in workload spec.
- `internal/attestation/gcp.go`: HTTP GET against the Confidential Space
  attestation server, returns a Google-signed OIDC JWT bound to the
  workload's image digest. The existing `/attestation` HTTP handler in
  main.go just forwards whatever bytes come back.
- `internal/entropy/gcp.go`: no-op (Confidential Space VMs don't have
  the boot-entropy starvation that motivated the AWS NSM seeding).

### Phase 3 — infra (~1 day)

- New `gcp/` subdir of `Lore-Hex/quill-cloud-infra` (parallel to the
  AWS modules):
  - Artifact Registry repo for the workload image
  - KMS key with attestation-condition policy bound to the published
    image digest
  - Secret Manager secret for the device-key blob, decryptable only by
    a Confidential Space workload at the published digest
  - Confidential Space VM template + Managed Instance Group
  - GLB with TCP passthrough on :443
  - Cloud DNS for `api-gcp.quill.lorehex.co`
- Same Sigstore signing applied to a new `image-digest.txt` published
  alongside `pcr0.txt` on the trust page.

### Phase 4 — multi-cloud trust page (½ day)

- Trust page lists BOTH AWS PCR0 and GCP image digest, each with their
  own `verify-attestation` recipe.
- Optional: device-side attestation logic chooses one or both providers
  per request (round-robin, failover, or user pick).

### Phase 5 — cutover (½ day)

- Provision GCP, point `api-gcp.quill.lorehex.co` at the GLB.
- Smoke a Google-OIDC-aware variant of `verify-attestation.py`.
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

Phases 0 and 1 are done. The realistic next blocker is the GCP project
itself — needs a billing account linked, `aiplatform.googleapis.com`
enabled, and ADC quota project set. Once that's in place, Phase 2
(filling in the remaining `internal/*` GCP siblings) is ~½ day of
mechanical work. Phase 3 (Terraform) is the bigger piece.

The AWS deploy keeps serving the prompt path while GCP gets built up;
nothing is on a critical path until we want geographic redundancy.
