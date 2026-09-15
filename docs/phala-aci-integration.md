# Phala ACI integration

## Release status

**Review branch only. Do not merge or deploy this branch with an empty policy.**

The Go transport works against Phala's E2EE v2 wire protocol. A direct synthetic
request on September 13, 2026 returned `PONG`; its encrypted response, signed
receipt, and exact request/response hashes verified with the new Go code.
Receipt: `rcpt-7c299456d94c16e7ed05eef6`.

That diagnostic tested interoperability using public keys from the report. It
did not approve the production release, reconstruct its boot measurements, or
establish the KMS trust root. It is not a production E2EE certification.

`sidecar/phala_policy.json` intentionally contains no approved releases. This
branch replaces both prepaid and BYOK Phala chat dispatch with mandatory ACI.
Deploying it now would reject Phala requests. The current production catalog's
`provider_e2ee=false` must remain unchanged until all enablement gates pass.

## Request path

1. Open one certificate-verified TLS connection to `api.redpill.ai`. On Nitro,
   reuse the existing opaque TLS vsock route. Refuse redirects and reconnection.
2. Fetch a fresh, random nonce-bound ACI report over that connection. Send only
   public evidence and the observed TLS SPKI to the in-enclave verifier sidecar.
3. Verify ACI JCS keyset binding, nonce, expiry, Intel TDX signature and debug
   state, reviewed boot registers, replayed RTMR3, measured compose and OS hashes,
   and KMS signature chains for both receipt and X25519 encryption keys.
4. Require the exact authorized model and domain in the embedded release policy.
   A policy is committed with the measured enclave image, never taken from the
   endpoint or a runtime environment override.
5. Find an unexpired upstream session with complete content-addressed evidence,
   an approved verifier, and a TLS channel binding. Pin its ID in the request.
6. Encrypt whole message content fields, including structured image content,
   with fresh X25519 ephemeral keys, HKDF-SHA256, and AES-256-GCM. Authenticate
   the model, field path, nonce, direction, and timestamp in the AAD.
7. Collect the original encrypted SSE within an 8 MiB limit. Authenticate and
   decrypt every generated content field. Verify the signed receipt against the
   exact body hashes, model, selected upstream, session, and stream ID.
8. Only then pass the real provider SSE through the existing translator. An
   invalid receipt cannot release output or the terminal event that permits
   normal settlement.

The main process imports only the small protocol package and JCS dependency.
Intel verification and KMS signature recovery stay in the existing sidecar
module. Prompts, credentials, and decrypted outputs are never sent to the
sidecar or written to diagnostics by this implementation.

## Scope and tradeoffs

The first implementation buffers upstream SSE before releasing output. It has
two admission slots and an 8 MiB encrypted-response limit, fails busy requests
promptly, and uses a five-minute overall deadline. It does not provide low TTFT
streaming. This can conflict with the existing gateway first-byte deadline and
is an additional production-readiness gate. Do not increase global timeouts to
hide the tradeoff. A later streaming design can release authenticated deltas
and defer only successful completion until the receipt audit, with an explicit
contract for partial output and stream failure.

The Phala v2 contract does not encrypt tool definitions, function arguments,
structured-output schemas, caller metadata, or arbitrary control fields. The
adapter rejects these fields rather than exporting their content in cleartext.
Text and encrypted whole-message image arrays are supported. The Phala v2
protocol is frozen and its published support window runs through February 10,
2027; track its v3 replacement before enabling a long-lived production contract.

Upstream hardware appraisal is **delegated to the reviewed, measured Phala
aggregator code**. Go verifies the signed result and immutable raw evidence
publication; it does not independently run every upstream vendor's GPU verifier.
Reviewing and pinning the aggregator's actual verifier configuration is therefore
mandatory. A provider assertion or evidence hash by itself is insufficient.

## Enablement gates

- Obtain an authenticated production KMS root and independently reconstruct
  MRTD/RTMR0/RTMR1/RTMR2 from the approved OS artifacts and VM configuration.
- Review the measured compose, launcher, immutable source/image pins, key custody,
  logging, runtime configuration, and downstream verification behavior. Commit a
  documented policy for each approved domain/model/release tuple. Do not copy
  measurements out of a live quote and treat that as approval.
- Resolve the streaming delivery/first-byte deadline tradeoff above, including
  disconnect and billing tests before advertising ordinary streaming support.
- Require a production canary for every admitted upstream, including key rotation,
  expiry, replay, stream corruption, receipt absence, session replacement, and
  selected-model billing. Keep the E2EE catalog flag disabled for failing routes.
- Stage one region, verify real attestation and encrypted inference, then roll
  forward region by region. Do not merge this branch merely because unit CI is
  green. Its default empty policy disables Phala inference.

## What to send Phala

We have a native Go ACI/E2EE v2 client working against your API. A direct Qwen
request returned PONG, and decryption plus the signed receipt and exact wire
hashes passed (`rcpt-7c299456d94c16e7ed05eef6`). We need the authenticated KMS root,
approved release/compose artifacts, and OS/VM inputs for our independent trust
policy before we enable it for customers.

The GLM 5.2 route still has an evidence-publication blocker. Receipt
`rcpt-d5895fcb4a7f5dd7b38b7ce2` cites session
`1d2a185185e9e2fbf45959d01193d28bd43a159e09471ed37cff684cc2c3f87a`, whose
`evidence` is `{}`. Your published TypeScript verifier rejects it as
`upstream-2: evidence does not hash`. In the tested source revision,
`src/aggregator/service/forward.rs` deliberately drops evidence for per-instance
Chutes sessions to stabilize their cache identity. Please keep the selected
instance's CPU/GPU/nonce/channel proof available for the receipt lifetime and
separate cache identity from evidence publication. We will not skip this check.

We also saw one HTTP 412 between two successful direct v2 wire tests. Your server
maps this to `session_not_accepted`. Please clarify how clients should select a
currently usable session and handle rotation across replicas without discarding
session pinning. We have not added automatic POST retries.

## Verification

Local regression coverage includes public protocol vectors, AAD substitution,
wrong model/session, signature tampering, empty evidence, boot/KMS/policy failures,
BYOK isolation, plaintext response rejection, truncated SSE, and zero caller
output on receipt failure. Hardware fixtures are synthetic; passing them does
not establish the current production release's trust policy.

```sh
cd enclave-go
go test -race -tags 'cloud_gcp,llm_multi' ./...
go vet -tags 'cloud_gcp,llm_multi' ./...
go test -race -tags 'cloud_aws,llm_multi' ./internal/llm ./phalaaci
go test -race -tags 'cloud_azure,llm_multi' ./internal/llm ./phalaaci
cd sidecar
go test -race -tags cloud_gcp ./...
go test -race -tags cloud_aws ./...
go vet -tags cloud_gcp ./...
```

## Protocol references

The implementation was checked against Phala's source at commit
`19daf2b7152eeaf1f8be3fd66d261b8c1ce8eac5` and published verifier 0.7.2:

- [ACI specification](https://github.com/Dstack-TEE/private-ai-gateway/blob/19daf2b7152eeaf1f8be3fd66d261b8c1ce8eac5/spec/aci.md)
- [E2EE v2 contract](https://github.com/Dstack-TEE/private-ai-gateway/blob/19daf2b7152eeaf1f8be3fd66d261b8c1ce8eac5/spec/e2ee-v2.md)
- [Published AAD vectors](https://github.com/Dstack-TEE/private-ai-gateway/blob/19daf2b7152eeaf1f8be3fd66d261b8c1ce8eac5/spec/e2ee-v2-test-vectors.md)
- [Dstack KMS signature-chain verifier](https://github.com/Dstack-TEE/private-ai-gateway/blob/19daf2b7152eeaf1f8be3fd66d261b8c1ce8eac5/src/aci/verifier/dstack.rs)
- [Production verification prerequisites](https://github.com/Dstack-TEE/private-ai-gateway/blob/19daf2b7152eeaf1f8be3fd66d261b8c1ce8eac5/docs/quickstart.md)
