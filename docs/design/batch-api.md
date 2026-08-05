# Attested Batch API

## Contract

TrustedRouter implements the OpenRouter inline batch contract at the attested
API hostname:

- `POST /api/beta/batches`
- `GET /api/beta/batches/{id}`

Create requests require `endpoint`, `model`, and then `requests` in that wire
order. Supported item endpoints are `/v1/chat/completions`, `/v1/responses`,
`/v1/messages`, and `/v1/embeddings`. Each item has a unique `custom_id` and a
normal endpoint request body. Streaming items are rejected.

The observable lifecycle is `validating`, `in_progress`, `finalizing`, and
`completed`, with `failed`, `expired`, and `cancelled` reserved as terminal
statuses. The completion window is 24 hours. Completed results are inline and
preserve request order.

## Trust boundary

The parent relay remains an opaque TLS byte pump. Batch routing, validation,
encryption, execution, and result decryption all happen in the measured Go
enclave.

Submitting a batch opts into temporary encrypted content retention. The
enclave generates an AES-256-GCM data key per artifact, binds the ciphertext to
the batch ID and artifact kind with authenticated data, and wraps the data key
with Cloud KMS. GCS receives ciphertext only.

The raw API key is validated during submission and immediately discarded. It
is never persisted, even inside the encrypted artifact. Delayed execution uses
only the existing one-way key lookup hash through an enclave-internal Go
context. Public clients cannot supply that context, and each item still checks
key revocation, workspace state, budgets, and credits through the ordinary
authorization path.

Batch resources are fixed in the measured GCP image. They are deliberately not
launch-time environment overrides. Access tokens come from a Confidential
Space attestation JWT exchanged through a Workload Identity Pool. IAM grants
GCS and envelope-key access to exact approved image digests, production
Confidential Space, the TrustedRouter project, and its workload service
account.

This is the intended deployed policy, not a claim that GCP project
administrators are cryptographically unable to change IAM. Encrypted Batch
retention therefore depends on Cloud KMS, Cloud Storage, and project IAM
administration. It is a different trust boundary from the zero-retention
property of ordinary synchronous and streaming inference, and customers must
opt into it explicitly.

The bucket storage CMEK and application envelope key are separate. Cloud
Storage can use its CMEK without gaining the ability to unwrap batch DEKs.

Never write any of these values to logs or metadata objects:

- raw API key
- request body or prompt
- response body or completion
- artifact plaintext or DEK

Ordinary synchronous and streaming inference remains content-stateless.

## Execution

Every item is sent through `serveOne` over an in-memory connection. This reuses
the normal attested authorization, provider routing and fallback, BYOK policy,
settlement/refund, custom model, and orchestration implementations. It avoids a
second inference stack and prevents the worker from sending a raw key or prompt
through DNS or a regional network hop.

Items run with bounded concurrency. Each item uses a deterministic idempotency
key, `tr-batch:<batch-id>:<item-index>`, so restart recovery cannot
double-charge it. Provider rollover remains inside the ordinary gateway path.
After that path settles or refunds its authorization, a final HTTP or transport
failure becomes the item's error result; the batch worker does not replay a
terminal authorization.

Each completed item is encrypted and checkpointed before job progress advances.
A restarted worker recovers checkpoints instead of invoking the provider again.
Aggregate usage is rebuilt from integer token and microdollar values in those
encrypted checkpoints. The worker does not create a second aggregate results
artifact: completed polling reconstructs the ordered inline results from the
per-item checkpoints. This avoids a successful large batch becoming
unreadable because a duplicate final object exceeded an object-size limit.

## Regional recovery

Active jobs live under a separate prefix from terminal jobs. Workers claim an
active metadata object with a GCS generation precondition and renew the lease
while items execute. Checkpoints and heartbeats share one serialized generation
cursor. Loss of the lease cancels the worker before it can finalize the job.

Terminal metadata and encrypted artifacts are automatically deleted after 30
days. Strict EU artifact residency is not part of the first beta and must be
documented as unsupported until regional stores are implemented.

## Limits

- 32 MiB batch-create HTTP body
- 64 MiB response body per item
- 256-byte `custom_id`
- no streaming items
- no list, cancel, or file-upload endpoints
- normal TrustedRouter route pricing; no blanket batch discount

## Deployment invariants

Before rolling an image:

1. Resolve the immutable OCI digest and verify it matches `IMAGE_DIGEST`.
2. Grant that digest access to the batch bucket and envelope KMS key.
3. Roll one region at a time with normal attestation and synthetic gates.
4. Run a real create, poll, content, ownership-isolation, and ciphertext smoke.
5. After every region runs the new digest, remove batch IAM grants for old
   digests.

If storage, KMS, attestation identity, authorization, or settlement is
unavailable, batch requests fail closed. They never fall back to a non-attested
worker or plaintext persistence.
