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
enclave generates one AES-256-GCM data key per active batch/key epoch, wraps it
with Cloud KMS, and caches it only in bounded enclave memory. Every artifact
uses a unique nonce and artifact-specific authenticated data, and embeds the
wrapped key so another measured enclave can recover after a restart. GCS
receives ciphertext only. Version 1 per-artifact envelopes remain readable for
rolling-deploy recovery.

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

### Provider-native discounted path

The enclave may submit eligible direct-model chat and embedding jobs to a
provider's native asynchronous Batch API. The first adapters cover OpenAI and
Parasail's Files + Batches contract. Both providers publish a 50% Batch
discount. The control plane freezes a normal prepaid route and full-price hold,
then settlement applies the verified provider discount using integer
microdollars and releases the remainder. Until settlement, that conservative
hold can temporarily consume up to twice the eventual 50%-discounted charge
for as long as the provider's 26-hour completion window. Contract sources:

- <https://developers.openai.com/api/reference/resources/batches>
- <https://docs.parasail.io/parasail-docs/api-reference/batch-api>
- <https://docs.parasail.io/parasail-docs/billing/pricing>

This path is explicitly allowlisted in the measured source binary. It is dark
by default; mutable instance metadata and provider credentials cannot enable
native content export. Activation requires a reviewed source change and a new
attested image digest. Native provider Batch APIs persist plaintext prompt and
output state under their own retention policies, so the control plane and
enclave both reject the native path for ZDR, E2E, confidential, EU, BYOK,
custom, orchestration, fallback-array, `store`, service-tier, and
Broadcast-enabled requests. Unknown routing/privacy fields also fail closed.
Those jobs use the managed path below.

Before upload, every item receives a durable authorization and the encrypted
artifact store checkpoints its opaque handle. Native execution uses only the
customer's first selected route; it never skips a preferred route to find a
later native-capable provider. At most 1,000 items enter one provider-native job,
which bounds simultaneous holds and authorization handles. Larger public jobs
remain supported through the managed path. Submission streams JSONL directly
into the multipart upload instead of materializing duplicate batch-sized
buffers. It sends a deterministic provider idempotency token where accepted,
but does not rely on providers to honor it. A restart or ambiguous authorization
or create retries the same deterministic identity and recovers checkpointed
state or opaque provider metadata instead of creating another hold or job. If
repeated recovery misses span 30 minutes, the batch fails those items closed and
refunds them; it never risks a second provider submission. Successful provider
items settle exactly once;
rejected or missing items refund their native hold before running through
ordinary provider fallback. Expiration cancels the provider job and must refund
every unresolved hold before the public batch can become terminal. Provider
input files request a 26-hour expiration. Output and error files request a
six-hour expiration so a regional rollout or outage does not force already-paid
items to run again; the enclave still deletes all three immediately after durable
result processing. Cleanup is best effort after durable settlement and result
checkpointing. After 12 failed cleanup attempts the provider file expiration is
the final deletion backstop and the already-complete public batch is allowed to
become terminal.

Recovery adapters, provider credentials, and their endpoint configuration must
remain present for at least 30 hours after the last native submission. Removing
one while its job may still exist is prohibited: the enclave deliberately keeps
the public batch active rather than abandon possibly retained content or live
provider work. A `404` or `410` for a known provider job or result is safe to
resolve because the provider object is demonstrably gone.

### Enclave-managed path

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
while items execute or expiry reconciliation settles and refunds provider work.
Checkpoints and heartbeats share one serialized generation cursor. Loss of the
lease cancels the worker before it can finalize the job. Expiry errors use
bounded exponential backoff instead of hot-looping provider and ledger calls.
Expired batches expose every durably settled result plus explicit failed-item
records for refunded work, so a customer never pays for a hidden completion.

Terminal metadata and encrypted artifacts are automatically deleted after 30
days. Strict EU artifact residency is not part of the first beta and must be
documented as unsupported until regional stores are implemented.

## Limits

- 32 MiB batch-create HTTP body
- 64 MiB response body per item
- 256-byte `custom_id`
- 50,000 requests per batch
- 1,000 requests per provider-native submission; larger batches use managed execution
- no streaming items
- no list, cancel, or file-upload endpoints
- verified native discounts only; every managed fallback uses normal route pricing

## Deployment invariants

Before rolling an image:

1. Require protected-branch access and a human reviewer on the GitHub
   `batch-release` environment. Its narrowly scoped service account can edit IAM
   on the two Batch resources and must not be available to unreviewed workflows.
2. Resolve the immutable OCI digest and verify it matches `IMAGE_DIGEST`.
3. Grant that digest access to the batch bucket and envelope KMS key.
4. Roll one region at a time with normal attestation and synthetic gates.
5. Run a real create, poll, content, ownership-isolation, and ciphertext smoke.
6. Keep old-digest grants for at least the provider retention/recovery window.
   Prune them only in a separate operator action after more than 26 hours and
   after proving no old instance or provider-native job still needs the digest.
   Record that delayed prune as a required deployment closeout; the rollout
   workflow intentionally never removes a recovery digest automatically.
7. Keep every native provider recovery adapter and credential configured until
   no active native state references it and the 30-hour recovery window has
   elapsed.

If storage, KMS, attestation identity, authorization, or settlement is
unavailable, batch requests fail closed. They never fall back to a non-attested
worker or plaintext persistence.
