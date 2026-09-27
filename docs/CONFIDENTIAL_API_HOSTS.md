# Confidential-only API origins

Public origins: `api.confidential.{trustedrouter,quillrouter,allyrouter,uptimerouter}.com`.
Every inference request must explicitly contain `provider.min_privacy="confidential"`.
The hostname does not repair or silently supply a missing setting. Neither ZDR
alone nor the `e2e` model alias substitutes for that request field.

## Enforcement

- TLS SNI OR HTTP Host activates the requirement. Forwarding headers are ignored.
- Duplicate Host headers are rejected. The requirement is evaluated on every
  HTTP request, including keep-alive connections.
- Supported POST routes: Chat Completions, Responses, Messages, and local
  Responses input-token counting. Other prompt-bearing APIs fail closed.
- Every internal chat authorization checks the inherited context constraint,
  then uses the existing control-plane endpoint privacy filter. No new billing
  or routing algorithm is introduced. Missing child policy fails before a hold.
- Local spend-lease admission is disabled for this origin. User-hosted custom
  endpoints are rejected, including when returned by custom-model resolution;
  hidden-prompt wrappers around eligible catalog routes remain supported.
- Hosted web search cannot send confidential prompts to the search provider.
- Health, attestation, receipt identity and catalog metadata remain readable.
- The original request bytes, not any normalized payload, are receipt-hashed.

## Rollout and DNS

1. Run the Go test matrix and Python verifier/reconciler tests. Deploy through
   the existing sequential GCP regional rollout with normal health gates.
2. Before new instances boot, the reconcilers provision DNS-01 CNAME delegations
   for the three mirror-name challenges into the existing trustedrouter.com
   Cloud DNS zone. These are certificate challenge records, not inference A
   records. The enclave obtains the certificates with its existing DNS-01
   credentials and shared cache; no new credential or exported TLS key is used.
3. The DNS reconciler first verifies the normal hostname's live attestation,
   then verifies each confidential hostname's certificate, attestation, and
   privacy rejection on the same TLS session with that name as both SNI and Host.
   An unsigned status-page assertion or a 401 from an old binary is insufficient.
   Only instances returning `400 confidential_privacy_required` for an explicit
   weaker setting on all four names qualify. Normal release measurement checks
   still run; a certificate that exists only for the ordinary name is not enough.
4. Confidential DNS respects regional drains. With zero qualified instances,
   remove its A records; do not retain policy-incompatible last-good addresses.
   Ordinary API last-good behavior is unchanged. Route53 mirrors copy only the
   confidential source record, never the ordinary source record.
5. Verify certificate issuance and fresh attestation on all four new names,
   missing/weak-setting rejections, one eligible confidential inference, and
   refusal of an explicitly non-confidential provider. Only then publish docs.

Example policy-readiness probe (no credentials or prompt):

```sh
uv run --script tools/verify-attestation.py \
  --api-host api.confidential.trustedrouter.com --connect-ip <candidate-ip> \
  --expect-digest sha256:<approved-image> --no-require-exporter-binding \
  --require-confidential-host api.confidential.trustedrouter.com
```

This extra probe is DNS liveness mode, not a replacement for strict exporter
binding verification. Run the normal strict verifier on each new hostname
after certificates become available. Never roll back a confidential-serving IP
in place to a binary without the policy; withdraw it first and wait for DNS TTL
and existing connections to drain. Routine MIG replacement uses fresh IPs and
the reconciler will refuse to publish an old binary to confidential DNS.

The request guard compiles for GCP, AWS, and Azure. These four public DNS names
currently use the GCP fleet; the separate regional AWS/Azure hostnames do not
become confidential-only by implication.

Compatibility note: `/v1/messages` now honors caller-supplied `provider`
settings on the ordinary hostname too; they were previously silently dropped.
Requests without those settings are unchanged. Transport/attestation failures
cannot qualify a DNS member. Withdrawing the confidential record when nothing
qualifies deliberately prioritizes fail-closed privacy over last-good serving;
it does not alter the ordinary hostnames' last-good availability behavior.

## Certificate bootstrap prerequisites

Confidential names use DNS-01 only. A cache miss must not initiate TLS-ALPN
issuance: the CA cannot reach a name that is deliberately absent from DNS until
its attestation and privacy policy pass. The shared cache remains enclave-owned;
never issue the certificate on an operator laptop or export its private key.

The workload identity needs `dns.changes.create`, `dns.resourceRecordSets.create`
and `dns.resourceRecordSets.delete`. Bind a custom role with only these permissions
on `trustedrouter-com`, conditioned on Change resources or these exact TXT records:

- `_acme-challenge.api.confidential.trustedrouter.com.`
- `_acme-challenge.api-confidential-quillrouter.trustedrouter.com.`
- `_acme-challenge.api-confidential-allyrouter.trustedrouter.com.`
- `_acme-challenge.api-confidential-uptimerouter.trustedrouter.com.`

Do not grant project-wide DNS administration or alter the read-only ops identity.
Cloud DNS checks each record modification as well as the enclosing Change;
ordinary A records and zone administration must be denied by the condition.
See [Google's per-record IAM guidance](https://codelabs.developers.google.com/codelabs/cloud-dns-per-rrset-iam).

A CA 429 yields to the configured backup instead of sleeping through its
Retry-After indefinitely. Each complete order has an eight-minute deadline;
registration has a one-minute deadline. Failed certificate bootstrap is distinct
from ordinary gateway availability. Zero confidential-ready instances produces
an explicit error log after withdrawing unsafe confidential A records; it must
not prevent ordinary DNS reconciliation or the rollout that repairs bootstrap.

Before telling clients this origin is ready, verify public DNS, strict TLS-bound
`/attestation`, `/receipt-key` (including the receipt-key attestation), and
missing/weaker privacy rejection on Chat Completions, Responses and Messages.
