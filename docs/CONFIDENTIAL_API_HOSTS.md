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
- Hosted web search cannot send confidential prompts to the search provider.
- Health, attestation, receipt identity and catalog metadata remain readable.
- The original request bytes, not any normalized payload, are receipt-hashed.

## Rollout and DNS

1. Run the Go test matrix and Python verifier/reconciler tests. Deploy through
   the existing sequential GCP regional rollout with normal health gates.
2. The binary adds confidential certificate names only for public domains it
   already serves. TLS still terminates inside the enclave, not a proxy.
3. The DNS reconciler first verifies the normal hostname's live attestation,
   then probes the confidential HTTP Host on that same attested TLS session.
   An unsigned status-page assertion or a 401 from an old binary is insufficient.
   Only instances returning `400 confidential_privacy_required` for an explicit
   weaker setting qualify. Normal release measurement checks still run.
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
  --api-host api.trustedrouter.com --connect-ip <candidate-ip> \
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
