# AWS gateway TLS key custody

This is a release checklist, not evidence of deployment. The AWS TLS cache
fingerprint was recorded from the KMS-generated P-256 SPKI and checked against
the independently audited generation receipt. A missing or mismatched
`nitroTLSCacheSPKI` must block release. Do not replace it with a value
learned from a running gateway, or turn off attested bootstrap.

## Key preparation

1. Read the live release coordinator, existing owners, signed trust records and
   actual public keys. A stopped foreign owner is not authorization to clear a
   reservation. Record issued expiry dates without opening the old cache.
2. Use a **new**, symmetric, AWS-generated multi-region KMS key in Dublin with
   a replica in Paris. Do not reuse a provider-secret key or its policy.
   `python3 -m tools.aws_tls_cache_policy --region REGION --phase locked`
   renders a project-specific proposal and does not apply anything. Establish
   and independently verify the locked policies on *both* regional key ARNs.
   Use `python3 -m tools.aws_tls_cache_policy --verify-key-id MRK_ID --phase locked`
   with the independently recorded MRK ID to check both policies, regional
   membership and absence of grants. Confirm only the intended management identities
   can change these policies; alert on policy changes. Key administrators who
   can rewrite policy remain inside this threat model.
3. Only in Dublin, install the reviewed seed policy and make **one**
   `GenerateDataKeyPairWithoutPlaintext` request with `ECC_NIST_P256` and
   encryption context `purpose=trustedrouter.aws-tls-cache.v1`. Save only
   the public SPKI, KMS ciphertext and non-sensitive audit receipt. Do not
   unwrap it for a test. On an ambiguous result, stop and reconcile the receipt;
   do not issue another seed. Immediately restore the locked policy and check
   both regions. The seed window is an operator step, not an IAM usage cap.
4. Verify the generating operation, ARN, context and SHA-256 of the DER SPKI
   independently. Commit that public hash to measured enclave source and
   register it separately as the publisher's `AWS_TLS_CACHE_SPKI_SHA256`
   repository variable from the approved receipt, not from the built image.
   A missing or mismatched fingerprint must stop EIF publication. Replicate
   the same ciphertext, with each region's related MRK ARN, in the two fixed
   Secrets Manager descriptors. Grant the parent only describe/read of that
   descriptor and recipient decrypt on that regional key. Provision the named
   ciphertext-only bucket with least-privilege object access; no plaintext
   imports, no legacy key/account reuse, no broad grant to other buckets.

## Before traffic

- The parent image is not inside the EIF. The reviewed cutover manifest is
  `tools/aws-secrets/tls-cache-parent.json`. Its `parent_tree` identifies the
  complete archived Git build context (`parent/`); the OCI digest identifies the
  single-platform linux/amd64 image, not its config or the archive. This first
  archive was built from commit `d63fe26e9f3ba699eba1790302c926c6904eda81`.
  Preserve the archive's digest when publishing to each regional `quill-parent`
  registry. The release checks both registries and both serving parent pins
  before taking a reservation, and repeats the check before generating each
  template. Changing the parent source or encountering a different serving
  digest requires a new reviewed plan. Do not substitute the pump image or a tag.
  A parent change still requires review of the **actual** template diff. If
  the diffs differ by region, use the reviewed Paris hash for
  `template_diff_sha256` and the independently reviewed Dublin hash for
  `dublin_template_diff_sha256`. Neither input authorizes any other diff.
- Verify both descriptor and parent relay revisions, CI on the exact release
  commit, and independent EIF/PCR0 reproduction. Do not infer AWS measurement
  from GCP. Only the reviewed non-debug PCR may enter the TLS key policies.
  The publisher and `tools/verify-pcr0.sh` use the same pinned BuildKit exporter
  with `rewrite-timestamp=true`: file timestamps are part of the measured
  application ramdisk, not just image metadata. The scratch timestamp test
  checks the exporter, not whether a specific release reproduced. A mismatch
  in the independent full rebuild still blocks admission.
  Compare both regional policies, list grants again, and run positive/negative
  checks with a disposable encrypted fixture. Never test ordinary decryption
  using the real seed. A non-attested parent, unrelated principal, wrong
  encryption context or wrong measurement must not obtain a key.
- Extract the SNI set from the exact measured image config and independently
  match it to the intended DNS names; the signed EIF manifest alone does not
  enumerate hostnames. The normal publisher at the previous serving source
  specifies `api-aws.trustedrouter.com`. Never inherit the GCP 19-name budget.
- Qualify isolated DNS-01 issuance, cold restart, independent replica read,
  renewal and cleanup first. Use separate staging key material and cache; the
  shipping binary must not accept an operator-supplied CA or cache location.
  Before a real order, establish a single no-traffic issuer and a bounded AWS
  hostname/order budget. No parallel ordering, overwrite, revocation or
  automatic retries on ambiguous results.
- The host-side opt-in `aws_tls_rehearsal` test binary uses only the Let's
  Encrypt **staging** directory, the fixed AWS hostname and a fresh private
  local directory. With the AWS prep reservation and an approved validation
  window, use separate invocations of `TestAWSStagingDNSRehearsal` for
  `init`, `issue`, `read`, `renew`, `read` via `TR_AWS_REHEARSAL_PHASE`
  and the same `TR_AWS_REHEARSAL_DIRECTORY`; always use `-count=1`.
  Compare only the public fingerprints: initial and cold read must match;
  renewal must differ, and its cold read must match the renewal. Check
  authoritative TXT cleanup before advancing. Each order phase is one-shot.
  This qualifies the DNS procedure, not a real Nitro restart, replica, KMS
  policy or serving fleet. Never import rehearsal objects into the live cache.
- The first AWS boot now verifies the key pair, public CA chain, hostname
  and validity **before** returning its cache to the listener. Only an
  actual missing leaf can start issuance. After the rehearsal and access
  checks, arm the no-traffic candidate by creating the public control object
  `release-control/v1/api-aws.trustedrouter.com/permit` in the new bucket
  with a create-only generation precondition. Its one line is
  `first-order-v1 api-aws.trustedrouter.com <approved-cache-SPKI-SHA256> <RFC3339-expiry>`.
  At claim time the expiry must be more than nine and at most thirty minutes
  away. Allow enough time for validation and TXT cleanup before any DNS grant
  expires. Verify both public resolvers are reachable through the reviewed
  vsock tunnels and the grant permits only the AWS validation TXT.
  The candidate creates the sibling `claimed` object with generation-match
  zero before any order. A conflict, lost response or failed order does not
  authorize a retry. Never delete or replace the claim to unstick the release.
  Remove the permit after reconciliation; keep the claim. Healthy replicas
  with a verified certificate do not consult the permit or contact a CA.

## Release and acceptance

Use the normal signed-trust and rolling gateway workflow with a healthy
holdback. An admitted image is not a serving image. For Dublin and Paris,
verify every serving target's exact non-debug PCR, nonce, certificate and
TLS exporter on the **same** connection; verify public CA/hostname/expiry,
new public keys, all serving certificate algorithms and repeat against the
regional load balancers. Confirm membership, health, traffic, final signed
trust publications and normal release finalization. Record no private keys,
prompts, credentials or certificate cache contents in the report.

Do not fall back to plaintext cache on rollback. Keep changes to key policies,
old-certificate expiry/revocation and DNS under explicit operator control.
Rotating the serving certificate does not invalidate previously issued ones.
