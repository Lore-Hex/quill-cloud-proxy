# AWS V1.1: attested secret release on Nitro

Status: plan, not started. AWS changes in this plan need Joseph's approval
before each IAM, KMS or Secrets Manager write.

## Problem

On AWS the parent process on the EC2 host fetches every enclave secret and
hands it to the enclave in plaintext. `parent/src/quill_parent/bootstrap_server.py`:

- reads every provider API key, the internal gateway token, the Cloudflare
  token and the spend-lease config from Secrets Manager;
- KMS-decrypts the cross-cloud GCP service-account key itself (the parent role
  holds `kms:Decrypt` on `alias/quill-enclave-cmk`);
- serves the result as one JSON `BootstrapData` on vsock port 9100 to any peer
  that connects, with no authentication.

This is the documented V1 caveat (`bootstrap_aws.go`, `types.go`, the trust
page). Prompts stay inside the enclave, but the credential plane does not: a
foothold on the host (a container escape, a compromised parent dependency, a
stolen instance-role session) yields every provider key and the GCP SA key.

The vsock port is not the root cause. Anyone on the host can already use the
instance role to call Secrets Manager and KMS directly, or read the parent's
memory. Restricting the port to the enclave's CID or adding a shared token
would not change that. The fix is to make the parent unable to decrypt.

GCP and Azure already have this property. Confidential Space reads Secret
Manager through workload identity gated on the attested image digest.
Azure releases a Key Vault key only to an MAA-attested container policy
(`docs/design/azure-cloud-local-secrets.md`). AWS is the only plane where an
unattested process holds the secrets.

## Goal

After V1.1, on AWS:

1. No process outside an enclave whose measurement we published can obtain any
   enclave secret in plaintext, including a process holding the instance role.
2. The parent cannot substitute secrets or configuration either: what the
   enclave accepts is authenticated, not just encrypted.
3. Releases keep working under the existing PCR0 set-widening procedure
   (`docs/runbook-aws-enclave-release.md`) with no manual key-policy edits on
   the critical path.

Non-goals: prompt confidentiality (already enclave-only), the cross-cloud GCS
ACME cache dependency (separate, see "Related"), and the parent's `/admin/usage`
endpoint.

## Design

### Mechanism: KMS `Recipient` with a Nitro attestation document

AWS KMS supports `Decrypt` with a `Recipient` parameter carrying a Nitro
attestation document. KMS checks the document's signature against the Nitro
root, evaluates key-policy conditions on its measurements
(`kms:RecipientAttestation:ImageSha384` is PCR0), and returns the plaintext
re-encrypted to the RSA public key inside the document
(`CiphertextForRecipient`, CMS EnvelopedData). Only the enclave holding the
matching private key can open it. The caller of `Decrypt` sees ciphertext only.

### One sealed bundle, one KMS call per boot

Follow the Azure shape: one bundle instead of 40 KMS-wrapped secrets.

- **Seal (operator, off-host).** `tools/sync-secrets-to-aws.sh` builds the
  bundle JSON (every field of `BootstrapData` that is secret or that the parent
  must not choose, including `trustedrouter_base_url`). It calls
  `kms:GenerateDataKey` on a new CMK, encrypts the JSON with AES-256-GCM under
  the data key, and stores `{encrypted_data_key, nonce, ciphertext, version}`
  as one Secrets Manager secret per region, `quill/enclave-bundle`. The
  plaintext data key is discarded. AES-GCM associated data binds the
  ciphertext to the region and bundle version.
- **Release (boot).** The enclave generates an ephemeral RSA-2048 key pair,
  asks the NSM (`github.com/hf/nsm`, already a dependency) for an attestation
  document carrying the public key, and sends it to the parent over vsock.
  The parent reads `quill/enclave-bundle`, calls
  `kms:Decrypt(CiphertextBlob=encrypted_data_key, Recipient={AttestationDocument})`,
  and returns `{CiphertextForRecipient, nonce, ciphertext, version}`. The
  enclave decrypts the data key with its private key, decrypts and
  authenticates the bundle, and discards the private key.

The parent makes the KMS call so the enclave needs no AWS credentials and no
new vsock-proxy entry. This is safe because the parent only ever handles
ciphertext; the attestation, not the caller, is what KMS authorizes.

### Key policy

A new CMK per region, `alias/quill-enclave-attested`, managed in Terraform
(see Phase 0):

- `kms:Decrypt` for the parent instance role **only** when
  `kms:RecipientAttestation:ImageSha384` is in the published PCR0 set.
- An explicit `Deny` of `kms:Decrypt` for every principal when the request has
  no recipient (`Null` condition on `kms:RecipientAttestation:ImageSha384`).
  This is the clause that makes a stolen role session useless.
- `kms:GenerateDataKey` and `kms:Encrypt` for the operator role that runs the
  seal step only. The parent role gets neither.
- Key administration for the account admin role, separate from use.

Debug-mode enclaves report all-zero PCRs, so they never match.

### Integrity, not just confidentiality

Today the parent also chooses non-secret configuration the enclave trusts,
such as `trustedrouter_base_url`. A compromised parent could point the enclave
at its own control plane. V1.1 moves every such field into the authenticated
bundle. The parent-supplied fields that remain must be ones the enclave
verifies itself (for example data it checks against a pinned key) or that
cannot change behavior in a way that matters.

Rollback: AES-GCM authenticates a bundle, but a parent could serve an older
valid bundle (for example one with a revoked provider key). Two options, to be
decided in Phase 1:

- the enclave enforces a minimum bundle version baked into the image (measured,
  so it changes PCR0 when raised), as Azure pins its bundle version; or
- accept rollback within the set of bundles sealed since the last key rotation,
  and revoke old keys at the provider on rotation, which is the practice
  anyway.

The second is simpler and the plan assumes it unless review says otherwise.

### PCR0 must be known before the candidate boots

This is the hard part. Today PCR0 is learned only after a candidate instance
runs `nitro-cli build-enclave` (runbook step 3). Under V1.1 a candidate whose
PCR0 is not yet in the key policy cannot get its secrets, so it cannot come up
far enough to be probed. The policy must be widened first, and the value used
to widen it must not come from the host being admitted: a compromised host
could report the PCR0 of an image it controls.

Plan: compute PCR0 in CI.

- `tools/verify-pcr0.sh` already rebuilds the image reproducibly and reads PCR0
  with `nitro-cli describe-eif`. Run it in a GitHub Actions job on the
  release commit, using AWS's reference Nitro builder image, and publish the
  result as a release artifact signed by the workflow (the repo already signs
  trust artifacts in `publish-trust-aws.yml`).
- `tools/release-aws-enclave.sh` reads that artifact, widens the key policy
  (Terraform variable `accepted_pcr0`, a set) before step 2, and the candidate
  then boots normally.
- Step 3's attested probe still runs and must match the CI value. A mismatch
  aborts the release and narrows the policy back.
- Step 5 ("narrow the pin") also narrows the key policy.

Alternative considered: condition on PCR8 (the EIF signing certificate) so the
policy does not change per release. Rejected for now: it moves trust from the
code measurement to custody of a signing key, and the rest of the system pins
PCR0.

## Phases

Each phase ships alone and is reversible until Phase 5.

**Phase 0: Terraform the AWS key and roles.** AWS infra is created by
`tools/deploy-aws-nitro.sh` with the CLI. Import the parent instance role, its
inline policy and the existing CMK into Terraform first, then add the new CMK
and its policy there. No behavior change. Needs: Joseph's approval for the
import and for every plan that writes IAM or KMS.

**Phase 1: Enclave reads either format.** Add the attested-release client to
`enclave-go/internal/bootstrap/bootstrap_aws.go`: build the attestation
document, send the v2 request, verify and decrypt the bundle. If the parent
answers in the V1 format, use it as today. Unit tests with a fake NSM and a
fake KMS response; a CMS parsing test against a captured real
`CiphertextForRecipient`. This is an enclave release (PCR0 changes) and follows
the runbook.

**Phase 2: Seal the bundle.** Create `alias/quill-enclave-attested` in both
regions with the policy above, `accepted_pcr0` set to the Phase 1 measurement.
Extend `tools/sync-secrets-to-aws.sh` to seal and write `quill/enclave-bundle`.
V1 secrets stay in place. Nothing reads the bundle yet.

**Phase 3: Parent serves the bundle.** The parent accepts the v2 request
(attestation document in, ciphertext out) and stops reading the V1 secrets for
enclaves that send it. Keep the V1 path behind a flag for rollback. Roll the
parent on one candidate, then the fleet. Verify on each instance that the
enclave reports `bootstrap_mode=attested` and that serving is unchanged.

**Phase 4: CI-computed PCR0 in the release flow.** Wire the CI measurement
into `release-aws-enclave.sh` and the runbook as described above. Do one
release end to end with it before Phase 5, because Phase 5 makes it mandatory.

**Phase 5: Remove the parent's access.** Remove `kms:Decrypt` on
`alias/quill-enclave-cmk` and `secretsmanager:GetSecretValue` on the V1 secret
names from the parent role, leaving only `quill/enclave-bundle`. Remove the V1
code path from the parent and the enclave. After a soak, schedule deletion of
the V1 secrets. Rotate every provider key and the GCP SA key afterwards: they
were readable by the parent role until this point.

**Phase 6: Say so.** Update the trust page, the `bootstrap_aws.go` and
`types.go` caveats, and the parent module docstring. The AWS trust statement
becomes the same as GCP's and Azure's: only attested code at a published
measurement can read the secrets.

## Verification

- **Negative control, before Phase 5 ships:** with the instance role's
  credentials on a candidate host, `kms:Decrypt` on the bundle's data key
  without a recipient is denied; with an attestation document from a
  debug-mode enclave it is denied; with a document whose PCR0 is not in the
  set it is denied.
- **Positive:** a published enclave boots and serves on every instance, in
  both regions, with the V1 secrets unreadable by the parent role.
- **Release drill:** one full enclave release with the CI-computed PCR0,
  including the abort path (inject a wrong expected value and confirm the
  release stops and the policy narrows back).

## Risks

- **Boot fails closed.** A policy that misses the running PCR0 takes the AWS
  plane down on the next restart. Mitigations: the set-widening order above,
  Phase 4's drill, and an alarm on `kms:Decrypt` denials from the parent role.
- **KMS availability becomes a boot dependency.** It already is for the GCP SA
  key, so no new dependency, but now every boot needs it. One call per boot
  keeps the rate trivial.
- **CMS parsing in the enclave** is new code on the trust boundary. Use a
  maintained library or a narrow parser with fuzz tests; do not accept any
  content type other than EnvelopedData with RSAES-OAEP-SHA256.
- **Reproducible PCR0 in CI** depends on pinning the nitro-cli version and
  kernel blobs. `verify-pcr0.sh` already pins the build args; the builder image
  must be pinned by digest too.

## Related

- AWS still depends on Google for the ACME certificate cache (the GCS bucket
  reached with the cross-cloud SA key). Azure moved its cache to cloud-local
  Blob storage with AES-GCM; AWS could do the same later, which would also
  remove the GCP SA key from the bundle.
- The vsock bootstrap listener binding `VMADDR_CID_ANY` stops mattering once it
  serves only ciphertext.
