# AWS V1.1: attested secret release on Nitro

Status: plan, not started. AWS changes in this plan need Joseph's approval
before each IAM, KMS or Secrets Manager write.

## Problem

On AWS the parent process on the EC2 host fetches every enclave secret and
hands it to the enclave in plaintext. `parent/src/quill_parent/bootstrap_server.py`:

- reads every provider API key, the internal gateway token, the Cloudflare
  token and zone, the spend-lease config and the synthetic prompts from
  Secrets Manager;
- KMS-decrypts the cross-cloud GCP service-account key itself (the parent role
  holds `kms:Decrypt` on `alias/quill-enclave-cmk`);
- takes `trustedrouter_base_url`, which the enclave trusts, from its own
  environment;
- serves the result as one JSON `BootstrapData` on vsock port 9100, bound to
  `VMADDR_CID_ANY`, to any peer that connects, with no authentication.

The code comments in `bootstrap_aws.go`, `types.go` and the parent module say
so. The trust page's AWS panel does not. Prompts stay inside the enclave, but
the credential plane does not: a foothold on the host (a container escape, a
compromised parent dependency, a stolen instance-role session) yields every
provider key and the GCP SA key, and lets the attacker choose the enclave's
configuration.

The vsock port is not the root cause. Anyone on the host can already use the
instance role to call Secrets Manager and KMS, or read the parent's memory.
Restricting the port to the enclave's CID or adding a shared token would not
change that. The fix is to make the parent unable to decrypt and unable to
forge.

GCP and Azure already have this property. Confidential Space reads Secret
Manager through workload identity gated on the attested image digest. Azure
releases a Key Vault key only to an MAA-attested container policy and pins the
bundle version in the measured environment
(`docs/design/azure-cloud-local-secrets.md`). AWS is the only plane where an
unattested process holds the secrets.

## Goals

After V1.1, on AWS:

1. **Confidentiality.** No process outside an enclave running a published
   measurement can obtain any enclave secret in plaintext, including a process
   holding the instance role. The KMS key administrators and the seal operator
   remain trusted, as they are on GCP and Azure.
2. **Integrity.** The enclave accepts secrets and configuration only if the
   seal operator produced them. The parent can withhold them (denial of
   service) but cannot substitute, forge or downgrade them.
3. **Releases keep working.** PCR0 is known before a candidate boots, so the
   key policy and pins can be widened first, with no manual step on the
   critical path.

Non-goals: prompt confidentiality (already enclave-only), the cross-cloud GCS
ACME cache dependency (see "Related"), and the parent's `/admin/usage`
endpoint.

## Design

### Confidentiality: KMS `Recipient` with a Nitro attestation document

AWS KMS `Decrypt` accepts a `Recipient`
(`{AttestationDocument, KeyEncryptionAlgorithm: RSAES_OAEP_SHA_256}`). KMS
verifies the document against the Nitro root, evaluates key-policy conditions
on its measurements (`kms:RecipientAttestation:ImageSha384` is PCR0), and
returns the plaintext re-encrypted to the RSA public key inside the document as
`CiphertextForRecipient` (CMS EnvelopedData), with `Plaintext` empty. Only the
enclave holding the matching private key can open it.

### Integrity: the operator signs the bundle

Encryption alone gives no integrity here. `CiphertextForRecipient` is not
signed by KMS, and the parent relays the attestation document, so it knows the
enclave's public key. It can wrap a data key of its own choosing and encrypt
any bundle under it, and the enclave could not tell. So:

- A per-region KMS asymmetric key, `alias/quill-enclave-bundle-signer`
  (`ECC_NIST_P384`, `SIGN_VERIFY`), with `kms:Sign` for the seal operator only.
- Its public key is compiled into the enclave image, so it is measured: a
  different key means a different PCR0.
- The operator signs a manifest: `{region, version, sha384(encrypted_data_key),
  sha384(nonce || ciphertext || tag)}`.
- The enclave verifies the signature before it uses anything, then checks that
  the data key it recovered decrypts that exact ciphertext under AES-GCM. A
  parent that substitutes its own data key cannot produce a ciphertext that
  both opens under that key and matches the signed hash.
- Rollback: the image also carries a minimum bundle version, measured. Raising
  it is an enclave release, done when a rotation must not be undone (for
  example after a leaked key). Between raises a parent can replay an older
  signed bundle, which carries only older values. That is acceptable, because
  rotated provider keys are revoked at the provider.

Every field the enclave trusts moves into the signed bundle, including
`trustedrouter_base_url`. After cut-over the parent supplies nothing the
enclave trusts.

### One sealed bundle per region, one KMS call per boot

- **Seal (operator, off-host).** `tools/sync-secrets-to-aws.sh` builds the
  bundle JSON, calls `kms:GenerateDataKey` on the region's attested CMK,
  encrypts the JSON with AES-256-GCM (associated data: region and version),
  signs the manifest with that region's signer, and writes
  `{encrypted_data_key, nonce, ciphertext, manifest, signature}` to Secrets
  Manager.
- **Per region, not replicated.** `sync-secrets-to-aws.sh` creates new secrets
  in eu-west-1 with an eu-west-3 replica by default. A replica would carry a
  data key sealed under the eu-west-1 CMK, which the eu-west-3 parent cannot
  use. Each region's bundle is sealed under its own CMK and written with
  `AWS_REPLICA_REGIONS=""`.
- **Release (boot).** The enclave generates an ephemeral RSA-2048 key pair,
  asks the NSM (`github.com/hf/nsm`, already a dependency) for an attestation
  document carrying the public key, and sends it to the parent. The parent
  calls `kms:Decrypt(CiphertextBlob=encrypted_data_key, Recipient=...)` and
  returns `CiphertextForRecipient` with the rest of the bundle. The enclave
  verifies the signature, opens the data key, decrypts, and discards its
  private key.

The parent makes the KMS call, so the enclave needs no AWS credentials and no
new vsock-proxy entry. That is safe because the attestation, not the caller, is
what the key policy authorizes, and the parent only ever handles ciphertext.

### Protocol: a new port, not a changed one

Today the parent writes the payload as soon as it accepts a connection, and the
enclave reads until EOF and never writes. Changing that in place breaks every
mixed pairing during a rollout or rollback. Instead:

- v2 is served on a new vsock port, 9101. The enclave speaks first (the
  attestation document) and the parent answers.
- A v2 enclave tries 9101 and falls back to 9100 if nothing is listening.
- The parent serves both until cut-over. V1 enclaves keep using 9100, unchanged.
- Tests cover all four pairings: V1 and v2 enclaves against V1 and v2 parents.

The fallback is also a downgrade path: a compromised parent can refuse 9101 and
serve forged V1 data on 9100. Goal 2 holds only once an enclave release removes
the fallback (Phase 6).

### Key policy (attested CMK)

The policy must deny every path except a correct recipient. A conditional Allow
is not enough: any unconditional Allow (the default "Enable IAM policies" root
statement, an IAM policy granting `kms:Decrypt` on `key/*`, a grant) would
release the key to a debug-mode enclave or an attacker-built image, since NSM
signs their documents too.

- **Deny** `kms:Decrypt` and `kms:ReEncrypt*` to `Principal: *` when
  `kms:RecipientAttestation:ImageSha384` is `StringNotEqualsIgnoreCase` any
  value in the accepted PCR0 set. A negated operator is true when the key is
  absent, so this one statement covers requests with no recipient, ReEncrypt,
  debug-mode zeros, NitroTPM documents and unpublished images.
- **Allow** `kms:Decrypt` for the parent instance role, which is then bounded by
  the Deny.
- **Deny** `kms:Encrypt`, `kms:GenerateDataKey*`, `kms:ReEncryptTo`,
  `kms:CreateGrant`, `kms:PutKeyPolicy`, `kms:ScheduleKeyDeletion` and
  `kms:DisableKey` to every principal except the named seal-operator and
  key-admin roles.
- **No root delegation statement.** Key administration goes to a named admin
  role whose statement uses `NotAction` to exclude the cryptographic
  operations.
- The signer key's policy allows `kms:Sign` for the seal operator only and
  `kms:GetPublicKey` for CI. No one needs `kms:Verify`; the enclave verifies
  locally.

Separately, `tools/deploy-aws-nitro.sh`'s IAM phase grants the parent role
unconditional `kms:Decrypt` on `arn:aws:kms:<region>:<account>:key/*` in any
region where `alias/quill-enclave-cmk` is not found. That fallback must go in
Phase 0, whatever else happens.

### PCR0 must be known before the candidate boots

Today PCR0 is learned only after a candidate instance boots (runbook step 3).
Under V1.1 a candidate whose PCR0 is not in the key policy cannot get its
secrets, so the policy must be widened first. The value must not come from the
host being admitted, because a compromised host could report the PCR0 of an
image it controls.

Two problems stand in the way:

- **Each host builds its own EIF at boot.** The launch template's user data
  installs `aws-nitro-enclaves-cli` with no version pin and runs
  `nitro-cli build-enclave` on an AMI resolved from the "latest AL2023" SSM
  parameter. PCR0 includes the kernel, init and NSM blobs from that package, so
  a package or AMI update changes PCR0 on the next replacement. Today that
  drains instances from DNS; under V1.1 it would fail every new boot closed.
- **`tools/verify-pcr0.sh` does not reproduce the release build.** It omits the
  measured `QUILL_ACME_DNS_GCP_PROJECT` and `QUILL_ACME_DNS_MANAGED_ZONE` build
  args that `tools/release-aws-enclave.sh` passes, and nothing shows it has
  ever matched a published PCR0.

Plan: build the EIF once, in CI, and run that artifact everywhere.

- Fix `verify-pcr0.sh`'s argument drift and extend
  `tools/test_verify_pcr0_build_args.py` to cover the DNS args.
- A release workflow builds the EIF with the builder image pinned by digest,
  records PCR0/1/2, and publishes the EIF and its measurements (S3 or ECR),
  signed by the workflow as the trust artifacts already are.
- Hosts download the published EIF, check its digest, and run it. They no
  longer build. The AMI ID and the nitro-cli version are pinned in the launch
  template.
- The release widens the PCR0 pins (and later the key policy) from the CI value
  before the candidate boots. Step 3's attested probe still runs and must
  match; a mismatch aborts the release and narrows back.

This has value on its own, before any of the rest: it removes today's silent
PCR0 drift on scale-out.

Alternative considered: condition on PCR8 (the EIF signing certificate) so the
policy need not change per release. Rejected for now: it moves trust from the
code measurement to custody of a signing key, and the rest of the system pins
PCR0.

## Phases

The order is chosen so that no state mid-rollout can fail a boot. Each phase is
reversible until Phase 6.

**Phase 0: Terraform and the wildcard fallback.** Import the parent instance
role, its inline policy and the existing CMK into Terraform. Remove the
`key/*` decrypt fallback. No other behavior change. AWS infra today is created
by `tools/deploy-aws-nitro.sh` with the CLI; there is no AWS Terraform yet.

**Phase 1: Reproducible, published EIF.** As in the section above. Exit when
one CI-built EIF's PCR0 equals a live instance's attested PCR0 in both regions,
and hosts run the published EIF.

**Phase 2: CI PCR0 in the release flow.** `release-aws-enclave.sh` and the
runbook widen pins from the CI measurement before the candidate boots. Do one
full release this way, including the abort path (a wrong expected value stops
the release and narrows back).

**Phase 3: v2-capable enclave.** Attested client on 9101 with the 9100
fallback; signature verification against the compiled-in signer public key;
minimum bundle version. Unit tests with a fake NSM and fake KMS responses, a
CMS parsing test against a captured real `CiphertextForRecipient`, fuzzing of
the CMS and manifest parsers, and the four pairing tests. This is an enclave
release through Phase 2's flow.

**Phase 4: Keys and the sealed bundles.** Create the attested CMK and the
signer in each region with the policies above, `accepted_pcr0` set to Phase 3's
measurement. Extend `sync-secrets-to-aws.sh` to seal and sign per region. V1
secrets stay. Nothing reads the bundles yet. The negative controls in
"Verification" run here.

**Phase 5: Parent serves v2.** The parent listens on 9101 and keeps 9100. Roll
it on one candidate, then the fleet. Each enclave reports which mode it booted
in; every instance must report `attested` before Phase 6.

**Phase 6: Cut over.** In order:

1. Every PCR0 still in the accepted set, including rollback targets, must be a
   Phase 3 or later image. Narrow the set until it is.
2. Enclave release that removes the 9100 fallback. From here Goal 2 holds.
3. Parent stops serving 9100 and stops reading V1 secrets.
4. Remove the parent role's `kms:Decrypt` on `alias/quill-enclave-cmk` and its
   `secretsmanager:GetSecretValue` on the V1 names, leaving only the bundles.
5. After a soak, delete the V1 secrets.
6. Rotate every secret the parent role could ever read: each provider key, the
   GCP SA key, the Cloudflare token, the spend-lease issuer config and the
   synthetic prompts, plus the internal gateway token. That last one is the
   same value Cloud Run uses as `TR_INTERNAL_GATEWAY_TOKEN`, so its rotation is
   a coordinated control-plane and enclave rollout with its own runbook step.

**Phase 7: Disclose.** Add the AWS credential-plane statement to the trust page
(it has none today), and update the `bootstrap_aws.go`, `types.go` and parent
comments. Claim parity with GCP and Azure only after Phase 6 step 2. Whether to
disclose the current V1 state on the trust page now is a separate decision for
Joseph.

## Verification

- **Negative controls, Phase 4, before any reliance:** with the instance role's
  credentials on a candidate host, the attested CMK refuses `Decrypt` with no
  recipient, `ReEncrypt`, a debug-mode enclave's document, and a document from
  an image whose PCR0 is not in the set; `GenerateDataKey`, `Encrypt`,
  `CreateGrant` and `PutKeyPolicy` are refused; `Sign` on the signer is
  refused.
- **Forgery:** the Phase 3 enclave refuses a bundle with a valid AES-GCM
  ciphertext under a data key the test chose and wrapped to the enclave's
  public key itself, a bundle with a bad or missing signature, a bundle for the
  other region, and one below the minimum version.
- **Positive:** a published enclave boots and serves on every instance in both
  regions with the V1 secrets unreadable by the parent role.

## Risks

- **Boot fails closed.** A policy or pin that misses the running PCR0 takes the
  AWS plane down on the next restart. Mitigations: published EIF and pinned
  AMI (no drift), widen-before-boot, Phase 2's drill, and an alarm on KMS
  denials for the parent role.
- **KMS becomes a hard boot dependency** for everything, not just the GCP SA
  key. One call per boot keeps the rate trivial.
- **New parsing on the trust boundary** (CMS EnvelopedData, the manifest).
  Accept only EnvelopedData with RSAES-OAEP-SHA256 and one recipient; fuzz both
  parsers.
- **Signer compromise** breaks Goal 2. The signer's `kms:Sign` is limited to the
  seal operator; its use should alarm.

## Related

- AWS still depends on Google for the ACME certificate cache (a GCS bucket
  reached with the cross-cloud SA key). Azure moved its cache to cloud-local
  Blob storage with AES-GCM; doing the same on AWS would also remove the GCP SA
  key from the bundle.
- The bootstrap listener binding `VMADDR_CID_ANY` stops mattering once it
  serves only ciphertext.
