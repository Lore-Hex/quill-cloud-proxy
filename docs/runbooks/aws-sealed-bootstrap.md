# AWS sealed bootstrap publication

This is a staged migration, not a declaration that V1 has been retired.
Follow the phase order in [the design](../design/aws-attested-secret-release.md).
Neither merging this tool nor publishing a bundle changes the serving parent
or enclave mode. IAM, KMS and Secrets Manager writes require Joseph's approval.

## Provisioning record: 2026-11-16

Phase 0 and Phase 1 infrastructure were applied after the preceding operator
released the AWS reservation and this migration acquired its own fence.
Phase 0 imported four existing resources without changes and created the
approved admin role, signer and alias. Phase 1 created the two private artifact
buckets, builder repository and additive artifact policies. A fresh Terraform
plan reported no drift. These steps did not change the serving fleet or its
legacy secret access.

* Signer: `arn:aws:kms:eu-west-1:330422590279:key/14d1c5b4-0b95-4c5c-995c-9511ff1038ab`.
* Signer public DER SHA-256:
  `1a8b304b7a2c84ce2d1ac24d5e3505160636a672358844e197f7540c9e38b37f`.
* The public key compiled into the transitional image was compared directly
  with KMS GetPublicKey. The image's minimum bundle version is 1.
* The builder was pushed to the dedicated ECR repository and read back as
  `sha256:7367ca7473a74d70433aa29bbce60ecef6aa0f713f7a361e18f90cd4c1044c06`.

At this checkpoint, no recipient-only CMK or sealed runtime bundle existed,
and no migration candidate had booted. This record is provisioning evidence,
not evidence of attested secret delivery or completed cutover.

## Before publication

1. Complete the signer and CI-built EIF stages. Authenticate the published
   measurements from CI, never from a host requesting admission. Confirm the
   candidate image contains the approved signer public key and minimum version.
2. Separately approve the regional recipient-only CMKs, the new secret metadata
   and the specific bundle publication. Leave V1 secrets and policies unchanged.
3. Acquire the AWS rollout reservation. Do not override another operator's lock.
   Keep the returned fence for publication and verification.
4. Assemble a complete `BootstrapData` JSON on the operator machine using the
   restricted local source. Compare its field and provider names with the
   current parent bootstrap catalog. Preserve all active provider credentials,
   prompts, lease configuration, Cloudflare values and the GCS ACME credential.
   A partial provider-key update is not a bootstrap bundle. Do not fetch or
   construct plaintext on a gateway, commit it, or put it in Terraform state.
5. Use an owner-only regular input file, not a symlink, and the real signer's
   public DER key exported from KMS. The signer public key is not secret.
   Review regional endpoints and the `https://trustedrouter.com` billing
   authority. Choose a strictly increasing version accepted by the image.

## Validate and publish

From the repository root, with approved paths and exact key ARNs substituted:

```sh
AWS_REPLICA_REGIONS="" bash tools/sync-secrets-to-aws.sh --sealed-bundle \
  --bootstrap-file "$PRIVATE_BOOTSTRAP_FILE" \
  --region eu-west-1 --version "$BUNDLE_VERSION" \
  --key-arn "$ATTESTED_CMK_ARN" --signer-arn "$BUNDLE_SIGNER_ARN" \
  --signer-public-key "$SIGNER_PUBLIC_DER"
```

The default is local validation with no AWS calls. Add `--apply` only after
approval and the rollout fence. This path never writes V1 copies. It requires
the named `jperla` seal operator, not a host or CI session. Run separately for
eu-west-3 with its own input region and CMK. Replication is rejected: the other
region must have an independently encrypted bundle.

Alternatively, replace `--bootstrap-file` with `--values "$PRIVATE_VALUES"`
and `--service-account-file "$PRIVATE_ACME_KEY"`. The values file contains
logical secret names and strings from the operator's local source, not AWS
wrapped ciphertext or unrelated control-plane credentials. The builder uses
the parent catalog and refuses missing values unless each inactive name is
explicitly listed with `--omit`. It never reads a cloud or logs values, and it
keeps the assembled plaintext in memory. The internal gateway credential and
the unwrapped ACME key are mandatory. Inspect missing names before approving
omissions; missing from a local file does not prove unused in production.

The tool creates `AWSPENDING`, reads the ciphertext back, then moves
`AWSCURRENT` from the observed predecessor. It verifies the resulting stage.
Output contains only region, version, ciphertext size and hash. The plaintext
and data key never go to a gateway. Python's memory clearing is best effort,
not a guarantee; use a trusted operator machine with restricted storage.

## Interrupted publication

Stop if the tool fails. Do not blindly retry, remove pending stages, decrement
the version, or restore a different active bundle. Inspect version IDs and
stages with the operator identity. The version ID is deterministic for the
region and bundle version; a newly encrypted payload cannot overwrite it.

If the active stage moved successfully but the response was lost, verify that
version's ciphertext, signature, region and minimum version before recording
completion. If a non-current pending version remains, review the stored signed
bundle and predecessor before an explicitly approved recovery. The tool fails
closed on this state rather than guessing. Do not print secret payloads into
terminal transcripts or logs during inspection.

## Serving and cutover gates

Test real KMS recipient release, debug and unpublished-image denial, missing
recipient denial, ReEncrypt denial, and denied host signing/key mutation before
relying on v2. The captured public CMS fixture and unit tests are not a
substitute for those live controls.

Set `AWS_BOOTSTRAP_MODE=dual` for the candidate template only after publishing
the new parent image. The deployment tool passes `QUILL_BOOTSTRAP_MODE=dual`
and the pinned regional CMK to that parent, which binds 9101 before 9100.
It refuses dual/v2-only mode before the regional key configuration is enabled.
Require every enclave to report attested bootstrap. A transitional image
can still fall back on any v2 failure, so it provides no host-resistant
configuration guarantee. Next release the measured strict image, remove every
fallback-capable image from both admission sets, then switch the parent to
`v2-only` and separately revoke V1 access. Keep strict rollback targets.
The legacy IAM provisioner refuses to run after attested-key activation, so a
later `--phase iam` cannot accidentally regrant the old broad permissions.

Secret deletion and rotation are later, separately approved steps. Coordinate
the internal gateway token with the control plane. Never claim credential-plane
parity before the strict-image and admission gates have passed.
