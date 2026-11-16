# AWS attested bootstrap infrastructure

This directory is the first stage of
[`aws-attested-secret-release.md`](../../docs/design/aws-attested-secret-release.md).
It does **not** make the current AWS credential plane confidential. The serving
fleet still uses V1 until the later phases pass their deployment gates.

## Default: adoption only

Run `terraform init`, `terraform validate`, and `terraform test` here. The
provider lock file pins the provider. Tests use mock providers and no cloud
credentials. A default `terraform plan` imports the parent role, its inline
policy and the two existing CMKs, without modifying those resources. All four
have `prevent_destroy` and `ignore_changes = all`: imports are not permission
to rewrite serving IAM or replace existing root-delegated legacy key policies.
The JSON file is a metadata-only baseline, not a new runtime policy.

The legacy shell IAM phase now refuses missing CMKs or failed alias lookups
before any IAM write. For a new region, provision and approve its CMK explicitly
before that phase; the old `--phase all` ordering is not a fresh-region shortcut.

Review the saved plan before any apply. Abort if adoption proposes creation,
deletion or modification of a legacy object. Never apply with a resource target
to work around an unexpected diff. State and saved plans are ignored by Git;
keep them in restricted operator storage and retain the state between phases.
No secret values or encrypted bundles belong in Terraform state.

## Explicit approval: signer bootstrap

After Joseph approves these specific writes, generate and inspect a new plan:

```sh
terraform plan -var=provision_signer=true -out=phase0.tfplan
terraform show phase0.tfplan
```

Expected new resources only:

* `quill-enclave-key-admin`, assumable by `user/jperla` with MFA, not the
  parent, an EC2 service, or a CI role.
* One P-384 SIGN_VERIFY key in eu-west-1 and the alias
  `alias/quill-enclave-bundle-signer`.

The named administrator role manages the key without a cryptographic grant.
The existing `user/jperla` is the seal operator and fallback administrator.
This is resilience to deletion of the admin role, not two-person approval or
independent human custody. The parent cannot sign. The existing main-only
`trustedrouter-github-trust-publisher` role can read the public key, not sign.
There is no account-root delegation and no bypass of KMS's lockout check.

Before apply, acquire the repository's AWS cloud-rollout reservation and verify
its fence. Keep it held throughout the mutation and verification. Do not run
the legacy shell IAM provisioner concurrently with Terraform. Apply only the
reviewed saved plan, then read back the role trust and key policy. Export only
the signer's public DER key for Phase 3; never generate a substitute local key.
After creation, keep `provision_signer=true` for later plans. Turning it off
is not rollback and is blocked by `prevent_destroy`.

## Remaining gates

1. Publish a pinned, CI-built EIF; verify its PCR0 on isolated candidates in
   both regions. Do not learn an admission measurement from the candidate host.
2. Widen signed public pins and runtime pins before candidate boot; test abort
   and narrowing. No release may strand another serving measurement.
3. Ship the v2 enclave with a measured signer and minimum bundle version, then
   validate CMS against a real KMS response and fuzz the parsers.
4. Separately approve regional attested keys and sealed-bundle writes. Test all
   recipient, forgery, version and parent-privilege negative controls.
5. Roll the dual-protocol parent and require attested boot on every instance.
6. Remove fallback and all accepted fallback-capable images before revoking
   legacy reads. Soak before deletion; coordinate every exposed-key rotation.

Do not claim AWS secret confidentiality or retire the V1 secrets at Phase 0.

## Phase 1: approved artifact storage

`provision_eif_storage=true` adds private, versioned artifact buckets in
eu-west-1 and eu-west-3, plus the immutable-tagged `quill-enclave-eif-builder`
ECR repository in eu-west-1. Review the saved plan with both opt-ins enabled
after Phase 0; do not disable an already-created stage. Keep the same Terraform
state and the AWS rollout fence. This stage must not alter a legacy resource.

Artifacts use `releases/<source_commit>/<eif_sha256>/`. Each object is uploaded
with a single PUT and `If-None-Match: *`; multipart upload, replacement and
deletion of release objects are denied. All public access is blocked, transport
must use TLS, and S3 encrypts objects at rest. Do not add lifecycle expiration:
accepted older releases must stay available for rollback and scale-out.

The parent gets a separate GetObject-only policy for those release prefixes.
The existing main-only CI publisher gets a separate policy to read the builder
and publish/read release objects. It cannot write the builder, delete artifacts
or access secrets through this policy. No existing secret access is changed.
The operator publishes the builder once and records its registry digest in the
release workflow. A moving tag is never an allowed builder input.

The trust-mirror bucket is deliberately not used: its publication script runs
`s3 sync --delete`. A successful trust-page publish must never erase an EIF.
The manifest verifier authenticates the dedicated `publish-aws-eif.yml` main
workflow identity and then validates the EIF's size and SHA-256 digest. It does
not itself admit a measurement, change KMS policy, or roll the fleet.

## Phase 4: separately approved recipient-only keys

`provision_attested_keys=true` is disabled by default. Enable it only after
the measured v2 enclave and pre-boot admission stages pass, with separate
approval for these KMS, IAM and Secrets Manager metadata changes. Keep earlier
opt-ins enabled and supply `accepted_pcr0` from authenticated CI manifests.
Never copy a candidate host's claimed measurement into this variable.

This creates one symmetric CMK and one independent
`quill/attested-bootstrap-v2` secret in each serving region. An additional
parent policy grants Decrypt on only those two keys and GetSecretValue on only
those two secrets. It does not remove or modify legacy permissions. Secret
values are not managed by Terraform and must contain only signed ciphertext.

The key policy explicitly denies Decrypt and ReEncrypt when the recipient's
ImageSha384 is missing or not accepted. An IAM Allow or grant cannot bypass
that Deny. Zero/debug measurements and empty sets are rejected by validation.
Named key administrators get no cryptographic operations; only the named
operator may generate data keys for the bootstrap purpose. There is no
account-root delegation or lockout-safety bypass.

Review a saved plan before applying it under the AWS rollout fence. Expected
changes are the two keys, two aliases, two secret metadata records and one
parent inline policy. Existing signer, artifact and legacy resources must not
change. Use the off-host sealer for independently encrypted regional bundles;
never configure Secrets Manager replication for these secrets.

After creation, prove the live recipient-only and parent-privilege negative
controls before any serving dependency on these keys. A mocked Terraform
policy test is not live KMS evidence. Later releases must widen this variable
and the signed/runtime admission sets before boot, and narrow both only after
verifying the surviving fleet. Removing the opt-in is not rollback and is
blocked by `prevent_destroy`.
