# AWS attested bootstrap: Phase 0

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
