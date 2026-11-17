# AWS sealed bootstrap publication

Use this runbook to publish signed, region-specific encrypted bootstrap bundles.
The provisioning history below records the migration stages, not instructions
to re-enable legacy access. Production must retain strict images, strict-only
admission and v2-only parents. Neither merging a tool nor publishing a bundle
proves those runtime properties; verify each serving instance and its access
policy. IAM, KMS and Secrets Manager writes require Joseph's approval.

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

At the Phase 0/1 checkpoint, no recipient-only CMK or sealed runtime bundle
existed, and no migration candidate had booted. Provisioning alone is not
evidence of attested secret delivery or completed cutover.

### Transitional fleet verification

The CI-published EIF from source
`95676bb4e4076a31f83422463ffb96ee5f6aaf10` has SHA-256
`de6e757966005bef2561499dccb1c7fd0c1e18995338e1e64b0745556ac1ff52`
and PCR0
`36e9bb20a8dd78ad2b25fdec5fead81cb5cbde19d86cad13a5da513fda6baa25758263ef6b017c1d5c4a83b23af16202`.
Its independent publisher run was `43890482411`. Both regional artifact
copies, the signed manifest, and the complete EIF digest were verified before
candidate boot.

Isolated candidates in Paris and Dublin passed the verified-socket bootstrap
probe before their regional fleet rollouts. Paris completed at
`2026-11-16T16:42:28Z`, and Dublin at `2026-11-16T17:27:38Z`. All four serving
instances individually passed the exact CI measurement, Nitro signature and
chain, expected instance, fresh nonce, TLS certificate binding, TLS exporter,
and same-connection health checks. Both regions ended with exactly two healthy
new targets and no old draining targets. Numbered launch templates are Paris
52 and Dublin 58. Parent and pump images were unchanged.

These checks explicitly reported `policy=transition`, `mode=legacy`, version
0. They prove the new measured image is serving, not that secrets are already
host-resistant. Recipient-only keys, encrypted bundles, attested boot, strict
admission, and legacy access revocation remain later gates. Neither regional
rollout shortened its 300-second warmup, 900-second checkpoint delay,
300-second drain, or 300-second final observation period.

The rollout also repaired a verifier wire mismatch: Go legitimately omits a
zero `bundle_version` in legacy health. PR #818 permits that omission only for
the explicit transitional/legacy/version-zero expectation. Strict and attested
boot still require an explicit positive version. The repair's full CI passed
before the first fleet rollout; no failed proof was promoted.

### Encrypted-bootstrap fleet verification

Phase 5 completed on 2026-11-16 with the same transitional EIF and the parent
pinned to `sha256:4e9fa3b1d5458f1e54eb233164f0ac45b0169afd515a863521b3e702a3a6d80c`.
Each region received its own signed version 1 bundle. Paris completed at
`20:03:11Z` on template 53 and Dublin at `20:41:27Z` on template 59.
All four serving replacements passed individual CI-measurement, Nitro-chain,
nonce, instance, TLS-binding and same-connection health verification, reporting
`policy=transition`, `mode=attested`, `bundle_version=1`. Both regions ended
with exactly two healthy serving targets. The isolated migration candidates
were then terminated. The rollout retained its full warmup, checkpoint,
drain and final observation periods.

This checkpoint proved encrypted secret delivery throughout the fleet, not
strict enforcement: the transitional image still allowed plaintext fallback,
parents were in dual mode, and the gateway role still had legacy access.
Those are separate cutover gates and must not be inferred from an attested
version 1 boot alone.

### Signing-key monitoring

The central CloudTrail trail records KMS management events in
`/aws/cloudtrail/quill`, in `us-east-1`. Two metric filters there split every
`kms.amazonaws.com` `Sign` call on this signer, whether it names the key by
key ARN, key ID, alias, alias ARN or (on success) `resources[0]`, into exactly
one of two metrics. They are Terraform in quill-router
(`infra/aws_security_alarms.tf`, pinned by `tests/test_aws_security_alarms.py`);
change them there, not with the CLI.

* `quill-enclave-bundle-signer-use` counts unexpected use into
  `TrustedRouter/Security / EnclaveBundleSignerUse`: every denied `Sign`, by
  anyone, the release signer included; any `Sign` by another principal; and
  any release-signer `Sign` that is not a `DIGEST` / `ECDSA_SHA_384` bundle
  signature. A denied `Sign` carries no `requestParameters` or `resources`,
  only the key ARN in `errorMessage`, so the filter matches that too. The
  first, CLI-created version of this filter matched `requestParameters.keyId`
  only and therefore never counted a denial, including the denial controls
  below (the unauthorized-API-call alarm did count them).
  `TR-EnclaveBundleSignerUse` alarms on one event in a 60-second period.
* `quill-enclave-bundle-release-sign` counts routine release signatures into
  `TrustedRouter/Security / EnclaveBundleReleaseSign`: successful, by the
  release signer (the one principal the key policy lets sign), `DIGEST` with
  `ECDSA_SHA_384`, as `tools/aws_sealed_bundle.py` sends. A release signs one
  bundle per region, two in all, and does not email.
  `TR-EnclaveBundleReleaseSignBurst` alarms on more than four in an hour.

Both alarms use the existing `tr-security-alarms` SNS topic, whose confirmed
recipient is `security@trustedrouter.com`. Missing data is not a signer use
event; CloudTrail delivery health must be monitored separately. Public-key
reads and unrelated keys match neither filter.

A routine release no longer emails, by operator decision on 2026-11-16 (each
AWS release had emailed twice). Retain each release's CloudTrail/KMS request
IDs and rollout reservation in the operation record anyway. A deliberate
denial test still alarms. Investigate every unexpected-use alarm and every
burst alarm that does not match approved work. Because the release signer is
an operator IAM user, a stolen access key signing a single bundle in the
release shape would now show only in `EnclaveBundleReleaseSign` and
CloudTrail; requiring an MFA session for the release signature and adding it
to the release shape would close most of that gap. These alarms detect use;
they are not compromise prevention and not two-person approval.

## Before publication

### Recipient-only key provisioning and denial evidence

On 2026-11-16, the approved Phase 4 plan added seven resources without
changing or deleting any existing resource. The exact regional CMKs are:

* Dublin: `arn:aws:kms:eu-west-1:330422590279:key/8eb99ae5-e78a-4427-86ab-7762bf8285bc`.
* Paris: `arn:aws:kms:eu-west-3:330422590279:key/a21065e5-ee25-44f3-8662-b4ca30b89447`.

Each has an independent `quill/attested-bootstrap-v2` ciphertext record.
The additive parent policy names exactly those two keys and records. Both
key policies accepted only the CI-authenticated transitional measurement
documented above, had no root delegation or grants, and retained the explicit
recipient and mutation denials. Existing credential access was not revoked.

The actual `quill-enclave-role` session of isolated, non-serving candidate
`i-09e301f758fce1b8b` passed nine live denial controls against each regional key:
Decrypt without a recipient, ReEncrypt, GenerateDataKey, Encrypt, CreateGrant,
PutKeyPolicy, signer Sign, a valid unpublished-image Nitro document, and a
valid debug-mode Nitro document. Each returned `AccessDeniedException` with
an AWS request ID. The probes used random test data, not customer credentials.
Mutation controls used AWS dry-run where supported; PutKeyPolicy submitted
the unchanged current policy. Before/after policy checks confirmed no change.

SSM evidence command IDs, in privileges/unpublished/debug order:

* Dublin: `96fc9bb3-732d-49a2-a907-f815d81d6ed1`,
  `a1e1e96d-0ba0-4d88-b586-51ce37023b9c`,
  `575a1f32-9f59-427e-8e46-dd7170b75715`.
* Paris: `85265ab2-e362-473a-9492-f883d3e20b71`,
  `79362285-da71-4fc5-a355-36382a4c7aae`,
  `f0623b28-09b7-4668-84cc-5138581291bc`.

The fresh Nitro documents were independently checked against the AWS root,
nonce, instance, measurements and RSA public-key requirements before the KMS
calls. The diagnostic enclaves were terminated afterward. Neither diagnostic
measurement was added to an admission list. The final denial completed at
`2026-11-16T18:53:25Z`.

KMS normalizes a singleton condition array to a string and may reorder the
administrator principal list in readback. The release checker accepts the
equivalent singleton encoding, while still requiring the exact nonzero
measurement set and complete explicit Deny. Tests cover changed, missing,
extra, malformed and debug measurements. This is representation handling,
not a policy exception.

`attested-release.json` now requires both exact key ARNs on every admission
check. Do not disable it to bypass a missing key or failed policy check. The
legacy shell IAM and secret-sync paths also refuse operation after activation.
These controls do not prove fleet adoption: require attested boot on every
serving instance and complete the strict cutover before making that claim.

### Operator checklist

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

For rotation, the tool creates `AWSPENDING`, reads the ciphertext back, then
moves `AWSCURRENT` from the observed predecessor. For an empty new secret,
AWS automatically assigns `AWSCURRENT` to the first version even when the PUT
specifies `AWSPENDING`. The publisher verifies that exact version after
readback rather than attempting a redundant label move. If another version
became current, it fails without overwriting it. See
[AWS PutSecretValue](https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_PutSecretValue.html).
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

For the Phase 3 transitional-image release, before sealed bundles or the dual
parent are enabled, use the same verified-socket probe with `--policy transition
--mode legacy --version 0`. This explicitly confirms the expected temporary
fallback state. It is not proof of attested secret delivery. The verifier's
default remains `attested`; strict policy never accepts a legacy expectation.

Test real KMS recipient release, debug and unpublished-image denial, missing
recipient denial, ReEncrypt denial, and denied host signing/key mutation before
relying on v2. The captured public CMS fixture and unit tests are not a
substitute for those live controls.

During the original Phase 5 migration, `AWS_BOOTSTRAP_MODE=dual` was used
for the candidate template only after publishing
the new parent image. The deployment tool passes `QUILL_BOOTSTRAP_MODE=dual`
and the pinned regional CMK to that parent, which binds 9101 before 9100.
For this parent-only roll, keep the same CI-authenticated EIF. The pre-boot
gate accepts a completed release only when its exact source and measurement
match the signed CI artifact and its public accepted set contains only that
measurement. Public signature, rollout fence, regional key and runtime-pin
checks still apply. Do not invent another candidate admission for the same EIF.
After retirement, the deployment tool refuses legacy and dual modes and defaults
to v2-only. Do not disable the regional key configuration to bypass that guard.
Require every enclave to report attested bootstrap. A transitional image
reports `aws_bootstrap` on its enclave HTTPS `/health` response with the
measured `policy`, actual successful `mode`, and signed `bundle_version`.
Read this from each instance over a verified, attested TLS connection, not
the parent's plaintext health port. The metadata is set inside the enclave
after bootstrap and cannot be supplied in bootstrap JSON. Normal Nitro
console logs are unavailable without debug mode; never enable debug mode to
obtain this evidence. Keep the distinction between actual mode and policy:
an `attested` result under `transition` still permits a later fallback boot.
With the instance's SSM forward open, run the checked-in verifier:

```sh
python3 -m tools.aws_bootstrap_probe \
  --manifest "$AWS_EIF_MANIFEST" --signature "$AWS_EIF_SIGNATURE" \
  --expected-source "$AWS_EIF_SOURCE_COMMIT" \
  --instance "$INSTANCE_ID" --port 18444 \
  --policy transition --version "$BUNDLE_VERSION"
```

This verifies the signed CI manifest, Nitro chain, exact PCR0, expected EC2
instance, fresh nonce, TLS certificate and exporter before reading health on
the same connection. It sends no API key or inference request. Use
`--policy strict` after cutover and require the exact approved bundle version.

A transitional image can still fall back on any v2 failure, so it provides no
host-resistant configuration guarantee. The cutover order is strict image,
strict-only admission, v2-only parent, then legacy access revocation. After
cutover, keep strict rollback targets and never re-admit the transitional image.
The legacy IAM provisioner refuses to run after attested-key activation, so a
later `--phase iam` cannot accidentally regrant the old broad permissions.

Secret deletion and rotation are later, separately approved steps. Coordinate
the internal gateway token with the control plane. Never claim credential-plane
parity before the strict-image and admission gates have passed.
