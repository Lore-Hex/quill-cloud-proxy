# Releasing an AWS Nitro enclave

Build once in protected-main CI, admit the signed measurement, then boot.
An instance is never a source of a new admission value. TLS terminates inside
the enclave; do not add an ALB, CDN, or other prompt TLS terminator.

This runbook covers the published-EIF release path. Production bootstrap must
remain strict: no plaintext fallback, only strict images in every admission
set, a v2-only parent, and no host permission to read the old secrets or decrypt
with their legacy keys. A rollback must preserve those properties. Historical
credential rotation is a separate step; see
[the migration plan](design/aws-attested-secret-release.md).

## Automated path: rollout-aws-gateway.yml

Sections 2 to 5 are automated by the `rollout-aws-gateway.yml` workflow,
dispatched on main with the full `release_sha` of a commit whose EIF
`publish-aws-eif.yml` already published (section 1 stays a separate dispatch):

~~~bash
gh workflow run rollout-aws-gateway.yml --repo Lore-Hex/quill-cloud-proxy --ref main \
  -f release_sha=<full sha> -f bundle_version=2
~~~

It acquires the AWS reservation, lands the candidate admission through a PR
it merges on green, then **waits** for the key administrator's reviewed
`tools/aws-secrets` Terraform apply that widens both recipient-only key
policies (the summary prints the plan command; the workflow has no KMS write).
It then widens the Fargate pins and, Paris then Dublin, generates the numbered
candidate template, refuses any template change beyond the EIF identity unless
re-dispatched with the reviewed diff's `template_diff_sha256`, verifies a
standalone candidate over SSM (exact instance, CI PCR0, strict bootstrap and a
wrong-PCR0 negative control), refreshes the ASG with automatic rollback and
verifies every member. A failed refresh or census rolls that region back to its recorded
template; candidates are always terminated. Finally it narrows the record and
runtime pins through a second PR and verifies the public record. Any failure
leaves the reservation blocked for a verified recovery. The KMS narrow to the
single new measurement remains the key administrator's second apply.

A failed run, including one stopped by the template diff gate, leaves the AWS
lease blocked. Before re-dispatching (for example with the reviewed
`template_diff_sha256`), confirm nothing was promoted, then recover the lease
with quill-router's `infra-apply.yml` (`operation=recover cloud=aws
operation_id=<the run's operation> confirmation=APPLY`). The admission and KMS
steps are idempotent: a staged candidate and already-widened keys pass through.

The workflow's identity is `trustedrouter-github-gateway-rollout`
(quill-router `infra/aws_gateway_rollout_role.tf`). The manual procedure
below remains the fallback and the specification the workflow follows.

The two recipient-only keys hand nothing to IAM, so that role can compare
their policies with the published set only because each key's own policy
names it (`RolloutReadsPolicy` in `tools/aws-secrets`, two metadata reads).
A key policy applied from an older checkout loses that statement, and the
`kms-widen` wait then never sees the widened set.

### Rehearse before a rollout

Run a rehearsal after the workflow, the role, or the helper scripts change,
and before the first rollout from a new runner image:

~~~bash
gh workflow run rollout-aws-gateway.yml --repo Lore-Hex/quill-cloud-proxy --ref main -f release_sha=<full sha> -f bundle_version=2 -f rehearse=true
~~~

It takes no reservation, opens no PR and writes nothing in AWS. With the
rollout role on a runner it authenticates the release's manifest, checks the
published set, the runtime pins and the live endpoint as they stand, and
verifies every serving member in Paris and then Dublin over SSM against the
release that member already runs. That is every read and the SSM path a
rollout uses on its candidate and its refreshed fleet. It does not cover the
two key policy reads (the `kms-widen` wait retries those for
`kms_wait_minutes`, long enough to correct a key policy) or any call that
writes: a template version, an instance, a refresh, a task definition.

A red rehearsal is safe to repeat. Rehearsals and rollouts share one
concurrency group, so a rehearsal dispatched during a rollout waits for it.

## 0. Preconditions and rollback record

Start from clean, reviewed, merged main. Required CI must pass. Acquire the
shared AWS rollout reservation and retain its returned fence through all
mutations, regional verification, narrowing and rollback. Do not take over
another cloud's reservation or release someone else's fence.

Record the serving instance census, numbered launch templates, ASG desired
capacities, target health, current signed public record and runtime PCR0 sets.
Keep a local copy of the complete previous AWS trust record for an abort.
Verify the live endpoint cryptographically:

~~~bash
python3 tools/verify-attestation.py --api-host api-aws.trustedrouter.com --attested-cert-only
~~~

Both Fargate services, tr-cp-euw1 and tr-cp-euw3 in cluster tr-cp, must be stable
with healthy targets and matching reviewed control-plane release versions.
App Runner tr-eu is retired. Use minimum healthy 100%, maximum 200% or greater,
and rollback-enabled circuit breakers. A mixed or unknown state blocks rollout.

The source_commit in the public record describes capabilities of every serving
enclave. Keep the old commit during a mixed fleet. Do not advance it merely
because a new image has been built or one candidate works.

## 1. Publish the EIF in CI

~~~bash
bash tools/release-aws-enclave.sh --apply
~~~

This dispatches publish-aws-eif.yml on main. It neither builds locally nor
rolls the fleet. Wait for success and inspect the workflow's exact source SHA,
signed manifest, PCR0/1/2, immutable builder digest and both regional object
locations. A newer main commit at dispatch must not be confused with the
operator's earlier checkout.

The workflow is the canonical build recipe: linux/amd64, cloud_aws,llm_multi,
ACME, api-aws.trustedrouter.com, and the measured Cloud DNS configuration.
The pinned builder produces one EIF; both regions receive identical bytes.
Do not use deploy.yml or host-side build-enclave.

Download the manifest, its Cosign bundle and EIF from the reported regional
release path. Authenticate them before use:

~~~bash
python3 -m tools.aws_eif_manifest verify \
  --manifest /path/manifest.json --signature /path/manifest.json.bundle \
  --eif /path/enclave.eif --expected-source <full-ci-source-sha>
~~~

The verifier pins the publisher workflow identity and GitHub OIDC issuer,
checks source, size and hash, and rejects incomplete or malformed metadata.
Bucket names are quill-enclave-eif-<region>-330422590279. Release objects are
create-only under releases/<source>/<eif-sha256>/.

For an independent rebuild, use a clean checkout of that exact source SHA
and set AWS_EIF_MANIFEST and AWS_EIF_SIGNATURE before running
tools/verify-pcr0.sh. It uses the manifest's immutable builder and compares
against the signed CI PCR0, not a potentially older public primary.

## 2. Admit before boot

Prepare the local AWS trust change from the CI proof:

~~~bash
python3 -m tools.aws_eif_admission prepare \
  --manifest /path/manifest.json --signature /path/manifest.json.bundle \
  --expected-source <full-ci-source-sha> --write
~~~

This retains old PCR0s and all serving provenance, adds the CI candidate and
its signed manifest, and marks it unobserved. Review only the AWS trust files,
merge normally and wait for publish-trust-aws.yml and public publication.
The signer re-verifies the CI proof before signing a candidate admission.

Under the AWS reservation, widen the runtime consumers:

~~~bash
python3 -m tools.aws_eif_admission widen-runtime
~~~

This requires byte-for-byte public publication signed by the AWS trust workflow,
checks the rollout fence, preserves old runtime pins and serving source, then
checks the published set. It updates Fargate one region at a time and stops on
a failed health gate. Do not proceed with a failed or incomplete pin update.

Once Phase 4 attested CMKs exist, this gate must also widen accepted_pcr0 in
both regional key policies, through reviewed Terraform and Joseph's KMS-write
approval, before any candidate boot. Public/runtime admission alone is not KMS
admission. Never restore wildcard decrypt access to get past a denial.

## 3. Isolated candidate, eu-west-3 first

Use the verified manifest and signature with AWS_EIF_SOURCE_COMMIT set to its
full source SHA. Generate a numbered candidate template with
CANDIDATE_TEMPLATE_ONLY=1 and deploy-aws-nitro.sh --apply --phase compute.
Set AWS_REGION explicitly. Compare the template with the recorded live version:
preserve networking, approved parent/pump images, IAM, capacity, secret paths
and health settings. Reject unrelated drift. The host AMI and nitro-cli package
are pinned; user data downloads the EIF and checks its size and SHA256.
Set AWS_PARENT_IMAGE_DIGEST and AWS_PARENT_PUMP_IMAGE_DIGEST to the approved
existing `sha256:...` values when preserving those images. The generator checks
that each digest exists in the exact regional repository and emits immutable
references. Without explicit values it resolves release tags once at template
creation, never at host boot; a different parent still requires review.
An explicit AWS_PARENT_IMAGE_DIGEST is mandatory for dual or v2-only bootstrap;
only the legacy bootstrap stage permits resolving the parent release tag.

Launch one standalone candidate outside the ASG and every serving target group.
Give it distinct non-production Project and Name tags so discovery cannot add
it. Confirm no DNS writes or target registration occur during boot, and confirm
its IP is absent from serving DNS before probing. An ASG refresh checkpoint is
not isolation: replacements may register before the checkpoint.

Use SSM, without opening a security group or changing TLS:

~~~bash
aws ssm start-session --region eu-west-3 --target <candidate-instance-id> \
  --document-name AWS-StartPortForwardingSession \
  --parameters '{"portNumber":["8444"],"localPortNumber":["18444"]}'

python3 -m tools.aws_eif_admission verify-candidate \
  --manifest /path/manifest.json --signature /path/manifest.json.bundle \
  --expected-source <full-ci-source-sha> --port 18444
~~~

The probe verifies the Nitro chain, certificate and session bindings and
requires exact equality with CI PCR0. Check the module ID belongs to this
candidate. A different measurement aborts; never widen to what the host reports.

## 4. Sequential regional rollout

After the candidate passes, refresh eu-west-3 with the explicit numbered
template and automatic rollback to the previous numbered template. Never use
$Latest or $Default. Preserve 100% healthy capacity. If using checkpoints,
end CheckpointPercentages at 100; a list ending at 50 is a partial refresh.

Verify every member's template, serving target health, module ID and exact
CI PCR0 over its own SSM forward. A Successful refresh is not a fleet census.
Keep the standalone candidate isolated; terminate it after verification.

Finish eu-west-3 before repeating the isolated-candidate and refresh gates in
eu-west-1. Both regions MUST report the same CI PCR0. Regional variation is a
failure, not an excuse to add another measurement.

## 5. Narrow only after full verification

Once every serving instance matches CI, capture that already-authenticated
measurement through one of the verified SSM forwards:

~~~bash
python3 tools/capture-plane-measurements.py --plane aws --write \
  --repin-aws-monitor --aws-forward-port 18444 --source-commit <full-ci-source-sha>
~~~

Review the result: only the intended PCR0 remains, source_commit is the actual
image build commit, and the temporary candidate reference is removed. Merge
the AWS trust change normally; wait for signing and public publication.
Narrow attested CMK policies too when Phase 4 is active, with approval.
Retain only rollback images satisfying the current secret-release security
policy. Never fall back to V1 after the strict cutover.

Recheck each regional member, runtime pins, public signatures and canonical
status before releasing the reservation:

~~~bash
bash tools/release-aws-enclave.sh --verify-only
python3 tools/verify-attestation.py --api-host api-aws.trustedrouter.com --attested-cert-only
~~~

## Abort and required drill

Before any fleet promotion, deliberately verify the isolated candidate against
a wrong nonzero expected PCR0 using verify-attestation.py --expected-pcr0.
The verifier must fail. Record the failure and confirm the production ASGs,
targets and DNS still contain only the unchanged serving fleet.

Terminate the isolated candidate, restore the saved pre-admission AWS trust
record and accepted-set files through review, wait for signed publication, and
restore runtime pins to that exact set. Restore regional KMS sets too once
attested keys exist. Verify every original instance remains accepted and healthy.
Do not remove a measurement while any serving instance still uses it.

For a failure after promotion, first roll the affected region back to the
recorded previous numbered template while both measurements are still accepted.
Verify all instances and health before narrowing. Never rebuild a rollback
artifact or learn its measurement from a failing host.

Record the abort/narrow drill and one complete successful release before
depending on this flow for attested-secret boot availability.
