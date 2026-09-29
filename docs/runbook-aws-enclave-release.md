# Runbook — releasing a new AWS Nitro enclave image

Rolling the AWS enclave changes **PCR0**, because the enclave binary is measured
and the binary contains build tags, the API host, the TLS mode, and the
control-plane hostname allowlist. So this is never just "deploy the new image":
it is a measurement change, and every party that pins the measurement has to
accept both values for the length of the roll.

Get the order wrong and the failure is not a red dashboard.
`reconcile-enclave-dns.py` health-gates DNS membership on attestation, so a
fleet-wide `pcr0_mismatch` **drains healthy instances out of DNS** — the roll
causes the outage it was meant to avoid.

---

## What is fixed, and must not be re-derived

`tools/release-aws-enclave.sh` pins the build configuration. It is recorded
there rather than here so the script and the truth cannot drift apart:

| | value | why it is load-bearing |
|---|---|---|
| platform | `linux/amd64` | the fleet is x86_64 `m5.xlarge`. `.github/workflows/deploy.yml` builds **arm64** and therefore cannot have produced the running image |
| build tags | `cloud_aws,llm_multi` | `deploy-aws-nitro.sh` provisions **47** vsock tunnels — anthropic, openai, cerebras, deepseek, mistral, moonshot, z.ai, together. `internal/llm/aws.go` is `llm_bedrock`; those providers are all `llm_multi`. A Bedrock-only enclave could dial none of them |
| TLS mode | `acme` | the cert is still minted inside the TEE and still bound by attestation; ACME (GCS cache primary, DNS-01 fallback) makes the same leaf verify for CA-only clients, which canonical failover requires. Self-signed until 2026-08-23 |
| API host | `api-aws.trustedrouter.com` | baked in, and therefore measured |

The build tags were previously undocumented and had to be recovered by
inference. `cloud_aws,llm_multi` is now in the CI matrix, because an untested
tag combination in production is how that ambiguity arose.

---

## The roll

### 0. Preconditions

* The PCR0 pin is a **SET** on every surface that checks it — quill-cloud-proxy
  `check_pcr0_pin`, quill-router `_pcr0_pin_matches`. Without this, step 3 is
  impossible: writing `old,new` against an equality check matches **neither**,
  because neither value equals the literal joined string.
* The current control-plane consumers are Fargate `tr-cp-euw1` (eu-west-1)
  and `tr-cp-euw3` (eu-west-3), both in cluster `tr-cp`. They serve the API
  and synthetic monitor behind the regional NLBs/Global Accelerator.
  App Runner `tr-eu` is retired; do not recreate it or treat its absence as
  permission to skip verification. See quill-router's
  `docs/storage-portability/HANDOFF.md` and `scripts/deploy/aws_ecs_control_plane.sh`.
* Start from a clean checkout of merged main. Release-tool fixes require normal
  PR/CI/merge before changing the fleet. Record the actual enclave build commit,
  immutable regional image digests, current launch-template versions, healthy
  instance census, and current public/runtime accepted PCR0 sets for rollback.
* Both Fargate regions must be stable, serve the same release/image digest,
  and have healthy targets. Keep 100% minimum healthy capacity, at least 200%
  maximum capacity, and the deployment circuit breaker with rollback enabled.
  An unknown, mixed, or incomplete deployment blocks the release.
* Record the current PCR0 so you can roll back and so step 3 has an "old":

```bash
python3 tools/verify-attestation.py --api-host api-aws.trustedrouter.com --attested-cert-only
```

### 1. Publish the image (additive, reversible)

```bash
bash tools/release-aws-enclave.sh --apply
```

Refuses to run against a dirty `enclave-go`, because an image that matches no
commit has an unreproducible PCR0.

If the reviewed image is already published in both regions, verify its digest
and reuse it. Tool-only fixes do not require rebuilding the enclave. Run the
read-only gate without rebuilding or pushing:

```bash
bash tools/release-aws-enclave.sh --verify-only
```

### 2. Point the launch template at the new tag, then roll ONE instance

Update `quill-enclave-lt` user-data in **eu-west-3** only, then replace a single
instance. One instance, in the region carrying less traffic, so a bad image
costs one host rather than the fleet.

Clone the existing launch-template version and change only the enclave image
reference. Preserve compressed user data, parent/pump images, secrets, IAM,
networking, and health/failover configuration. Maintain healthy capacity and
pause the refresh after the first replacement until step 3 is verified.

The new instance will report `pcr0_mismatch` until step 3 — that is expected,
and it is why only one is rolled.

### 3. Learn the new PCR0 and widen the pin

PCR0 does not exist until `nitro-cli build-enclave` has run on an instance, so
it can only be read after step 2:

Use the official AWS Session Manager plugin and an SSM TCP forward to each
instance's enclave listener (8444). The public NLB's port 443 is not the
per-instance port; do not open security groups or add a TLS terminator.

```bash
# Keep this session open in a separate terminal; use the instance's region.
aws ssm start-session --region eu-west-3 --target <instance-id> \
  --document-name AWS-StartPortForwardingSession \
  --parameters '{"portNumber":["8444"],"localPortNumber":["18444"]}'

python3 tools/verify-attestation.py \
  --api-host api-aws.trustedrouter.com --connect-ip 127.0.0.1 --port 18444 \
  --attested-cert-only
```

This authenticates the Nitro root chain, certificate and channel bindings
while keeping the public API SNI. Confirm the module ID belongs to the intended
instance. Once learned, pass `--expected-pcr0 <new-PCR0>` on subsequent probes.
Stop each SSM session after verification. Capture alone parses a measurement;
it does not replace this cryptographic verification.

Then publish **both** measurements (set order is immaterial) everywhere PCR0 is
pinned. Widen before rolling further; never narrow before the roll completes.
Use the exact verified candidate's forward in the capture command below, not a
load-balanced endpoint that could still return the outgoing enclave. Wait for
both Fargate pin updates, AWS trust signing, public trust publication, and
attestation/status health before proceeding. Do not modify another cloud's
trust files or deploy router code as part of this pin-only update.

### 4. Roll the rest

Refresh the remaining eu-west-3 instance, then eu-west-1. Verify between
regions rather than at the end. For every replacement, use an SSM forward and
verify the new PCR0/module ID; then recheck the canonical endpoint and status:

```bash
python3 tools/verify-attestation.py --api-host api-aws.trustedrouter.com --attested-cert-only
curl -s https://aws.trustedrouter.com/status.json | python3 -c \
  "import sys,json; d=json.load(sys.stdin)['data']; print(d['overall_status'], len(d.get('recent_events') or []))"
```

### 5. Narrow the pin

Only once every instance reports the new measurement. Leaving the set widened
means a rolled-back instance would still verify, which defeats the point of
pinning at all.

---

## Rollback

Point the launch template back at the previous tag and refresh. The old PCR0 is
still in the pinned set at that stage, which is the reason step 5 comes last.

---

## What must NOT be done

* **Do not run `.github/workflows/deploy.yml`.** It builds arm64, which this
  fleet cannot execute, and it moves the `enclave-latest` alias as a side
  effect. It used to sign and republish trust artifacts too; it no longer
  touches them.

  This instruction is correct, but for a long time it was the *only* thing said
  about trust artifacts here — and since `deploy.yml` was the only workflow that
  signed and published them, forbidding it quietly meant nothing ever republished
  the AWS measurement. `trust-page/pcr0.txt` carried a value matching no running
  enclave from the initial commit until 2026-08-15 as a direct result.

  Publishing the AWS measurement is now a separate step that does not involve
  `deploy.yml` at all — see "Publish the measurement" below. Do that instead.
* **Do not narrow the pin before the roll finishes** — the un-rolled instances
  fail, and the DNS reconciler drains them.
* **Do not put anything that terminates TLS in front of the enclave.** The
  attestation binds the leaf minted inside the TEE; an ALB or CDN voids it.

Launch-template user data is gzip-compressed because the measured egress
allowlist is larger than EC2's 16 KiB raw limit. To inspect it during an
incident, decode and inflate it before reading:

```bash
aws ec2 describe-launch-template-versions \
  --launch-template-name quill-enclave-lt --versions <version> \
  --query 'LaunchTemplateVersions[0].LaunchTemplateData.UserData' \
  --output text | base64 --decode | gzip --decompress
```


## Publish the measurement

PCR0 does not exist until an instance boots, so it is read from a live
attestation rather than computed at build time:

```bash
# during the roll, while old instances are still serving
python3 tools/capture-plane-measurements.py --plane aws --write --keep-accepted \
    --repin-aws-monitor --aws-forward-port 18444 --source-commit <enclave-build-sha>

# after the last instance is refreshed and verified, narrow the pin
python3 tools/capture-plane-measurements.py --plane aws --write \
    --repin-aws-monitor --aws-forward-port 18444 --source-commit <enclave-build-sha>
```

`--source-commit` is the commit that BUILT the enclave now running, and it has
no default. A release-tool fix may have moved HEAD since the image was built;
always pass the image's source commit, not the current tooling commit.
If nobody can name it, omit the flag and the
record records `not-configured`, which makes quill-router's envelope-format
ordering gate refuse control-plane deploys against this cloud until a real
commit is published. A commit that is in this repository but is not the one
that built the running enclave is the one error nothing downstream can detect:
it makes the gate read a real file at the wrong commit.

Review and commit only the AWS files produced under `trust-page/`, then merge
through the normal PR/CI procedure. That fires `publish-trust-aws.yml`, which
signs the record under the AWS-only identity a verifier pins. Wait for signing
and publication, and verify the public accepted set before rolling further.

`--repin-aws-monitor` now updates only the two current Fargate services. It
preflights both before mutation, clones each task definition (including tags),
changes only `TR_ATTESTATION_EXPECTED_PCR0`, waits for stability and actual
healthy serving tasks/targets, and restores/verifies the previous task
definition on failure. With `--keep-accepted`, existing runtime pins are retained
alongside the published pins and newly captured PCR0. A failed region stops the
sequence; do not advance the enclave fleet while it is unresolved.

`--keep-accepted` is not optional during a roll. Without it you publish a set
that excludes the instances that have not rolled yet, and anyone verifying
against one of them is told the enclave does not match its published
measurement.

`tools/release-aws-enclave.sh` now refuses to exit 0 while the published set
disagrees with what is running, so a skipped publish fails the release rather
than passing quietly.
