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
| TLS mode | `self-signed` | AWS mints its cert inside the TEE and clients verify by attestation — no CA in the trust path |
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

### 2. Point the launch template at the new tag, then roll ONE instance

Update `quill-enclave-lt` user-data in **eu-west-3** only, then replace a single
instance. One instance, in the region carrying less traffic, so a bad image
costs one host rather than the fleet.

The new instance will report `pcr0_mismatch` until step 3 — that is expected,
and it is why only one is rolled.

### 3. Learn the new PCR0 and widen the pin

PCR0 does not exist until `nitro-cli build-enclave` has run on an instance, so
it can only be read after step 2:

```bash
python3 tools/verify-attestation.py \
  --api-host api-aws.trustedrouter.com --connect-ip <new-instance-ip> \
  --attested-cert-only
```

Then publish **both** measurements — old first, new second — everywhere PCR0 is
pinned. Widen before rolling further; never narrow before the roll completes.

### 4. Roll the rest

Refresh the remaining eu-west-3 instance, then eu-west-1. Verify between
regions rather than at the end:

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
  fleet cannot execute, and it also republishes trust artifacts and moves the
  `enclave-latest` alias as a side effect.

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


## Publish the measurement

PCR0 does not exist until an instance boots, so it is read from a live
attestation rather than computed at build time:

```bash
# during the roll, while old instances are still serving
python3 tools/capture-plane-measurements.py --write --keep-accepted \
    --source-commit "$(git rev-parse --short HEAD)"

# after the last instance is refreshed and verified, narrow the pin
python3 tools/capture-plane-measurements.py --write \
    --source-commit "$(git rev-parse --short HEAD)"
```

`--source-commit` is the commit that BUILT the enclave now running, and it has
no default. Here — immediately after a release, from the same checkout the
release was built from — HEAD is that commit, which is why the recipe above
spells it out rather than relying on a default that would also fire in every
other flow. Anywhere else (re-publishing later, answering a drift alert), pass
the sha of the release instead; if nobody can name it, omit the flag and the
record records `not-configured`, which makes quill-router's envelope-format
ordering gate refuse control-plane deploys against this cloud until a real
commit is published. A commit that is in this repository but is not the one
that built the running enclave is the one error nothing downstream can detect:
it makes the gate read a real file at the wrong commit.

Commit `trust-page/`. That fires `publish-trust-aws.yml`, which signs the record
under the AWS-only identity a verifier pins.

`--keep-accepted` is not optional during a roll. Without it you publish a set
that excludes the instances that have not rolled yet, and anyone verifying
against one of them is told the enclave does not match its published
measurement.

`tools/release-aws-enclave.sh` now refuses to exit 0 while the published set
disagrees with what is running, so a skipped publish fails the release rather
than passing quietly.
