# Enclave deploy debugging

When the GHA workflow `deploy-enclave-gcp.yml` fails or rolls back,
walk through these checks before guessing.

For any active deploy, keep
[enclave-deploy-monitoring-checklist.md](./enclave-deploy-monitoring-checklist.md)
open beside this runbook. Debugging starts with what the public API
and direct backend IPs are actually serving, not with the workflow's
current step name.

## Quick triage

```bash
gh run list --workflow=deploy-enclave-gcp.yml --limit=3
gh run view <run-id> --log-failed | tail -50
```

Find the FIRST step that errored — later steps' errors are usually
cascades.

## Failure modes (catalog)

These are real failures we've hit. Sorted by frequency. Each entry:
**symptom → root cause → fix.**

### 1. Build step: `exec format error`

```
Step #0: exec /bin/sh: exec format error
```

The Dockerfile pins a base image to a single-arch (arm64) digest.
Cloud Build runs amd64. Without QEMU, docker can't run an arm64
builder. **Fix:** the workflow's build step already installs QEMU via
`tonistiigi/binfmt --install arm64,amd64` and uses `docker buildx`.
If this regresses, restore those lines in
`.github/workflows/deploy-enclave-gcp.yml` → `Build enclave image via
Cloud Build` step.

### 2. Build step: `gcloud.builds.submit` exit 1 with "Viewer/Owner"

```
The build is running, and logs are being written to the default logs bucket.
This tool can only stream logs if you are Viewer/Owner of the project
```

Cloud Build itself succeeded (`gcloud builds describe <id>` will show
SUCCESS). The CLI exited because it can't *stream* logs without
project Viewer. **Fix already in place:** the workflow uses
`--async` + a status poll loop. If you see this re-emerge, ensure
the build invocation has `--async --format='value(id)'`.

### 3. Build step: `--tag and --config are mutually exclusive`

The first `gcloud builds submit` revision tried `--tag` AND
`--config=-` together. **Fix:** the workflow uses only `--config=`
with a heredoc cloudbuild.yaml. Tag is set inside the config via
substitutions.

### 4. Rollout: `usage: tools/deploy-gcp-mig.sh <region>`

Script needs the region as a positional arg. **Fix:** the workflow
passes `us-central1` and `europe-west4` explicitly. If a new region
is added, update both the workflow and the
`scripts/deploy/secrets.sh` etc.

### 5. Rollout: `set API_HOST=...`

```
tools/deploy-gcp-mig.sh: line 64: API_HOST: set API_HOST=api.quillrouter.com
```

Each region needs `API_HOST` exported (the SNI the enclave's TLS
handler accepts). Workflow sets `API_HOST=api.quillrouter.com` for us
and `API_HOST=api-europe-west4.quillrouter.com` for eu.

### 6. Rollout: instances stay UNHEALTHY after MIG roll

Symptom: `gcloud compute backend-services get-health` shows new
instances UNHEALTHY indefinitely. New traffic routes to old
instances, smoke test 502s.

First, check whether direct public instance traffic and GCP backend
health disagree. If direct instance `/health` and `/attestation` pass
but backend health is red, this is a load balancer or health-check
path issue. Do not keep waiting on `wait-until --stable` without
checking the public path every 2 minutes.

```bash
gcloud compute backend-services get-health quill-enclave-bes-us \
  --region=us-central1 --project=quill-cloud-proxy

for ip in <new-instance-ip-1> <new-instance-ip-2>; do
  curl -sS -o /dev/null -w 'health %{http_code} %{time_total}\n' \
    --resolve api.trustedrouter.com:443:${ip} \
    --max-time 8 https://api.trustedrouter.com/health || true
  curl -sS -o /dev/null -w 'attestation %{http_code} %{time_total}\n' \
    --resolve api.trustedrouter.com:443:${ip} \
    --max-time 12 "https://api.trustedrouter.com/attestation?nonce=$(openssl rand -hex 16)" || true
done
```

Pull the workload's serial console:

```bash
gcloud compute instances get-serial-port-output <new-instance> \
  --zone=<zone> --project=quill-cloud-proxy | tail -50
```

Common substring → cause:

- **`env var ... is not allowed to be overridden on this image`** —
  Confidential Space launch policy `tee.launch_policy.allow_env_override`
  in the Dockerfile doesn't include the env name. Add it:
  `enclave-go/Dockerfile.enclave.gcp.multi` LABEL line.
- **`bootstrap/gcp: ... key: secret fetch http 403`** — the workload
  SA (`quill-workload@…`) doesn't have access to the named secret.
  Common when adding a new provider:
  ```bash
  gcloud secrets add-iam-policy-binding trustedrouter-<provider>-api-key \
    --member="serviceAccount:quill-workload@quill-cloud-proxy.iam.gserviceaccount.com" \
    --role=roles/secretmanager.secretAccessor
  ```
- **`workload finished with a non-zero return code`** without a
  preceding error — pull more lines, the actual error is usually
  10–20 lines before this.

### 6b. Public attestation fails while health passes

Symptom: `/health` returns an expected auth-gated response, but
`/attestation` returns non-200 or the verifier fails.

This is a trust-critical failure. Do not rely on provider smoke alone.
Run:

```bash
DIGEST="$(cat trust-page/image-digest-gcp.txt)"

uv run --script tools/verify-attestation.py \
  --api-host api.trustedrouter.com \
  --expect-digest "${DIGEST}" \
  --samples 4
```

Common cause:

- **Wrong or missing TLS cert binding** — `/attestation` must bind the
  cert selected on the same TLS connection. A process-global cert
  cache is not acceptable when serving multiple SNI hostnames.
- **Debug Confidential Space image** — verifier must reject
  `dbgstat=enabled`. Production deploys must use
  `CSP_IMAGE_FAMILY=confidential-space`, not
  `confidential-space-debug`.

### 7. Rollout: MIG rolling but no instances replaced

Symptom: `gcloud compute instance-groups managed describe` shows
`isStable: false, versionTarget.isReached: false` and stays there.

Likely the new instances are failing health checks (see #6) and
autohealing keeps trying. Force a replace cycle if you've already
fixed the underlying cause:

```bash
gcloud compute instance-groups managed recreate-instances quill-enclave-mig-us \
  --region=us-central1 --project=quill-cloud-proxy \
  --instances=$(gcloud compute instances list --project=quill-cloud-proxy \
    --filter="name~quill-enclave-mig-us-" --format="value(name)" | paste -sd, -)
```

### 8. Smoke test: `provider error` HTTP 502

The MIG rolled, instances are HEALTHY, but inference returns 502.
Means the enclave's provider client is failing. Common when adding a
new provider:

- **Together / open-weight provider**: `Unable to access model X` →
  TR sent the OpenRouter-canonical model id to a provider that uses
  its own naming. Add a translation in
  `enclave-go/internal/llm/byok.go` `togetherModelMap` (or the
  per-provider equivalent).
- **All providers failing 502**: TR control plane authorized a route
  but the enclave doesn't have that provider compiled in. Check
  `enclave-go/internal/llm/multi.go` switch has a case for the
  provider slug. The error message names which compiled providers
  were available — scan for that.

### 9. Trust page commit succeeds but Pages publish fails

Symptom: `publish-trust-page` job fails after `rollout` succeeded.

- **Pages not enabled**: repo Settings → Pages → Source: GitHub
  Actions. One-time per repo.
- **DNS not resolving** for `trust.trustedrouter.com`: ok, the page
  is still served at `<owner>.github.io/<repo>/`. Custom domain just
  hasn't propagated yet.
- **`actions/configure-pages@v5` errors**: usually a workflow
  permissions issue. The workflow needs `pages: write` and
  `id-token: write` at the workflow level (already set).

## Recovery: rollback without GHA

If you can't get GHA to deploy and you need to ship something now:

```bash
# Build + push image manually (requires docker locally)
make gcp-release   # or use Cloud Build:
gcloud builds submit --config=cloudbuild.yaml ... enclave-go/

# Roll the MIG
IMAGE_REF=us-central1-docker.pkg.dev/.../enclave-multi:gcp-release-<sha> \
API_HOST=api.quillrouter.com \
REGION_SHORT=us \
  bash tools/deploy-gcp-mig.sh us-central1
```

## After fixing

If the failure mode wasn't already in this runbook, **add it**.
Failure-mode coverage compounds — every captured one is 30 min the
next person doesn't have to spend re-discovering.
