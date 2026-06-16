# GCP Enclave Emergency Rollout

Use this when a trust-critical enclave fix must be tested or served faster than the normal staged global rollout.

The normal GitHub workflow is intentionally conservative: CI gate, build, trust artifact commit, us-central1 rollout, 3 minute us canary, europe-west4 rollout, 3 minute eu canary, then trust page publish. That is safe, but it can take 15 to 25 minutes. The emergency path gets one attested regional endpoint live first, proves it with a regional smoke, and lets the normal global rollout finish afterward.

## Do Not Bypass

- Do not deploy an image that has no `trust-page/gcp-release.json` digest.
- Do not fall back to a non-enclave prompt path.
- Do not force push trust artifacts.
- Do not run a second MIG update while the GitHub rollout is already updating the same MIG.

## Fastest Safe Path

1. Commit and push the enclave fix.

   ```bash
   make enclave-go-test
   git add enclave-go/cmd/enclave/fusion.go enclave-go/cmd/enclave/main_test.go
   git commit -m "Pass panel evidence to fusion finalizer"
   git push origin main
   ```

2. Watch only until `build-and-release` completes. This is the point where the immutable digest has been built and committed.

   ```bash
   gh run list --repo Lore-Hex/quill-cloud-proxy --limit 5
   gh run watch <deploy-gcp-run-id> --repo Lore-Hex/quill-cloud-proxy --interval 20
   ```

3. Pull the trust artifact commit.

   ```bash
   git pull --ff-only origin main
   cat trust-page/image-reference-gcp.txt
   cat trust-page/image-digest-gcp.txt
   ```

4. If `us-central1` is already rolled and canary-passed by the workflow, use the regional endpoint immediately:

   ```bash
   curl -sS https://api-us-central1.quillrouter.com/health
   ```

   Then run the product smoke against `https://api-us-central1.quillrouter.com/v1`, not the global endpoint.

5. If the workflow has not rolled a region yet and this is an emergency, roll **one** region manually using the released digest. Prefer `us-central1` first.

   ```bash
   export PROJECT_ID=quill-cloud-proxy
   export IMAGE_REF="us-central1-docker.pkg.dev/quill-cloud-proxy/quill/enclave-multi@$(cat trust-page/image-digest-gcp.txt)"
   export REGION_SHORT=us
   export API_HOST="api.quillrouter.com,api-us-central1.quillrouter.com,api.trustedrouter.com"
   export MAX_SURGE=3
   export MAX_UNAVAILABLE=0

   bash tools/deploy-gcp-mig.sh us-central1
   gcloud compute instance-groups managed wait-until quill-enclave-mig-us \
     --region=us-central1 --project=quill-cloud-proxy --stable
   ```

6. Run a short canary, not the full global gate.

   ```bash
   python3 tools/watchdog.py --regions us-central1 --duration-min 1 --rollback-after 1
   ```

7. Smoke the regional prompt path.

   ```bash
   SMOKE_KEY="$(gcloud secrets versions access latest \
     --secret=trustedrouter-synthetic-monitor-api-key \
     --project=quill-cloud-proxy)"

   curl -sS --max-time 45 \
     -H "authorization: Bearer ${SMOKE_KEY}" \
     -H "content-type: application/json" \
     -d '{"model":"trustedrouter/monitor","messages":[{"role":"user","content":"reply exactly PONG"}],"max_tokens":8}' \
     https://api-us-central1.quillrouter.com/v1/chat/completions
   ```

8. Use the regional endpoint for urgent verification or traffic steering while the standard workflow completes EU and publishes trust.

## EU Follow-Up

After US is healthy, roll EU with the same released digest.

```bash
export PROJECT_ID=quill-cloud-proxy
export IMAGE_REF="us-central1-docker.pkg.dev/quill-cloud-proxy/quill/enclave-multi@$(cat trust-page/image-digest-gcp.txt)"
export REGION_SHORT=eu
export API_HOST="api-europe-west4.quillrouter.com"
export MAX_SURGE=3
export MAX_UNAVAILABLE=0

bash tools/deploy-gcp-mig.sh europe-west4
gcloud compute instance-groups managed wait-until quill-enclave-mig-eu \
  --region=europe-west4 --project=quill-cloud-proxy --stable
python3 tools/watchdog.py --regions europe-west4 --duration-min 1 --rollback-after 1
```

## Rollback

Capture the current template before the rollout:

```bash
gcloud compute instance-groups managed describe quill-enclave-mig-us \
  --region=us-central1 --project=quill-cloud-proxy \
  --format='value(versions[0].instanceTemplate)'
```

To roll back:

```bash
export PREV_TEMPLATE=quill-enclave-tpl-us-123
gcloud compute instance-groups managed set-instance-template quill-enclave-mig-us \
  --region=us-central1 --project=quill-cloud-proxy \
  --template="${PREV_TEMPLATE}" --quiet
gcloud compute instance-groups managed rolling-action replace quill-enclave-mig-us \
  --region=us-central1 --project=quill-cloud-proxy \
  --max-unavailable=0 --max-surge=3 --quiet
```

## Timing Observed

For commit `981ed44` on 2026-06-16:

- Local full enclave tag matrix: about 3 seconds.
- GitHub CI gate plus GCP build and trust commit: about 4 minutes.
- `us-central1` MIG update to stable: about 6 minutes.
- `us-central1` regional Fusion smoke with Opus finalizer: 10.9 seconds.

The deploy was usable for regional verification after US canary, before EU completed. That is the emergency operating model.
