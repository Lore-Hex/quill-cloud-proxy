# Enclave state snapshot + verification — 2026-06-19

A point-in-time record of the GCP enclave fleet after the LB teardown + manual
re-roll to HEAD, with copy-paste checks anyone (codex, on-call) can run to confirm
everything is still good. For the durable architecture, see
[README.md](./README.md). This doc is a *snapshot* — trust the live checks below
over the specific digests/IPs here if they've since moved.

## TL;DR — what good looks like right now

| Property | Expected |
|---|---|
| Serving digest (all regions) | `sha256:a2394d67…` (image of commit `3a06925`, HEAD) |
| Regions | us-central1 + us-east4 + europe-west4, **2 instances each (6 total)** |
| Machine/conf (all regions) | `c3-standard-4` / **TDX** |
| DNS `api.trustedrouter.com` | A record, **6 IPs**, reconciler-managed (zone `trustedrouter-com`, TTL 60) |
| Load balancer | **NONE** — `bes=0 fr=0 hc=0 lb-ip=0` for `quill-enclave-*` |
| MIG autohealing | **cleared** on all 3 (reconciler is health authority) |
| Trust page | live `image_digest` == serving digest; `commit` == `3a06925` |

Everything is aligned: `main` (`3a06925`) == trust artifacts == serving fleet ==
live trust page == `a2394d67`.

## What changed 2026-06-19 (why this snapshot exists)

1. A bare-TCP:443 LB was trialed (codex) and proven a dead end — it stayed
   UNHEALTHY in every region even with the in-enclave handshake-deadline fix
   live, can't cover us-central1's CVM health-check quirk, and a socket-accept
   probe is too weak a gate for an attested endpoint. **Torn down** (all
   `quill-enclave-bes/fr/tcp-443-hc/lb-ip`), and **`tools/deploy-gcp-mig.sh`
   stripped** of all LB provisioning (commit `3a06925`) so a roll never
   re-creates it.
2. `deploy.yml` (the AWS pipeline) got `paths-ignore: [docs/**, **.md]` — it used
   to fire on every push to main incl. docs-only ones. The GCP-enclave workflow
   was always correctly path-filtered.
3. The auto-pipeline deploy of `3a06925` aborted on a **transient eu canary**
   (the `status.json` watchdog read eu `down` for 2 min during the instance
   surge; the new eu instances were actually serving). So the fleet was
   **manually re-rolled** to `a2394d67` region-by-region (us-east4 → eu →
   us-central1) with per-region attestation checks and no canary watchdog, then
   the trust page was published to match.

## Known gotchas

- **us-central1 CVMs are flaky but recreate-curable.** They sometimes come up
  wedged (connection-refused on `/attestation`) after churn; a clean
  `rolling-action replace` onto a stable template fixes it. It is **not**
  digest-related. Don't exclude the region — recreate it.
- **The eu canary watchdog over-triggers** during a surge (fresh-instance cert /
  regional-DNS lag reads as `down`). A *manual* region-by-region roll (verify
  each region's `/attestation` directly, no watchdog) avoids the false abort.
- **No LB, ever.** Ignore any `gcloud compute backend-services get-health` step
  in old notes — those resources are gone and the script no longer makes them.
- **Trust page publish is a manual step** after a manual roll:
  `gh workflow run publish-trust-page.yml --ref main` (the bot release commit
  does not trigger Pages).

## Verification checklist (copy-paste)

Auth: `SA=tr-deploy@quill-cloud-proxy.iam.gserviceaccount.com` works for all the
reads below (use `--account=$SA`). `P=quill-cloud-proxy`.

```bash
SA=tr-deploy@quill-cloud-proxy.iam.gserviceaccount.com; P=quill-cloud-proxy

# 1) All instances on the same digest, 2 per region
gcloud compute instances list --project=$P --account=$SA --filter="name~quill-enclave-mig" \
  --format='value(name,zone)' | while read n z; do
  gcloud compute instances describe "$n" --zone="$z" --project=$P --account=$SA --format=json \
   | python3 -c "import json,sys;d=json.load(sys.stdin);print('  '+next(i['value'] for i in d['metadata']['items'] if i['key']=='tee-image-reference').split('/')[-1])"; done

# 2) Reconciler says all healthy (expect: 'N healthy across 3 regions')
gcloud run jobs execute enclave-dns-reconciler --region=us-central1 --project=$P --account=$SA --wait
gcloud logging read 'resource.type="cloud_run_job" AND resource.labels.job_name="enclave-dns-reconciler" AND textPayload:"healthy across"' \
  --project=$P --account=$SA --limit=1 --freshness=10m --format='value(textPayload)'

# 3) Public DNS + live attestation (expect 200) on both hostnames
dig @8.8.8.8 +short api.trustedrouter.com A
for h in api.trustedrouter.com api.quillrouter.com; do
  curl -sS -o /dev/null -w "$h %{http_code}\n" "https://$h/attestation?nonce=$(openssl rand -hex 8)"; done

# 4) Strict attestation verifier (cert-binding, dbgstat, digest) against the live trust-page digest
D=$(curl -sS https://trust.trustedrouter.com/trust/image-digest-gcp.txt)
uv run --script tools/verify-attestation.py --api-host api.trustedrouter.com --expect-digest "$D" --samples 4

# 5) Real inference smoke (needs the synthetic-monitor key)
K=$(gcloud secrets versions access latest --secret=trustedrouter-synthetic-monitor-api-key --project=$P --account=$SA)
curl -sS --max-time 45 -H "authorization: Bearer $K" -H "content-type: application/json" \
  -d '{"model":"trustedrouter/monitor","messages":[{"role":"user","content":"PONG"}],"max_tokens":8}' \
  https://api.trustedrouter.com/v1/chat/completions

# 6) NO load balancer (expect every line empty)
for r in backend-services forwarding-rules; do gcloud compute $r list --project=$P --account=$SA --filter='name~quill-enclave' --format='value(name)'; done
gcloud compute health-checks list --project=$P --account=$SA --filter='name~quill-enclave' --format='value(name)'

# 7) Trust page == serving (expect equal)
curl -sS https://trust.trustedrouter.com/trust/image-digest-gcp.txt   # live published
gcloud compute instances describe "$(gcloud compute instances list --project=$P --account=$SA --filter='name~quill-enclave-mig-us-' --format='value(name)' --limit=1)" \
  --zone="$(gcloud compute instances list --project=$P --account=$SA --filter='name~quill-enclave-mig-us-' --format='value(zone)' --limit=1)" \
  --project=$P --account=$SA --format=json | python3 -c "import json,sys;d=json.load(sys.stdin);print(next(i['value'] for i in d['metadata']['items'] if i['key']=='tee-image-reference'))"
```

## Manual deploy procedure (when the pipeline's canary mis-fires)

Use the stripped `tools/deploy-gcp-mig.sh` from a clean `origin/main` checkout.
Roll one region at a time; verify `/attestation` 200 on the new instances before
the next region; publish the trust page last. Per-region env (preserve the live
`c3-standard-4`/`TDX` and canonical-inclusive `API_HOST`):

```bash
export CLOUDSDK_CORE_ACCOUNT=tr-deploy@quill-cloud-proxy.iam.gserviceaccount.com
export PROJECT_ID=quill-cloud-proxy
export IMAGE_REF="us-central1-docker.pkg.dev/quill-cloud-proxy/quill/enclave-multi@<DIGEST>"
export MACHINE_TYPE=c3-standard-4 CONF_COMPUTE_TYPE=TDX MAX_SURGE=3 MAX_UNAVAILABLE=0
# us-east4 first (most reliable), then eu, then us-central1 (flakiest) last:
REGION_SHORT=useast4 API_HOST="api.quillrouter.com,api-us-east4.quillrouter.com,api.trustedrouter.com" bash tools/deploy-gcp-mig.sh us-east4
REGION_SHORT=eu      API_HOST="api.quillrouter.com,api-europe-west4.quillrouter.com,api.trustedrouter.com" bash tools/deploy-gcp-mig.sh europe-west4
REGION_SHORT=us      API_HOST="api.quillrouter.com,api-us-central1.quillrouter.com,api.trustedrouter.com" bash tools/deploy-gcp-mig.sh us-central1
gh workflow run publish-trust-page.yml --ref main   # publish AFTER all 3 are healthy on the new digest
```
