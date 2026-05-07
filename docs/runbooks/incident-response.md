# Incident response

Use when https://status.trustedrouter.com/ shows red, or a customer
reports the API is broken. Designed for cold-start: assume you don't
remember anything from the last 24h.

## Decide blast radius first (~30 sec)

```bash
curl -s https://trustedrouter.com/status.json | python3 -c "
import json,sys; from collections import Counter
d = json.load(sys.stdin)['data']
print('overall:', d['overall_status'])
for c in d.get('current',{}).get('checks',[]):
    print(' ', c.get('target_region') or 'global', c.get('probe_type'),
          c.get('effective_status'), c.get('error_type') or '')
"
```

You're looking for: which **target_region** is degraded, which
**probe_type** is failing, what **error_type** they report.

| Pattern | Likely scope | Next step |
|---|---|---|
| One target_region down, other up | Regional issue (provider outage in that region, MIG instance churn, regional secret access) | [Per-region triage](#per-region-triage) |
| Both regions down on same probe_type | Code regression or shared upstream | [Recent-deploy triage](#recent-deploy-triage) |
| All probe_types in one region down | Regional LB / regional MIG / regional secret | [Per-region triage](#per-region-triage) |
| Only attestation probe red | Confidential Space attestation chain (TLS, key fetch, GCS access) | [Attestation chain](#attestation-chain) |

## Recent-deploy triage

Most outages correlate with the most recent deploy. Check that first.

```bash
# Most recent enclave release (this is the running attested digest)
cat trust-page/image-reference-gcp.txt
git log -1 --format="%H %s" trust-page/gcp-release.json

# Most recent control-plane revisions (per region)
for region in us-central1 europe-west4; do
  gcloud run services describe trusted-router \
    --region="$region" --project=quill-cloud-proxy \
    --format="value(spec.template.spec.containers[0].image,status.latestReadyRevisionName)"
done

# GHA: did a deploy run in the last hour?
gh run list --workflow=deploy-enclave-gcp.yml --limit=3
gh run list --workflow=deploy.yml --limit=3 --repo Lore-Hex/quill-router
```

If the timing of the outage matches a recent deploy, the auto-rollback
should have already tripped. If it didn't (e.g., the regression is
slow-burning, takes >10 min to surface), trigger manual rollback:

```bash
# Enclave: revert MIG to the previous template
gcloud compute instance-groups managed describe quill-enclave-mig-us \
  --region=us-central1 --project=quill-cloud-proxy \
  --format="value(versions[0].instanceTemplate)"
gcloud compute instance-templates list --project=quill-cloud-proxy \
  --filter="name~quill-enclave-tpl-us" --sort-by="~creationTimestamp" --limit=5
# Pick the previous tpl, then:
gcloud compute instance-groups managed set-instance-template quill-enclave-mig-us \
  --region=us-central1 --project=quill-cloud-proxy --template=<prev>
gcloud compute instance-groups managed rolling-action replace quill-enclave-mig-us \
  --region=us-central1 --project=quill-cloud-proxy --max-unavailable=0 --max-surge=3

# Control plane: roll Cloud Run traffic back to a prior revision
gcloud run revisions list --service=trusted-router --region=us-central1 \
  --project=quill-cloud-proxy --limit=5
gcloud run services update-traffic trusted-router \
  --region=us-central1 --project=quill-cloud-proxy \
  --to-revisions=<prev-revision-name>=100
```

## Per-region triage

Pull the actual error messages the workload was emitting in the
affected region:

```bash
tools/dx/enclave-logs.sh --since 30m --region us-central1 --grep "error|fatal|panic|denied|failed"
tools/dx/enclave-logs.sh --since 30m --region us-central1 --top   # top messages by count
```

Common patterns and their meanings:

| Log substring | Diagnosis |
|---|---|
| `acme_get_certificate_failed sni=""` | **Background noise.** Health-check probes hit the LB IP without SNI all the time; ~50/hour every hour, on healthy and unhealthy hours alike. **NOT** evidence of an outage on its own. Compare the count against another hour using `tools/dx/enclave-logs.sh --since <healthy-hour>` before chasing this. |
| `acme_get_certificate_failed ... HostWhitelist` | Same — probe hit raw IP instead of `api.quillrouter.com`. Background noise. |
| `bootstrap/gcp: ... key: secret fetch http 403` | Workload SA missing `roles/secretmanager.secretAccessor` on the named secret. Re-run `tools/deploy-gcp-bootstrap.sh` or grant the binding directly. |
| `env var ... is not allowed to be overridden on this image` | Confidential Space launch policy `allow_env_override` doesn't include the env name. Add it to the Dockerfile LABEL and rebuild. |
| `provider error` http 502 | Upstream provider failing OR enclave provider client misrouting. Check upstream's status page; if down, route customer requests via `provider.only=[]` to a healthy provider. |
| `attestation through TPM quote` (info, frequent) | Normal — every health check probe records this. |

> **Don't post-hoc the first scary string you see.** Run `tools/dx/enclave-logs.sh --since <healthy-hour> --top` for a known-good hour and diff against the bad hour. If the error counts are similar, the error isn't your culprit.

## Attestation chain

Attestation probes hit `/attestation?nonce=...` and verify the
returned token. Failures usually mean:

1. **Workload SA can't refresh the attestation token** — check
   `iam.serviceAccountTokenCreator` on `quill-workload@…`.
2. **GCS log bucket inaccessible** (Confidential Space refuses to
   start without it) — check `quill-acme-cache` bucket exists and SA
   has read.
3. **Image digest mismatch** — verify
   `trust-page/image-digest-gcp.txt` matches the actually-running VM
   metadata `tee-image-reference`.

```bash
gcloud compute instances list --project=quill-cloud-proxy \
  --filter="name~quill-enclave-mig" --format="value(name,zone)" | \
while read name zone; do
  digest=$(gcloud compute instances describe "$name" --zone="$zone" \
    --project=quill-cloud-proxy --format=json 2>/dev/null | \
    python3 -c "import json,sys; d=json.load(sys.stdin); print(next((i['value'] for i in d.get('metadata',{}).get('items',[]) if i.get('key')=='tee-image-reference'),''))")
  echo "$name -> $digest"
done
```

Compare each instance's image to `trust-page/image-reference-gcp.txt`.
A drift means a stale instance survived a rollout — delete it and let
the MIG provision a fresh one.

## After resolution

1. **Did synthetics catch it?** If yes, the auto-rollback should have
   triggered. If it did, the workflow run will be red — leave a note
   in the run summary explaining the actual root cause.
2. **Did synthetics MISS it?** Higher-priority follow-up — extend
   probe coverage to catch this class of failure.
3. **Was the runbook useful?** Update with anything missing while
   it's fresh.
4. **File a postmortem** for any incident > 5 min impact.
