# Enclave Deploy Monitoring Checklist

Use this during every GCP enclave deploy, including emergency deploys.
The goal is to avoid waiting on a slow rollout while the public API is
quietly serving a bad or stale image.

## Rule

Do not wait passively on any deploy step for more than 2 minutes.
If a step is still running, run the relevant external checks below and
write down the result before continuing to wait.

Do not replace a regional MIG while that region is still in the canonical
`api.trustedrouter.com` DNS answer. The safe order is:

1. Reconcile canonical DNS with the target region excluded.
2. Wait until authoritative DNS no longer contains that region's IPs, then wait
   one TTL for recursive resolver drain.
3. Roll the regional MIG.
4. Wait for MIG stable, attestation healthy, and regional synthetic green.
5. Re-add the region to canonical DNS.

This is the zero-downtime deploy path that works without buying spare
Confidential VM capacity for blue/green fleets. During the roll, the explicit
regional hostname may be degraded, but the canonical API keeps serving from the
other warm regions.

## Before Rollout

Capture the target release:

```bash
git rev-parse --short HEAD
cat trust-page/image-reference-gcp.txt
cat trust-page/image-digest-gcp.txt
gh run list --workflow=deploy-enclave-gcp.yml --repo Lore-Hex/quill-cloud-proxy --limit=5
```

Capture current traffic. The primary record is now **`api.trustedrouter.com`**
(A, reconciler-managed, zone `trustedrouter-com`); `api.quillrouter.com` is a
CNAME to it.

```bash
dig @8.8.8.8 +short api.trustedrouter.com A
dig @1.1.1.1 +short api.trustedrouter.com A

gcloud dns record-sets list \
  --zone=trustedrouter-com \
  --project=quill-cloud-proxy \
  --name=api.trustedrouter.com. \
  --type=A
```

Capture rollback points (all three regions):

```bash
for pair in us:us-central1 useast4:us-east4 eu:europe-west4; do
  short=${pair%%:*}; region=${pair##*:}
  gcloud compute instance-groups managed describe quill-enclave-mig-$short \
    --region=$region --project=quill-cloud-proxy \
    --format="value(versions[0].instanceTemplate)"
done
```

## During Each Region Rollout

Before starting the replace, confirm the target region is drained from
canonical DNS:

```bash
QUILL_API_HOST=api.trustedrouter.com \
QUILL_DNS_ZONE=trustedrouter-com \
QUILL_PUBLISH_REGIONAL=1 \
QUILL_REGIONAL_ZONE=quillrouter-com \
QUILL_REGIONAL_SUFFIX=quillrouter.com \
QUILL_EXCLUDE_CANONICAL_REGIONS=<region> \
  uv run --script tools/reconcile-enclave-dns.py --apply

bash tools/wait-canonical-drained.sh <region>
```

Poll the workflow and MIG state:

```bash
gh run view <run-id> --repo Lore-Hex/quill-cloud-proxy --json status,conclusion,jobs

gcloud compute instance-groups managed describe quill-enclave-mig-us \
  --region=us-central1 --project=quill-cloud-proxy \
  --format='yaml(isStable,status,versions,currentActions,targetSize)'

gcloud compute instance-groups managed list-errors quill-enclave-mig-us \
  --region=us-central1 --project=quill-cloud-proxy
```

List candidate backend IPs and smoke each one directly with the public
hostname as SNI:

```bash
gcloud compute instances list \
  --project=quill-cloud-proxy \
  --filter='name~quill-enclave AND zone~us-central1' \
  --format='table(name,zone,status,networkInterfaces[0].accessConfigs[0].natIP)'

for ip in <candidate-ip-1> <candidate-ip-2>; do
  echo "== ${ip}"
  curl -sS -o /dev/null -w 'health %{http_code} %{time_total}\n' \
    --resolve api.trustedrouter.com:443:${ip} \
    --max-time 8 \
    https://api.trustedrouter.com/health || true

  curl -sS -o /dev/null -w 'attestation %{http_code} %{time_total}\n' \
    --resolve api.trustedrouter.com:443:${ip} \
    --max-time 12 \
    "https://api.trustedrouter.com/attestation?nonce=$(openssl rand -hex 16)" || true
done
```

Required result before using a candidate instance:

- `/health` reaches the enclave. `401` is acceptable if the endpoint is auth-gated.
- `/attestation` returns `200`.
- The attestation token reports the expected image digest.
- `dbgstat` is absent or disabled. `enabled` is a blocker.
- The cert fingerprint in the token matches the cert from the same TLS connection.

Run the verifier once traffic reaches the candidate or regional hostname:

```bash
DIGEST="$(cat trust-page/image-digest-gcp.txt)"

uv run --script tools/verify-attestation.py \
  --api-host api.trustedrouter.com \
  --expect-digest "${DIGEST}" \
  --samples 4

uv run --script tools/verify-attestation.py \
  --api-host api.quillrouter.com \
  --expect-digest "${DIGEST}" \
  --samples 4
```

## DNS is moved automatically — verify, don't hand-edit

You don't move DNS by hand. The `enclave-dns-reconciler` job (every 2 min)
attests each instance and publishes only the passing ones, so a freshly-rolled
instance joins `api.trustedrouter.com` within a reconcile cycle + TTL (≈3 min)
once it attests. Your job is to confirm it actually happened, and to nudge it if
it lags:

```bash
# Force a reconcile and read its verdict per instance (ok / FAIL)
gcloud run jobs execute enclave-dns-reconciler --region=us-central1 --project=quill-cloud-proxy --wait
gcloud logging read 'resource.type="cloud_run_job" AND resource.labels.job_name="enclave-dns-reconciler"' \
  --project=quill-cloud-proxy --limit=20 --freshness=10m --format='value(textPayload)'

# Then confirm the published A record matches the healthy new IPs
gcloud dns record-sets list --zone=trustedrouter-com --project=quill-cloud-proxy \
  --name=api.trustedrouter.com. --type=A --format='value(rrdatas[].list())'
```

If a new instance passes `/attestation` directly but the reconciler marks it FAIL,
the usual cause is a digest the reconciler doesn't accept yet — it accepts the
live trust-page digest plus the newest `gcp-release-*` in Artifact Registry, so
make sure the running digest is one of those (publish the trust page if the
release is new: `gh workflow run publish-trust-page.yml --ref main`).

## After Moving Traffic

Verify public DNS and both public hostnames:

```bash
for resolver in 8.8.8.8 1.1.1.1 ns-cloud-d1.googledomains.com; do
  echo "== ${resolver}"
  dig @${resolver} +short api.quillrouter.com A
done

for host in api.trustedrouter.com api.quillrouter.com; do
  echo "== ${host}"
  curl -sS -o /dev/null -w 'health %{http_code} %{time_total}\n' \
    --max-time 8 "https://${host}/health"
  curl -sS -o /dev/null -w 'attestation %{http_code} %{time_total}\n' \
    --max-time 12 "https://${host}/attestation?nonce=$(openssl rand -hex 16)"
done
```

Then run the full attestation verifier and a cheap product smoke:

```bash
DIGEST="$(cat trust-page/image-digest-gcp.txt)"

uv run --script tools/verify-attestation.py \
  --api-host api.trustedrouter.com \
  --expect-digest "${DIGEST}" \
  --samples 4

SMOKE_KEY="$(gcloud secrets versions access latest \
  --secret=trustedrouter-synthetic-monitor-api-key \
  --project=quill-cloud-proxy)"

curl -sS --max-time 45 \
  -H "authorization: Bearer ${SMOKE_KEY}" \
  -H "content-type: application/json" \
  -d '{"model":"trustedrouter/monitor","messages":[{"role":"user","content":"reply exactly PONG"}],"max_tokens":8}' \
  https://api.quillrouter.com/v1/chat/completions
```

## Stop Conditions

Stop the rollout and either roll back or use the emergency path if any
of these happen:

- Public `/attestation` is not `200`.
- The verifier reports a digest mismatch.
- The verifier reports `dbgstat=enabled`.
- The verifier reports a cert binding mismatch.
- The MIG has been stable for >5 minutes but the reconciler still won't add the
  new instances to DNS (and direct `/attestation` on them is non-200).
- A digest mismatch the reconciler can't resolve (running digest is neither the
  trust-page digest nor the newest `gcp-release-*`).

## Incident Notes

For every deploy, capture:

- Run ID.
- Target commit and digest.
- Before and after DNS answers.
- Backend IPs checked.
- `/health` and `/attestation` result for every IP.
- Final verifier output for both `api.trustedrouter.com` and
  `api.quillrouter.com`.

This evidence is more valuable than the workflow's final green check,
because it proves what customers were actually reaching.
