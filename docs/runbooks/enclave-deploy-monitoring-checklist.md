# Enclave Deploy Monitoring Checklist

Use this during every GCP enclave deploy, including emergency deploys.
The goal is to avoid waiting on a slow rollout while the public API is
quietly serving a bad or stale image.

## Rule

Do not wait passively on any deploy step for more than 2 minutes.
If a step is still running, run the relevant external checks below and
write down the result before continuing to wait.

## Before Rollout

Capture the target release:

```bash
git rev-parse --short HEAD
cat trust-page/image-reference-gcp.txt
cat trust-page/image-digest-gcp.txt
gh run list --workflow=deploy-enclave-gcp.yml --repo Lore-Hex/quill-cloud-proxy --limit=5
```

Capture current traffic:

```bash
dig @8.8.8.8 +short api.quillrouter.com A
dig @1.1.1.1 +short api.quillrouter.com A
dig @ns-cloud-d1.googledomains.com +short api.quillrouter.com A

gcloud dns record-sets list \
  --zone=quillrouter-com \
  --project=quill-cloud-proxy \
  --name=api.quillrouter.com. \
  --type=A
```

Capture rollback points:

```bash
gcloud compute instance-groups managed describe quill-enclave-mig-us \
  --region=us-central1 --project=quill-cloud-proxy \
  --format='value(versions[0].instanceTemplate)'

gcloud compute instance-groups managed describe quill-enclave-mig-eu \
  --region=europe-west4 --project=quill-cloud-proxy \
  --format='value(versions[0].instanceTemplate)'
```

## During Each Region Rollout

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

## Before Moving Traffic

Never move DNS or load balancer traffic based only on MIG stability.
First prove the exact target IPs or regional endpoint pass:

```bash
for ip in <new-ip-1> <new-ip-2>; do
  curl -sS -o /dev/null -w '%{http_code} %{time_total}\n' \
    --resolve api.trustedrouter.com:443:${ip} \
    --max-time 12 \
    "https://api.trustedrouter.com/attestation?nonce=$(openssl rand -hex 16)"
done
```

If any old IP fails attestation and any new IP passes, switch traffic
toward the passing new IPs rather than waiting on the stale route.

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
- The MIG waits for health longer than 5 minutes and direct instance
  smoke disagrees with backend health.
- The old traffic path fails attestation while a new candidate passes.

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
