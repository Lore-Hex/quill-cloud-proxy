# Historical outage investigation

Use when a status-page bucket > 1h ago is red and you need to figure
out why. The public `status.json` only carries ~5 min of recent
sample data; deeper investigation requires the synthetic monitor's
DB samples + Cloud Logging + Cloud Monitoring metrics.

## Step 1 — Verify which probes failed

Synthetic samples are persisted in Bigtable (instance
`trusted-router-logs`, table `trustedrouter-generations`). Each sample
is a JSON blob keyed by reverse-time so you can range-scan a
specific hour cheaply.

Compute the reverse-time keys for your window:

```python
python3 -c "
import datetime as dt
def rt(s):
    p = dt.datetime.fromisoformat(s.replace('Z','+00:00'))
    return f'{9_999_999_999_999 - int(p.timestamp()*1000):013d}'
day = '2026-05-06'
start_hour = '2026-05-06T03:00:00Z'
end_hour   = '2026-05-06T04:00:00Z'
print(f'start: synthetic_day_recent#{day}#{rt(end_hour)}')
print(f'end:   synthetic_day_recent#{day}#{rt(start_hour)}')
"
```

Then read the range:

```bash
cbt -instance=trusted-router-logs -project=quill-cloud-proxy read \
  trustedrouter-generations \
  start='synthetic_day_recent#2026-05-06#8221959999999' \
  end='synthetic_day_recent#2026-05-06#8221963599999' \
  count=2000 \
  | grep '^    "{' | python3 -c "
import sys, json
from collections import Counter
samples = []
for line in sys.stdin:
    line = line.strip()[1:-1].replace('\\\\\"', '\"').replace('\\\\\\\\','\\\\')
    try: samples.append(json.loads(line))
    except: pass
not_up = [s for s in samples if str(s.get('status','')).lower() != 'up' or s.get('error_type')]
print(f'parsed {len(samples)} samples, {len(not_up)} not-up')
print('error_type:',     Counter(s.get('error_type') for s in not_up).most_common())
print('probe_type:',     Counter(s.get('probe_type') for s in not_up).most_common())
print('target_region:',  Counter(s.get('target_region') for s in not_up).most_common())
print('monitor_region:', Counter(s.get('monitor_region') for s in not_up).most_common())
print('selected_provider:', Counter(s.get('selected_provider') or '<none>' for s in not_up).most_common())
print('http_status:',    Counter(s.get('http_status') for s in not_up).most_common())
"
```

(`cbt` ships with `gcloud` — install via `gcloud components install cbt` if missing.)

This tells you exactly **which target failed, with what error, from
which monitor region**. Patterns to look for:

| Pattern | Likely cause |
|---|---|
| All failed samples target one `target_url` (e.g., a single provider model) | That upstream provider was down for that hour |
| All failed samples have one `monitor_region` | The monitor itself or its network had a regional issue, not the API |
| All failed samples target one `target_region` (across probe_types) | Regional LB or regional MIG issue |
| `error_type=ReadTimeout` clustered on `chat_completions` probes | TR routed to a slow/dead upstream; check `selected_provider` |
| `error_type=ConnectTimeout` | TLS or LB dropped before the request reached the workload |

## Step 2a — Per-request structured log

The enclave logs one `enclave.invoke_attempt` line per provider attempt
and one `enclave.invoke_complete` line per request. Format:

```
enclave.invoke_attempt request_id="..." attempt=1/3 model="..." provider="anthropic"
  endpoint="..." outcome=ok|fail ttfb_ms=234 total_ms=5678 bytes=12345 err="..."
enclave.invoke_complete request_id="..." outcome=ok|fail provider_used="..." model="..."
  endpoint="..." attempts=2 fallbacks=1 ttfb_ms=234 upstream_ms=5678 total_ms=6234 bytes=12345
```

This is the most direct signal for "was a specific upstream slow?" —
filter on `outcome=fail` or `err="ttfb_exceeded"` for the bad window:

```bash
gcloud logging read 'logName=~"confidential-space-launcher" AND textPayload:"enclave.invoke_attempt" AND textPayload:"outcome=fail" AND timestamp>="2026-05-06T03:00:00Z" AND timestamp<="2026-05-06T04:00:00Z"' \
  --project=quill-cloud-proxy --limit=500 \
  --format='value(textPayload)' \
  | grep -oE 'provider="[^"]+"|err="[^"]+"' | sort | uniq -c | sort -rn
```

`request_id` matches the TR control plane's authorization id, so you
can join with TR's gateway logs for end-to-end traces.

No prompt or response content is ever logged — only metadata.

## Step 2b — Cross-reference Cloud Logging at the workload

Use [tools/dx/enclave-logs.sh](../../tools/dx/enclave-logs.sh)
against the same hour AND against a healthy hour. Diff the top
messages — only differences are signal:

```bash
tools/dx/enclave-logs.sh --since 2026-05-06T03:00:00Z --until 2026-05-06T04:00:00Z --top --limit 2000 > /tmp/bad-hour.txt
tools/dx/enclave-logs.sh --since 2026-05-06T12:00:00Z --until 2026-05-06T13:00:00Z --top --limit 2000 > /tmp/good-hour.txt
diff /tmp/good-hour.txt /tmp/bad-hour.txt
```

**Counter-example: what isn't a smoking gun.** ACME `acme_get_certificate_failed`
errors look terrifying but show ~50/hour every hour, healthy or not.
Compare against a known-good hour before concluding ACME caused
anything.

## Step 3 — Reconciler + DNS history

Since 2026-06-18 the **serving path is DNS, not a load balancer** — DNS membership
is owned by the `enclave-dns-reconciler` job. (A TCP:443 LB was briefly trialed
2026-06-19 and torn down; for any bucket, ignore LB/backend health and use the
reconciler + DNS history — see README.) For a recent bucket, reconstruct what was in DNS and
what the reconciler decided:

```bash
# What the reconciler concluded each cycle (per-instance ok/FAIL, applied changes)
gcloud logging read 'resource.type="cloud_run_job" AND resource.labels.job_name="enclave-dns-reconciler" AND timestamp>="<start>" AND timestamp<="<end>"' \
  --project=quill-cloud-proxy --format='value(timestamp,textPayload)' --limit=50

# DNS A-record changes during the bucket (Cloud DNS change history)
gcloud dns record-sets changes list --zone=trustedrouter-com --project=quill-cloud-proxy \
  --format='table(startTime,status)' --limit=20

# MIG events in the affected region (recreate / surge / VM death)
gcloud compute instance-groups managed list-errors quill-enclave-mig-us \
  --region=us-central1 --project=quill-cloud-proxy
```

A region dropping out of `api.trustedrouter.com` during the bucket means the
reconciler stopped getting healthy `/attestation` from that region's VMs (digest
mismatch, ACME/cert failure, teeserver 500, or all VMs gone). Its `MIN_HEALTHY=2`
guard freezes the record rather than blanking it, so a partial failure shows up
as a *stale* DNS answer, not an empty one.

> For buckets **before 2026-06-18** the LB still existed — inspect
> `loadbalancing.googleapis.com/https/backend_request_count` filtered by
> `backend_service_name = quill-enclave-bes-{us,eu}`, grouped by
> `response_code_class`, for elevated 5xx or healthy-backends dropping to 0.

## Step 4 — Audit log: did anything change?

```bash
# Was a Cloud Run revision deployed?
gcloud logging read 'protoPayload.methodName="google.cloud.run.v1.Services.ReplaceService" AND timestamp>="2026-05-06T02:30:00Z" AND timestamp<="2026-05-06T04:00:00Z"' \
  --project=quill-cloud-proxy --format="value(timestamp,protoPayload.authenticationInfo.principalEmail,protoPayload.resourceName)" --limit=10

# Was a MIG template swapped?
gcloud logging read 'protoPayload.methodName=~"setInstanceTemplate|patch" AND resource.type="gce_instance_group_manager" AND timestamp>="2026-05-06T02:30:00Z" AND timestamp<="2026-05-06T04:00:00Z"' \
  --project=quill-cloud-proxy --format="value(timestamp,protoPayload.authenticationInfo.principalEmail,protoPayload.resourceName)" --limit=10

# Was a secret rotated?
gcloud logging read 'protoPayload.serviceName="secretmanager.googleapis.com" AND protoPayload.methodName=~"AddSecretVersion" AND timestamp>="2026-05-06T02:30:00Z" AND timestamp<="2026-05-06T04:00:00Z"' \
  --project=quill-cloud-proxy --format="value(timestamp,protoPayload.authenticationInfo.principalEmail,protoPayload.resourceName)" --limit=10
```

A change correlated with the start of the outage is the leading
suspect.

## Step 5 — Upstream providers' historical status

If the failed samples cluster on a specific `selected_provider`,
check that provider's public status page or their incident-history
RSS for the same window. Most upstream providers expose this. Add
links here as we learn the URLs:

- Anthropic: https://status.anthropic.com/
- OpenAI: https://status.openai.com/
- Google AI Studio / Vertex: https://status.cloud.google.com/
- Cerebras: https://cerebrascloud.statuspage.io/
- Together: https://status.together.ai/

Many regional outages on TR turn out to be regional outages on the
specific upstream the route landed on. The auto-rollback only fires
on TR's deploys, not on upstream incidents — so an upstream-caused
red bar doesn't get an automatic remediation. Customer recourse:
explicit `provider.only=[]` to a healthy provider, or
`trustedrouter/auto` will fail over.

## Worked example: 5/6 03:00 UTC

This procedure was applied to a real 51-min red bucket. Findings:

- **Step 1 (Bigtable):** 51 ReadTimeouts in 03:25–03:49 UTC, all
  `target_region=us-central1`, both monitor regions saw it equally,
  all `http_status=None` and `selected_provider=None` (request never
  completed within the 30s probe budget).
- **Step 2 (enclave logs):** us-central1 launcher logs in the failure
  window were unremarkable — normal attestation/token rates, ACME
  background noise unchanged.
- **Step 3 (LB metrics):** not pulled.
- **Step 4 (audit log):** no deploys, secret rotations, or admin ops
  during the window.
- **Step 5 (upstream status):** not investigated.

Most consistent story: an upstream provider routed-to by us-central1
was hanging for >30s on inference. The enclave doesn't currently log
per-request upstream attribution, so we can't identify *which*
provider from the data we keep. **Adding that log line is the gap
this incident exposed.**

## Observability gaps to close

When a real incident reveals a missing signal, file the gap here:

- [x] **Per-request enclave log** — `enclave.invoke_attempt` and
  `enclave.invoke_complete` (added after the 5/6 outage; see Step 2a).
- [ ] **Failed-probe routing-decision capture** — the synthetic monitor
  records `selected_provider=None` when a probe times out, because the
  enclave never returned. A separate probe that calls the authorize
  endpoint directly would capture the routing decision even when the
  later inference times out.

## Honest caveat

If after Steps 1–5 you still don't know the root cause, **say so in
the incident postmortem**. Don't pick the first plausible-looking
log line and call it the cause. Doing that this session cost 30 min
of false-confidence time and led to a runbook initially diagnosing
"ACME TLS failures" as the cause of the 5/6 51-min outage when the
actual data showed ACME was background noise. The synthetic samples
DB is the source of truth for which probes failed; the enclave logs
only help if the failure was IN the enclave. Many outages — upstream
provider issues, monitor-side network blips, regional LB events —
won't have signal in the enclave logs at all.
