# Historical outage investigation

Use when a status-page bucket > 1h ago is red and you need to figure
out why. The public `status.json` only carries ~5 min of recent
sample data; deeper investigation requires the synthetic monitor's
DB samples + Cloud Logging + Cloud Monitoring metrics.

## Step 1 — Verify which probes failed

The status page shows aggregate uptime per component per hour. The
synthetic monitor stores every individual probe sample with full
context. To get them:

```sql
-- Run against the TR control plane DB (Cloud SQL)
SELECT
  created_at,
  monitor_region,
  target_region,
  probe_type,
  target_url,
  effective_status,
  error_type,
  http_status,
  latency_milliseconds,
  selected_provider,
  selected_model
FROM synthetic_samples
WHERE created_at >= '2026-05-06T03:00:00Z'
  AND created_at <  '2026-05-06T04:00:00Z'
  AND effective_status IN ('down', 'degraded')
ORDER BY created_at;
```

This tells you exactly **which target failed, with what error, from
which monitor region**. Patterns to look for:

| Pattern | Likely cause |
|---|---|
| All failed samples target one `target_url` (e.g., a single provider model) | That upstream provider was down for that hour |
| All failed samples have one `monitor_region` | The monitor itself or its network had a regional issue, not the API |
| All failed samples target one `target_region` (across probe_types) | Regional LB or regional MIG issue |
| `error_type=ReadTimeout` clustered on `chat_completions` probes | TR routed to a slow/dead upstream; check `selected_provider` |
| `error_type=ConnectTimeout` | TLS or LB dropped before the request reached the workload |

## Step 2 — Cross-reference Cloud Logging at the workload

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

## Step 3 — Cloud Monitoring for the LB

Backend 5xx rate, healthy-backend count, request latency p99 — all
exposed as Cloud Monitoring metrics for the load balancer.

```bash
# Inspect via metrics explorer for the hour:
#   loadbalancing.googleapis.com/https/backend_request_count
#   filter: backend_service_name = quill-enclave-bes-us | -eu
#   group_by: response_code_class
# Look for elevated 5xx during the bucket.
```

If the LB shows 5xx, the workload was returning errors. If the LB
shows healthy-backends dropping to 0 briefly, that's a MIG-side
event (instance recreate, surge during a rollout, autohealing).

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

## Honest caveat

If after Steps 1–5 you still don't know the root cause, **say so in
the incident postmortem**. Don't pick the first plausible-looking
log line and call it the cause. Doing that this session cost 30 min
of false-confidence time and led me to write a runbook diagnosing
"ACME TLS failures" as the cause of a 51-min outage when the actual
data showed ACME was background noise. The synthetic samples DB is
the source of truth for which probes failed; the enclave logs only
help if the failure was IN the enclave. Many outages — upstream
provider issues, monitor-side network blips, regional LB events —
won't have signal in the enclave logs at all.
