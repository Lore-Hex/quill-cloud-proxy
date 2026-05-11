# AWS-as-primary failover runbook

**Audience**: on-call operator handling a GCP-side outage.

**What "AWS-as-primary" means here**: `api.quillrouter.com` is served by
Cloudflare LB with two pools — GCP (weight 99) and AWS (weight 1).
A GCP-side outage drops the GCP pool from CF rotation and 100% of
inference traffic flows to the AWS Nitro enclave in us-west-2. The
control plane similarly has GCP Cloud Run + AWS ECS Fargate behind
two LBs.

This runbook covers:
1. How you know AWS is now primary (signals + dashboards).
2. What to verify within the first 5 minutes.
3. How to manually force AWS primary (when CF can't).
4. How to fail back to GCP-primary cleanly.
5. Known caveats + cost ceilings.

---

## 1. Signals that AWS is primary

You'll see one or more of:

- **`https://trustedrouter.com/status.json`** — at least one
  `target_region` check has `effective_status: down` for ≥3
  consecutive minutes. (Cloudflare LB drops pool members at
  `--rollback-after 3` minutes of failed health checks; it's the
  same threshold the deploy watchdog uses.)
- **Cloudflare LB pool health** —
  `https://dash.cloudflare.com/<account>/load-balancing/manage/<lb>`
  shows `quill-gcp-pool` as **Unhealthy** (red), `quill-aws-pool`
  as **Healthy** (green). Pool-health is per-POP; you'll see the
  `Unhealthy in 283/283 POPs` (full degraded) or partial.
- **PagerDuty alert** — `synthetic_monitor.deploy_canary_failed`
  or `synthetic_monitor.region_down` fires off the watchdog
  output.
- **Customer reports** — anyone in EU asking "TR keeps timing
  out from europe-west4"; clients with sticky retries hit AWS
  on the second attempt and notice slightly higher latency
  (~30-50ms p50 added vs us-central1).

If you only see *one* of those and the rest looks healthy, treat
it as a single-probe blip until at least two corroborating
signals land. Forcing failover on a false positive is more
expensive than a brief degradation.

## 2. First 5 minutes — verify AWS is actually serving

Before you do anything corrective, confirm the AWS path is up:

```bash
NLB_IP=$(dig +short quill-enclave-nlb-df6a5999caabf334.elb.us-west-2.amazonaws.com @8.8.8.8 | head -1)

# (a) TLS cert is a real LE cert — should be CN=api.quillrouter.com
# signed by Let's Encrypt CN=E8, NOT self-signed.
echo "" | openssl s_client -connect "$NLB_IP:443" -servername api.quillrouter.com 2>/dev/null \
  | grep -E "subject=|issuer="

# (b) End-to-end chat completion through the AWS enclave only.
SMOKE_KEY=$(gcloud secrets versions access latest --secret=trustedrouter-synthetic-monitor-api-key --project=quill-cloud-proxy)
curl -sS --resolve api.quillrouter.com:443:$NLB_IP \
  -X POST "https://api.quillrouter.com/v1/chat/completions" \
  -H "Authorization: Bearer ${SMOKE_KEY}" -H "Content-Type: application/json" --max-time 30 \
  -d '{"model":"anthropic/claude-haiku-4.5","messages":[{"role":"user","content":"failover smoke"}],"max_tokens":12}'
```

If (a) returns a self-signed cert OR (b) errors out, **do NOT
force CF to fail over to AWS** — AWS isn't ready to take the
traffic. Page the cert team and stay on GCP until the AWS cert
is right.

## 3. Manually force AWS primary (CF didn't auto-fail-over)

Only do this if **section 2 verified AWS works** and CF hasn't
already dropped GCP. Reasons CF might not auto-fail-over: false
health-check passes (GCP enclave responds 200 but inference is
broken behind it), regional CF degradation, manual override
left in place from a prior incident.

```bash
CF_TOKEN=$(grep -E '^(CLOUDFLARE_API_TOKEN|CF_API_TOKEN)=' ~/.quill_cloud_keys.private | head -1 | cut -d= -f2-)
CF_ACCT=2698c706fd4793c818af14adad4e1a39
GCP_POOL=a2bf12ab24decf52402b4c4844ae7cd1

# Disable the GCP pool. Every active TCP connection that's open
# stays on GCP (sticky), but every new connect goes to AWS.
curl -sS -X PATCH \
  -H "Authorization: Bearer ${CF_TOKEN}" \
  -H "Content-Type: application/json" \
  "https://api.cloudflare.com/client/v4/accounts/${CF_ACCT}/load_balancers/pools/${GCP_POOL}" \
  -d '{"enabled": false}'
```

Within 30 seconds CF edges propagate the change and 100% of new
traffic lands on AWS. Watch the synthetic monitor recover from
`down` to `up` over the next 1–2 minutes.

**If AWS starts buckling under load**: the ASG is configured min=1
max=50. Auto-scaling triggers at >70% CPU on the single
pre-warmed instance. New instances take **~5-8 min** to fully
bootstrap (docker pulls + nitro-cli build-enclave + run-enclave +
autocert cache load). During that window AWS may 429 / 503 a
fraction of traffic. Pre-empt this by manually bumping the ASG:

```bash
aws autoscaling update-auto-scaling-group \
  --auto-scaling-group-name quill-enclave-asg \
  --desired-capacity 5 --region us-west-2
```

Five m5n.xlarge instances handle ~1k concurrent connections each
based on the GCP-side baseline. If you're seeing more than ~3k
concurrent on the LB, bump to 10. The hard cap is 50.

## 4. Fail back to GCP-primary

Once GCP is healthy again — confirm via:

```bash
# GCP enclave-side LB is back up
curl -sS https://trustedrouter.com/status.json | jq '.data.current.checks[] | select(.target_region=="us-central1")'

# End-to-end through GCP
curl -sS --resolve api.quillrouter.com:443:34.61.11.3 \
  -X POST "https://api.quillrouter.com/v1/chat/completions" \
  -H "Authorization: Bearer ${SMOKE_KEY}" -H "Content-Type: application/json" --max-time 30 \
  -d '{"model":"anthropic/claude-haiku-4.5","messages":[{"role":"user","content":"recovery smoke"}],"max_tokens":12}'
```

Re-enable the GCP pool:

```bash
curl -sS -X PATCH \
  -H "Authorization: Bearer ${CF_TOKEN}" \
  -H "Content-Type: application/json" \
  "https://api.cloudflare.com/client/v4/accounts/${CF_ACCT}/load_balancers/pools/${GCP_POOL}" \
  -d '{"enabled": true}'
```

Optionally bring the AWS ASG back to the resting size (1
pre-warmed instance):

```bash
aws autoscaling update-auto-scaling-group \
  --auto-scaling-group-name quill-enclave-asg \
  --desired-capacity 1 --region us-west-2
```

The CF LB applies the 99/1 weights again; AWS keeps the 1%-trickle
warm pattern that prevents the AWS path from going stale.

## 5. Known caveats

- **AWS Nitro single-region**. us-west-2 only. A regional AWS
  outage (rare but real) takes the failover capacity down. There's
  no AWS-side failover region today; if AWS goes hard-down, the
  service is GCP-only.
- **Cross-cloud Spanner reads**. The AWS enclave + AWS Fargate
  read from Spanner nam6 via cross-cloud (~150-200ms RTT). Every
  `/v1/chat/completions` request makes 2-3 Spanner reads
  (authorize + settle). So **AWS-served latency is ~300-400ms
  higher than GCP-served latency** — clients should still
  complete normally but expect the p50 to walk up.
- **Spanner is the binding constraint**. A GCP-global Spanner
  outage takes both clouds down. Multi-cloud compute failover
  doesn't help here. The real fix is Stage 5b (CockroachDB
  multi-cloud), not yet shipped.
- **Cert renewal during outage**. If the AWS LE cert expires
  while CF is routing 100% to AWS (unlikely — cert renews 30
  days before expiry), TLS-ALPN-01 might fail because there's
  no GCP enclave to serve the challenge cert from the shared
  cache. If you see cert-expiry-related TLS errors during an
  AWS-primary period, force-fail-back to GCP for the duration of
  the renewal even if GCP is degraded — degraded GCP is better
  than expired-cert AWS.
- **Phala** is intentionally removed from `tr_keyed_providers`
  as of 2026-05-11 (security incident, awaiting their email).
  Don't treat phala-route 400s during an outage as a regression
  — they're expected until phala restores.

## 6. Costs while AWS-primary

Per hour, with ASG bumped to 10 m5n.xlarge instances:
- 10× m5n.xlarge on-demand × $0.30/hr = **$3/hr**
- NLB data processing ~$0.006/GB at typical 1M req/hr × 5KB → ~$0.03/hr
- AWS Secrets Manager: negligible
- Cross-cloud egress to GCP Spanner (~150kB/request × 1M req/hr = 150GB/hr × $0.02/GB) = **$3/hr**

So a sustained 1-hour AWS-primary event with bumped ASG ≈ **$6/hr**. A
24-hour failover would be ~$140 + the steady-state $145/mo we
already pay for the pre-warmed instance.

If a real fail-over goes longer than 24 hours, the AWS-side
control plane bill also starts mattering — Fargate at 0.5 vCPU /
1GB is ~$15/mo idle, scales linearly with active vCPU.

## 7. Game-day drill

A repeat of this scenario is the planned quarterly drill. The
pattern is captured in section 3 (disable GCP pool) → section 4
(re-enable GCP pool). Drill duration: 10 minutes AWS-only.
Customer impact: ~30s of new-connection 503s during the propagation
window, then normal service with slightly higher latency.

History:
- 2026-05-10 22:55Z: first drill — failed (AWS self-signed cert
  rejected by all clients).
- 2026-05-11 04:39Z: second drill after the AWS cert was fixed —
  TLS-validated, structured 401s during the drill confirmed the
  auth path works end-to-end. Real chat completions verified
  via direct NLB probe.
- Next drill: quarterly, scheduled at the start of each quarter.
