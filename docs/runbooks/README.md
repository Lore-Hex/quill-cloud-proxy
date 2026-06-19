# Runbooks

Operational playbooks for TrustedRouter + Quill Cloud Proxy. Each
runbook is short, action-oriented, and assumes you already know the
architecture (see top-level README for that).

If you're paged or notice red on https://status.trustedrouter.com/,
start with [incident-response.md](./incident-response.md).

## Current architecture (DNS & health) — read this first

The enclave fleet's **serving path is DNS, not a load balancer.** The GCP LB was
deleted 2026-06-18; a **bare-TCP:443** LB (`quill-enclave-bes-*` /
`quill-enclave-fr-*`, health check `quill-enclave-tcp-443-*`) was then restored
2026-06-19. The earlier objection was specifically about *HTTP / dedicated-port*
probes — those can't pass a Confidential Space enclave that terminates TLS in-VM —
so the restored check is a raw TCP connect to the publicly-open serving port,
paired with a 30 s handshake read-deadline in the enclave (`serveOne`) so an L4
probe (TCP connect, no ClientHello) closes cleanly with a FIN instead of pinning a
goroutine and reading half-open/UNHEALTHY.

**That LB is NOT the serving authority** — DNS points at attested instance IPs
published by the reconciler, not at the LB forwarding-rule IPs. As of 2026-06-19
every backend still reads `UNHEALTHY` (us-central1 Confidential VMs fail *all* GCP
health-check types — a platform quirk — and the TCP:443 path isn't yet proven live
in the other regions). So **do not treat `gcloud compute backend-services
get-health` as a serving signal.** It is at most a coarse liveness hint for a
secondary fast-failover layer that is not in the path today. Attestation, via the
reconciler, remains the membership gate.

- **Health authority = the control-plane reconciler**, `tools/reconcile-enclave-dns.py`,
  run as Cloud Run job **`enclave-dns-reconciler`** on Cloud Scheduler
  **`enclave-dns-reconciler-tick`** (every 2 min). It attests every
  `quill-enclave`-tagged RUNNING instance by IP (`tools/verify-attestation.py`)
  and publishes **only the healthy ones** into DNS (`MIN_HEALTHY=2`, never blanks
  the record). It accepts a digest **set** — the live trust-page digest plus the
  newest `gcp-release-*` digest in Artifact Registry — so it tolerates a rollout
  window. It is **not** in the serving path: if it stops, DNS freezes at last-good
  and serving continues. Force a cycle with
  `gcloud run jobs execute enclave-dns-reconciler --region=us-central1 --project=quill-cloud-proxy`.
- **DNS:** primary is **`api.trustedrouter.com`** (A record, reconciler-managed,
  Cloud DNS zone `trustedrouter-com`, TTL 60). `api.quillrouter.com` is a CNAME to
  it. Per-region retry hostnames `api-<gcp-region>.quillrouter.com` are
  reconciler-published A records pointing at **only that region's** VMs (each
  enclave whitelists only its own region's regional SNI, so they cannot point at
  the all-region set).
- **3 regions:** `quill-enclave-mig-us` (us-central1), `quill-enclave-mig-useast4`
  (us-east4), `quill-enclave-mig-eu` (europe-west4). The MIGs have **no
  autohealing** (the reconciler is the health authority); `deploy-gcp-mig.sh`
  actively `--clear-autohealing`. A MIG only recreates a VM on actual VM death,
  not on app-health failure.
- **The real operator signal** is direct per-instance `/attestation` over the
  canonical SNI (`tools/verify-attestation.py`, or its `--binding-stress` mode)
  plus the reconciler job logs
  (`gcloud logging read 'resource.type="cloud_run_job" AND resource.labels.job_name="enclave-dns-reconciler"' --limit 20`),
  **not** GCP backend health.

## Catalog

| Runbook | When to use |
|---|---|
| [incident-response.md](./incident-response.md) | Status page is red right now. First response. |
| [historical-outage-investigation.md](./historical-outage-investigation.md) | Status-page bucket > 1h ago is red and you need to figure out why. |
| [enclave-deploy-monitoring-checklist.md](./enclave-deploy-monitoring-checklist.md) | Checklist to run during every enclave deploy so public API, attestation, digest, and debug state are checked at each step. |
| [enclave-deploy-debugging.md](./enclave-deploy-debugging.md) | A GHA enclave deploy failed or rolled back. |
| [provider-onboarding.md](./provider-onboarding.md) | Adding a new upstream LLM provider (Together, Fireworks, …). |

## Tooling

`tools/dx/` holds quick-look scripts the runbooks lean on:

- **`enclave-logs.sh`** — fetch attested workload logs by time window.
  The Confidential Space launcher writes to a non-obvious log name;
  this wrapper applies the right filter.
  ```
  tools/dx/enclave-logs.sh --since 30m
  tools/dx/enclave-logs.sh --since 2026-05-06T03:00:00Z --until 2026-05-06T04:00:00Z --top
  tools/dx/enclave-logs.sh --since 1h --grep "error|panic|denied"
  ```

## When updating

A runbook earns its place by being followable under stress. If you
ever read one during an incident and find yourself filling in gaps,
update it the same week — when the steps are still fresh. Stale
runbooks are worse than no runbooks because they encode false
confidence.
