# Runbooks

Operational playbooks for TrustedRouter + Quill Cloud Proxy. Each
runbook is short, action-oriented, and assumes you already know the
architecture (see top-level README for that).

If you're paged or notice red on https://status.trustedrouter.com/,
start with [incident-response.md](./incident-response.md).

## Current architecture (DNS & health) — read this first

The enclave fleet has **no GCP load balancer** — the serving path is **DNS,
managed by the reconciler.** A GCP health check can't usefully validate a
Confidential Space enclave: an HTTP/L7 probe needs the in-VM TLS cert it can't
get, and a bare-TCP:443 probe only proves the socket accepts — not that the
instance *attests*. Attestation is the only health signal that means anything
here, so the reconciler owns membership. **Ignore any older step that runs
`gcloud compute backend-services get-health` or waits on "backend health"; there
is no LB.**

> History (so git-log spelunkers aren't confused): an LB existed until
> 2026-06-18, then a **bare-TCP:443** LB was briefly trialed 2026-06-19 to test
> whether an L4 health check could pass a CS enclave (paired with a 30 s
> handshake read-deadline in `serveOne` so an L4 probe closes cleanly). It
> couldn't — every backend stayed `UNHEALTHY` even with the read-deadline image
> live in us-east4 and europe-west4 — so the whole stack (`quill-enclave-bes-*`,
> `-fr-*`, `quill-enclave-tcp-443-*`, `quill-lb-ip-*`) was torn down again the
> same day. Don't recreate it. (`tools/deploy-gcp-mig.sh` still re-creates it on
> a roll until that's stripped — see the deploy runbooks.)

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
