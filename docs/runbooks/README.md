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
  reconciler-published A records pointing at **only that region's** VMs.
- **4 GCP regions:** `quill-enclave-mig-us` (us-central1),
  `quill-enclave-mig-useast4` (us-east4), `quill-enclave-mig-eu`
  (europe-west4), and `quill-enclave-mig-uswest1` (us-west1), all Intel TDX on
  `c3-standard-4`. us-west1 is the newest: while it is listed in
  `tools/gcp-enclave-migs-pending.txt` rather than `tools/gcp-enclave-migs.txt`
  it is being bootstrapped, and the reconciler publishes
  `api-us-west1.quillrouter.com` but never adds the region to the canonical
  answer (see [Adding a gateway region](#adding-a-gateway-region)). São Paulo
  (`quill-enclave-mig-sa`, southamerica-east1, AMD SEV because TDX is not
  available there) is retired. The MIGs have **no
  autohealing** (the reconciler is the health authority); `deploy-gcp-mig.sh`
  actively `--clear-autohealing`. A MIG only recreates a VM on actual VM death,
  not on app-health failure.
- **The real operator signal** is direct per-instance `/attestation` over the
  canonical SNI (`tools/verify-attestation.py`, or its `--binding-stress` mode)
  plus the reconciler job logs
  (`gcloud logging read 'resource.type="cloud_run_job" AND resource.labels.job_name="enclave-dns-reconciler"' --limit 20`),
  **not** GCP backend health.

## Adding a gateway region

The deploy refuses to run unless production's `quill-enclave-mig-*` MIGs match
the inventory, and the rollout is what creates a MIG. A new region therefore
goes in through a second inventory, `tools/gcp-enclave-migs-pending.txt`, and is
promoted by a later commit. Both files are bare `region:mig` lines (several
parsers read them, so they cannot hold comments);
`tools/gcp_enclave_inventory.py` enforces the rules for the rollout and
`tools/reconcile-enclave-dns.py` reads both files for DNS. A production MIG
that neither file names still fails the deploy.

**The three states.**

| | 1. PENDING | 2. PENDING, known to the control plane | 3. PROMOTED |
|---|---|---|---|
| Listed in | `gcp-enclave-migs-pending.txt` | the same, plus quill-router `ENCLAVE_REGIONS` | `gcp-enclave-migs.txt` |
| MIG | may be absent: the first deploy creates it | exists | must exist, or the deploy refuses |
| `api-<region>.quillrouter.com` | cold CNAME until the first rollout's direct canary passes; from then on the reconciler keeps it equal to the region's attested VMs | maintained | maintained |
| Canonical (`api.trustedrouter.com`, its mirrors, the confidential names) | **never**, whatever `QUILL_EXCLUDE_CANONICAL_REGIONS` says | **never** | yes |
| Synthetic monitor / status.json | no target | has a `target_region` entry | has one |
| TLS expiry check (`tools/check-public-tls.py`) | not probed | not probed | probed |

A pending region is rolled, drained, relieved of a stockout and held to the
Stage D flag bijection exactly like a serving one. The only differences are that
its MIG may be absent and that it cannot receive canonical traffic.

**Preconditions, checked by hand.** Nothing in the pipeline checks these, and
each one fails the first rollout late if it is wrong:

1. The cold CNAME exists: `api-<region>.quillrouter.com. CNAME api.quillrouter.com.`
   in zone `quillrouter-com`. `tools/verify-region-before-dns.sh` swaps that
   CNAME for one verified VM so the VM can obtain the regional certificate, and
   fails closed when the name has neither a CNAME nor an A record.
   ```bash
   gcloud dns record-sets list --zone=quillrouter-com --project=quill-cloud-proxy \
     --name=api-<region>.quillrouter.com.
   ```
2. Every zone you will pass in `MIG_ZONES` supports Intel TDX for the machine
   type (`c3-standard-4`); see Google's "Confidential VM supported
   configurations". On 2026-09-21 that was us-central1-a/b/c, us-west1-a/b,
   us-east4-a/b/c and europe-west4-a/b/c. A regional MIG created without
   `--zones` gets three zones chosen by Google, which is how us-central1 came
   to span zone f (no TDX hosts at all); on 2026-09-20/21 one stocked-out zone
   then blocked every deploy for 22 hours. A group's zones cannot be changed
   after it is created, so `tools/deploy-gcp-mig.sh` reads `MIG_ZONES` only
   when it creates the MIG (and creates it BALANCED with redistribution off).
3. The region has C3 quota for a full surge: the 2 serving VMs plus their 2
   replacements, 16 vCPUs of `c3-standard-4`.
   ```bash
   gcloud compute regions describe <region> --project=quill-cloud-proxy --format=json \
     | jq '.quotas[] | select(.metric == "C3_CPUS")'
   ```

Networking needed nothing for us-west1 (checked 2026-09-21): the `default`
network has a subnet there, and the `quill-allow-public-tls` firewall rule
(tcp/443, target tag `quill-enclave`) is global. Check the subnet for any other
region.

**Commit 1: bootstrap (state 1).** One commit that

- adds `<region>:quill-enclave-mig-<short>` to `tools/gcp-enclave-migs-pending.txt`;
- adds a "Refresh AWS credentials ..." + "Roll ... GCP MIG" step pair to
  `.github/workflows/deploy-enclave-gcp.yml`, copied from the US East pair and
  placed LAST, so a first-time region cannot hold up the regions that serve,
  with `MIG_ZONES` in the roll step's `env`;
- adds the region to `tools/stage-d-heartbeat-regions.txt` and
  `tools/stage-d-terminate-regions.txt` if the step turns those flags on (the
  gate in `tools/tests/test-stage-d-gates.sh` holds a pending region to the
  same bijection as a serving one);
- adds the region to `region_mig()` in `tools/cleanup-enclave-rollout-drains.sh`,
  to the `region` options of `.github/workflows/relieve-mig-stockout.yml`, and
  to the usage text of `tools/dx/enclave-logs.sh`.

`python3 tools/test_rollout_safety.py` cross-checks those lists against both
inventories. The commit deploys the gateway and rebuilds the scheduled
reconciler's image, which carries both inventory files.

On that deploy the inventory check passes with the MIG absent, the capture step
records an empty previous template, and `tools/roll-secondary-region.sh` takes
its first-deployment path. It sets the rollout drain, and while that drain is set
the reconciler leaves the cold CNAME alone. `tools/deploy-gcp-mig.sh` creates the
template and the MIG; `tools/verify-region-before-dns.sh` verifies every VM
through the canonical SNI, swaps the CNAME for one verified VM so it can obtain
the regional certificate, and verifies every VM through the regional SNI. Only
then does the script let the reconciler publish the region's full A set
(`QUILL_ALLOW_DRAINED_REGIONAL_PROMOTION_REGIONS`). With no synthetic target
yet, direct per-instance attestation + PONG is the gate.

If that first rollout fails there is nothing to roll back to, so recovery
refuses to touch anything. The region's rollout drain is left in place on
purpose: `tools/cleanup-enclave-rollout-drains.sh` never clears a pending
region's drain, because "stable and attesting" is all it checks and the
bootstrap gate asks for more, and the drain is what keeps the reconciler from
publishing VMs that failed that gate. The region's own rollout step clears it
when the gate passes. The serving regions have already rolled; the deploy
is red and the transitional trust set stays published. A MIG that was already
created stays too, which puts the retry under the rule below: after fixing the
cause, either delete the half-made MIG (it serves nothing, and the next deploy
is a first deployment again) or get the region into state 2 before retrying.

**Then the control plane learns the region (state 2).** Add the region to
quill-router's `ENCLAVE_REGIONS` and deploy the control plane, so the synthetic
monitor probes `api-<region>.quillrouter.com` and
https://trustedrouter.com/status.json carries a `target_region` entry for it.

This is the one sharp edge, and it has a deadline. Once the pending MIG exists,
every later deploy reaches the region's step with a previous template, and
`tools/roll-secondary-region.sh` then fails closed unless status.json has that
entry. So the control-plane change has to be deployed before the next gateway
deploy reaches the region's step. If it is not, that run goes red at "Roll
<region> GCP MIG" with `existing region is missing from synthetic status;
failing closed`, and the script rolls the region back to its previous template.
Nothing that serves is affected: the serving regions rolled earlier in the same
run and keep the new image, the pending region is not in canonical DNS, and the
trust set stays transitional (both digests published) because
`finalize-trust-artifacts` only runs after a green rollout. Re-running the
failed `rollout` job, or the next deploy, once the control plane is deployed
fixes it: the step finds its synthetic target and the trust set collapses.

**Commit 2: promotion (state 3).** Once the region is `up` in status.json, move
its line from `tools/gcp-enclave-migs-pending.txt` (leave the file in place,
empty) to the end of `tools/gcp-enclave-migs.txt`, and move it between the two
lists pinned in `tools/test_rollout_safety.py`
(`test_gcp_rollout_inventory_matches_deployed_regions`). That commit redeploys
the scheduled reconciler and runs a full deploy; from then on the reconciler
also publishes the region's VMs in `api.trustedrouter.com`, and
`tools/check-public-tls.py` watches its certificate. `tools/dns/main.tf` still
lists the region under `quill_cold_region_aliases` (as it does us-central1); no
pipeline applies that module, but drop the region from the list before applying
it by hand, or Terraform will try to put the cold CNAME back.

## Catalog

| Runbook | When to use |
|---|---|
| [enclave-state-2026-06-19.md](./enclave-state-2026-06-19.md) | Current-state snapshot + copy-paste verification checklist + manual-deploy procedure. Start here to confirm the fleet is healthy. |
| [azure-enclave.md](./azure-enclave.md) | Azure SEV-SNP/MAA enclaves: stand up a region from scratch, deploy, audit, verify. The only Azure source of truth. |
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
