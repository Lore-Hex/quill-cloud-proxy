# Gateway secondary regions in waves

A gateway rollout holds the shared gcp lease for about 140 minutes (p50,
2026-11-09 to 11-13). After us-central1 (39 minutes including its canary) the
three secondaries rolled one after another: Europe 27.6, US East 40.1, US West
27.6 minutes, 95 in all. They now roll in two waves: **Europe and US East
together, then US West alone**, about 68 minutes, saving about 27 minutes per
gateway hold. The measurements behind the cross-repo work are in quill-router
`docs/design/deploy-fifo-admission.md`.

## Capacity check (read-only, 2026-11-13)

**Fleet.** Every region is a regional MIG of 2 `c3-standard-4` (4 vCPU) Intel
TDX VMs, not autoscaled, `maxSurge 3`, `maxUnavailable 0`: 8 VMs, 32 vCPU.
Zones: us-central1 has both VMs in us-central1-b (zone c has no capacity and f
no TDX), europe-west4 a and c, us-west1 a and b, us-east4 a.

**DNS.** `api.trustedrouter.com` is a plain multi-value A record, TTL 60, of
every attested VM not drained (no GEO policy; `QUILL_CANONICAL_GEO` is unset),
so each serving VM gets roughly an equal share of canonical traffic. A drained
region leaves that answer; its regional hostname keeps resolving to its own
VMs, which keep serving through the surge-first replacement.

**Load.** Cloud Monitoring, last 14 days, 5-minute means, summed per region and
across the fleet (rollout boot spikes included, so this overstates steady load):

| | p50 | p99 | max |
|---|---|---|---|
| Fleet CPU (vCPU, mean per bucket) | 0.21 | 1.71 | 3.29 |
| Fleet CPU (vCPU, max per bucket) | 0.28 | 2.94 | 4.19 |
| Fleet network in (Mbit/s) | 0.80 | 5.6 | 69 |
| Fleet network out (Mbit/s) | 1.77 | 6.2 | 25 |
| Per region CPU p99 (vCPU) | eu 0.50, us-central1 0.59, us-east4 0.72, us-west1 0.54 | | |

**What serves canonical traffic during the secondary phase:**

| Plan | Serving canonical | vCPU | Fleet max load on it | Zones |
|---|---|---|---|---|
| Serial (before) | 3 regions, 6 VMs | 24 | 17% | 4 or 5 |
| Two at a time (this change) | us-central1 + us-west1, 4 VMs | 16 | 26% | 3 (us-central1-b, us-west1-a, us-west1-b) |
| All three at once | us-central1, 2 VMs | 8 | 52% | 1 (us-central1-b) |

CPU and network allow all three at once. Redundancy does not: with all three
drained, canonical traffic would rest on two VMs in a single zone for about 40
minutes of every rollout, and one zonal event or one bad VM pair would take
`api.trustedrouter.com` down with nothing to fail over to. Today's minimum is
three regions. Two at a time keeps two regions and three zones serving, so this
change uses waves of two. Europe pairs with US East because US East is the
slowest (40 minutes) and US West, the region that may still be bootstrapping,
must roll last and alone so a first-time region cannot hold up the others.

Not measured: memory (no agent metric), concurrent in-flight streams per VM
(the enclave's client to the control plane allows 256 connections per host),
and provider-side per-region limits. Load concentration in a wave is 1.5 times
today's (4 serving VMs instead of 6).

## What stays as strict, and what changes

Each region in a wave runs `tools/roll-secondary-region.sh` with every gate it
had: drain and wait one TTL, deploy, MIG stable, attested, per-instance verify
before DNS, synthetic wait for that region, the per-region three-minute
watchdog (`--regions <region>`), and its own automatic recovery to the
previous template and drain state. Every gate reads only its own region, so
each verdict is attributable; each worker writes its own log, tailed with a
`[region]` prefix, and the wave prints one verdict per region (promoted;
stopped by a peer; deadline passed; or its own failure).

The script does change in a wave (run alone, it behaves as before):

- **One DNS lock** for the wave, shared by the regions and their recoveries
  (`recover-gcp-region.sh` takes it too). The persistent drain is a
  read-modify-write of one TXT record with no compare-and-swap, so two regions
  updating it at once could lose each other's drain.
- **An abort file.** The first region to fail records itself, under that lock,
  before its recovery. Every other region checks it between steps, every MIG
  wait round, every second of its long read-only waits (which are stopped at
  once), and under the same lock immediately before re-entering canonical DNS.
  A region that has not promoted stops, restores its previous template and
  drain state, and reports "stopped by a peer"; a region not yet started is
  left untouched; a region that already promoted keeps the release.
- **This is not the serial end state.** Serially, a failure left later
  regions untouched. In a wave, a peer that was still rolling is rolled back
  even if it was healthy: if US East fails before Europe promotes, Europe is
  restored too. The fleet still never serves an image that failed a gate.
- **A forward-only deadline.** `TR_SECONDARY_WORKER_TIMEOUT` (55 minutes)
  stops a region's rollout steps (exit 76) and starts its recovery. Recovery
  is never bounded by it: once recovery starts it ignores TERM, INT and
  SIGPIPE, so a wave TERM, a group signal or a dead log reader cannot cut it
  short. The wave step allows 100 minutes so recovery (up to 40 minutes of MIG
  wait) can finish, which the old 55-minute per-region step could not.
- **Cancels.** A TERM to the wave alone is forwarded to every worker, and the
  wave waits for their recoveries. A GitHub cancel or step timeout kills the
  whole tree within seconds, so a region can be left mid-rollout, possibly on
  the new template. Each region records `started`, then `promoted`,
  `recovered` or `recovery-failed`, and the drain finalizer
  (`cleanup-enclave-rollout-drains.sh`) refuses to re-add a region this run
  left at `started` or `recovery-failed`; it stays drained for an operator.
- **AWS session.** Credentials are refreshed before each wave (one hour). A
  recovery that outlives them can no longer fail on its final backup-domain
  sync: that sync is now tolerant, which leaves the backup names still
  excluding the region (synced when it was drained) until the next sync. The
  GCP drain state is restored either way.

Stage D flags stay per region: the wave step carries
`<REGION_KEY>_QUILL_USAGE_HEARTBEAT` and `<REGION_KEY>_QUILL_TERMINATE_AT_CAP`,
the runner refuses a wave-wide flag and hands each worker only its own pair,
and `tools/tests/test-stage-d-gates.sh` holds the keyed flags to the same
region bijection, matching each key to that step's own `<KEY>_PREV_TEMPLATE`.

## Not verified

No production run has used a wave. The tests run the real wave runner and
workers with real advisory locking, real deadlines and real signals, with
every cloud call stubbed (recovery is a slow stub that must run to the end).
A runner SIGKILL during a cancel still cannot be survived; the finalizer only
keeps such a region out of canonical DNS.
