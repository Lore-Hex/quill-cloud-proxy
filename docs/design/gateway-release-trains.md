# Gateway release trains

The full design, with measurements for both repositories, is
quill-router `docs/design/deploy-fifo-admission.md`. This note covers the
quill-cloud-proxy side.

## Why

A gateway rollout holds the shared gcp lease for about 140 minutes (measured
p50, 2026-11-09 to 11-13): us-central1 39 minutes including its canary, then
Europe 28, US East 40 and US West 28, one at a time. Every push to main that
touches the workflow's push paths queued its own rollout, so a burst of N
merges meant N rollouts and N times 140 minutes of lease, during which every
control-plane deploy waits.

## Rule

`deploy-enclave-gcp.yml` gains a `train` job after `gate-on-ci`, with only
`actions: read` and `contents: read`. `tools/superseded_rollout.py decide`
skips this run (green, nothing built, no trust commit, no lease) when either:

- a newer **push** run of the same workflow is queued for a strict descendant
  of this commit that is still on main, and that commit's `ci.yml` run is
  green, so the newer run ships this commit too; or
- a newer run for a descendant still on main has **rolled out** (its `rollout`
  job succeeded, even if a later job failed), so deploying this commit would
  roll the gateway back. A train-skipped run concludes success but never
  counts as rolled out.

Every pass re-reads the run list; all waiting for a successor's CI shares one
30-minute deadline (the job allows 40). Otherwise it proceeds. Manual
dispatches never skip and are never treated as a queued successor. Any failed
read, malformed answer or unexpected error means proceed, which was the
behavior before this change. The decision is taken before
`build-and-release`, because skipping after the transitional trust publish
would advertise a digest that never ran. Each run still builds and attests
exactly its own commit.

## A skipped commit always ships

A skip trusts a run that has not happened yet. If that run then fails at
build, trust publication, the Batch grant, admission or a canary, or is
cancelled, its `rescue-skipped` job (always run on pushes, `actions: write`)
calls `superseded_rollout.py rescue`: when this run did not skip and its
`rollout` job did not succeed, it re-runs the newest older run that skipped in
its favor since the last rollout (an ancestor of this commit still on main),
unless such a run is already queued again. The re-run decides afresh, finds
the failed run is no successor, and deploys its own commit, which contains
every older skipped one. If that also fails, its own rescue continues with
the next older skipped run, stopping at the last rollout. A rescue that cannot
read GitHub fails red, naming the manual step.

## Bot commits

The rollout's "[bot] enclave release" and "[bot] finalize enclave release"
commits, and the publish workflows' "[bot] sign ... trust artifacts" commits,
stage only `trust-page/` paths, which are not push paths of this workflow.
`tools/test_superseded_rollout.py` checks both halves, so a bot commit can never
start another rollout.

## FIFO admission

`tools/cloud-rollout.py` runs quill-router's coordinator at the commit pinned in
`tools/cloud-rollout-source.json`. Gateway admissions join the cross-repository
FIFO queue once that pin moves to a coordinator with the queue; until then
they keep polling as before, which is unfair but not unsafe.
