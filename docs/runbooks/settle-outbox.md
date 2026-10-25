# Settle outbox (enclave side)

The enclave parks a settle or refund it could not deliver as a GCS object
under `trustedrouter-settle-outbox/v1/pending/` (quill-router
`docs/design/durable-settle-outbox.md` §9.2; code
`enclave-go/internal/settleoutbox`). A sweeper in a sibling enclave replays
them. Infra: `infra/gcp/settle-outbox/main.tf`.

## Flags

- `QUILL_SETTLE_OUTBOX_BUCKET=<bucket>`: the store. Enclaves park; nothing
  replays.
- `QUILL_SETTLE_OUTBOX_SWEEP=on`: the sweeper, in addition to the bucket.

**Hard rule: never set `QUILL_SETTLE_OUTBOX_SWEEP=on` before quill-router's
R3 (X-TR-Boot-Auth verified on `/internal/gateway/settle` and `/refund` when
present) is deployed on the plane the sweeper replays to.** Until then the
router accepts any shaped header under the sweeper's own internal token, so
an object created by any pool-admitted workload would settle as trusted. The
sweeper refuses unsigned objects itself; only the router can refuse a forged
signature. R3 is quill-router PR #2048 (`e4/r3-terminal-boot-auth`): its
refusal is HTTP 401, `error.type` `unauthorized`, `error.reason`
`boot_not_accepted` (`settleoutbox.BootAuthRefusedReason`); confirm the
deployed router answers that before enabling.

## Enabling

The store is on for the GCP fleet: `tools/deploy-gcp-mig.sh` defaults
`QUILL_SETTLE_OUTBOX_BUCKET` to `quill-cloud-proxy-settle-outbox` (the
`bucket_name` default in `infra/gcp/settle-outbox/main.tf`) and puts
`tee-env-QUILL_SETTLE_OUTBOX_BUCKET=<bucket>` on every instance template
(PR #599). Order of operations, which that PR did not change:

1. Apply `infra/gcp/settle-outbox` (bucket, `objectCreator` for the pool,
   the sweeper role, the alert) before a template carries the entry. An
   enclave that parks into a bucket it cannot write to logs
   `settle_outbox.write_failed` and then `settle_outbox.lost`, while its
   boot registration already declared `capabilities.settle_outbox=true`.
2. Merging the PR rolls the fleet. Evidence per boot in
   `tools/dx/enclave-logs.sh`: `enclave.settle_outbox_started
   bucket="quill-cloud-proxy-settle-outbox" boot_signed=true`.
   `capabilities.settle_outbox=true` is a field of the boot registration the
   enclave sends to the control plane; read it there. It is not a line that
   `enclave-logs.sh` prints.
3. Confidential Space refuses a template that supplies a tee-env name the
   image's `tee.launch_policy.allow_env_override` label does not list. So do
   not pin a pre-label image (for example `gcp-release-72be94e6`) while the
   bucket tee-env is set: the launch would be refused. To roll back to an
   image older than the label that admits the variable, export
   `QUILL_SETTLE_OUTBOX_BUCKET=` (empty); the script then leaves the entry
   out.

The deploy script never sets `QUILL_SETTLE_OUTBOX_SWEEP`; a test pins that.
The sweeper is a separate step, in this order:

1. A serving image whose label carries `QUILL_SETTLE_OUTBOX_SWEEP`
   (`Dockerfile.enclave.gcp.multi` and `Dockerfile.enclave.gcp.anthropic`):
   a release built after the label PR. Earlier images do not have it.
2. Router R3 deployed on the plane the sweeper replays to (hard rule above).
3. Only then the tee-env `QUILL_SETTLE_OUTBOX_SWEEP=on` on the instance
   templates. The tee-env alone is not enough.

## What to expect in the logs while the sweeper is off

With no bucket, each boot logs `enclave.settle_outbox_disabled reason=no_bucket`
(or `reason=<error> bucket=<name>` if the store could not be built). With the
bucket set and the sweep unset, each boot logs
`enclave.settle_outbox_sweeper_disabled reason=sweep_off`. Other disabled
reasons are `no_outbox` (sweep set, no bucket) and `no_control_plane`. These
negative lines are the signal that the feature is off; the absence of
`settle_outbox.` counter lines is expected.

## When the alert fires

The alert (`google_monitoring_alert_policy.settle_outbox_attention`) pages on
a sweep counter line with `dead=` or `quarantined=` above zero, or on
`settle_outbox.sweep_sender_refused`. Read the lines with
`tools/dx/enclave-logs.sh` and grep `settle_outbox.`.

- `v1/dead/`: the router refused the authorization (404: never seen or past
  retention; 409: a retired settlement kind). The object holds the exact
  terminal bytes; decide with billing whether a manual charge is due. Never
  auto-deleted.
- `v1/quarantine/`: unsigned or malformed envelope, a `boot_kid` that
  disagrees with the header, or the router refused the boot auth. Do not
  replay it as trusted. Never auto-deleted.
- `settle_outbox.sweep_sender_refused`: the router refused the sweeper's
  internal token (not the object), or answered a 401/403 that is neither
  that nor R3's boot-auth refusal (`type=` and `reason=` in the line say
  which). The sweeper stops the page, releases the lease and pauses for one
  lease (2 min). Fix the token or read the router's answer; the backlog
  stays pending and is replayed afterwards.
- To re-park an object by hand, copy it back under `v1/pending/` with the
  same name. Objects are immutable bytes; never edit one.
