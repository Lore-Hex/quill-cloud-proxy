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
