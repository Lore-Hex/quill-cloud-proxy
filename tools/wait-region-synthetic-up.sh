#!/usr/bin/env bash
# Wait until the synthetic monitor (status.json — the SAME signal the canary
# reads via tools/watchdog.py) reports <gcp-region> as "up".
#
# Why this exists: the post-stable canary starts immediately after the DNS
# reconcile, but the synthetic monitor probes each region's endpoints
# (api-<region>.quillrouter.com: tls_health, *_pong, attestation) on its own
# cadence and status.json lags. Right after a rolling-replace the region's
# regional endpoint is briefly unreachable (old instances draining, new ones
# not yet in the regional A record), so the synthetic still reads the
# boot-window "down" and the 3-min/rollback-after-2 canary trips a region
# that is actually healthy (observed europe-west4 three times, 2026-06-20:
# attestation 200 + real inference PONG, yet status.json said down).
#
# Gating on the synthetic's OWN reading — not /attestation — makes the canary
# measure true steady state. If the region never comes up (a real failure),
# this fails closed after the ceiling, which is a clean abort, not a false
# rollback of a good release.
#
# Require a complete probe set from both monitor regions created after this
# gate starts. This prevents stale peer failures from poisoning a healthy
# rollout and prevents one fast TLS check from releasing the gate before the
# inference and attestation probes finish.
#
# Usage: wait-region-synthetic-up.sh <gcp-region> [label]
set -uo pipefail

REGION="${1:?usage: wait-region-synthetic-up.sh <gcp-region> [label]}"
LABEL="${2:-$REGION}"
URL="${STATUS_URL:-https://trustedrouter.com/status.json}"
ROUNDS="${WAIT_UP_ROUNDS:-20}"   # 20 * 30s = 10 min ceiling
SLEEP="${WAIT_UP_SLEEP:-30}"
STARTED_AT="${WAIT_UP_STARTED_AT:-$(date -u +%s)}"
MONITOR_REGIONS="${WAIT_UP_MONITOR_REGIONS:-us-central1,europe-west4}"

for i in $(seq 1 "$ROUNDS"); do
  st=$(curl -sS --max-time 10 "$URL" 2>/dev/null | \
    python3 tools/synthetic_gate_status.py \
      "$REGION" "$STARTED_AT" "$MONITOR_REGIONS")
  echo "${LABEL}: synthetic status = ${st} (round ${i}, elapsed ${SECONDS}s)"
  [ "$st" = "up" ] && exit 0
  sleep "$SLEEP"
done

echo "${LABEL}: synthetic never reported 'up' within ceiling" >&2
exit 1
