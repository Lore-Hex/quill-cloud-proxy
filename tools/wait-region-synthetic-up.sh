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
# Parse matches tools/watchdog.py fetch_per_region exactly: worst
# effective_status across data.current.checks whose target_region matches.
#
# Usage: wait-region-synthetic-up.sh <gcp-region> [label]
set -uo pipefail

REGION="${1:?usage: wait-region-synthetic-up.sh <gcp-region> [label]}"
LABEL="${2:-$REGION}"
URL="${STATUS_URL:-https://trustedrouter.com/status.json}"
ROUNDS="${WAIT_UP_ROUNDS:-20}"   # 20 * 30s = 10 min ceiling
SLEEP="${WAIT_UP_SLEEP:-30}"

for i in $(seq 1 "$ROUNDS"); do
  st=$(curl -sS --max-time 10 "$URL" 2>/dev/null | REGION="$REGION" python3 -c "
import json, os, sys
region = os.environ['REGION']
sev = {'up': 0, 'degraded': 1, 'down': 2}
try:
    checks = json.load(sys.stdin).get('data', {}).get('current', {}).get('checks', []) or []
except Exception:
    print('unknown'); sys.exit()
worst = -1
for c in checks:
    if (c or {}).get('target_region') != region:
        continue
    s = ((c or {}).get('effective_status') or (c or {}).get('status') or '').lower()
    if s in sev and sev[s] > worst:
        worst = sev[s]
print({0: 'up', 1: 'degraded', 2: 'down'}.get(worst, 'unknown'))
")
  echo "${LABEL}: synthetic status = ${st} (round ${i})"
  [ "$st" = "up" ] && exit 0
  sleep "$SLEEP"
done

echo "${LABEL}: synthetic never reported 'up' within ceiling" >&2
exit 1
