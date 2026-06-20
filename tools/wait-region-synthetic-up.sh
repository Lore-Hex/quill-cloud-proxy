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
  st=$(curl -sS --max-time 10 "$URL" 2>/dev/null | REGION="$REGION" ELAPSED="$SECONDS" python3 -c "
import json, os, sys
region = os.environ['REGION']
# Gate runtime so far. A synthetic check whose age_seconds < elapsed was
# probed AFTER this gate started (i.e. after the roll). 'up' only counts on
# such a fresh post-start probe; a stale pre-roll 'up' (age >= elapsed) does
# not release the canary, which would otherwise race the post-roll dip
# (codex 2026-06-20). The synthetic cadence (~3-4 min) means the gate self-
# waits roughly that long for the first qualifying probe, which is fine.
elapsed = float(os.environ.get('ELAPSED', '0'))
sev = {'up': 0, 'degraded': 1, 'down': 2}
try:
    checks = json.load(sys.stdin).get('data', {}).get('current', {}).get('checks', []) or []
except Exception:
    print('unknown'); sys.exit()
worst = -1
min_age = None
for c in checks:
    if (c or {}).get('target_region') != region:
        continue
    s = ((c or {}).get('effective_status') or (c or {}).get('status') or '').lower()
    if s in sev and sev[s] > worst:
        worst = sev[s]
    a = (c or {}).get('age_seconds')
    if isinstance(a, (int, float)) and (min_age is None or a < min_age):
        min_age = a
status = {0: 'up', 1: 'degraded', 2: 'down'}.get(worst, 'unknown')
if status == 'up' and (min_age is None or min_age >= elapsed):
    status = 'stale-up'
print(status)
")
  echo "${LABEL}: synthetic status = ${st} (round ${i}, elapsed ${SECONDS}s)"
  [ "$st" = "up" ] && exit 0
  sleep "$SLEEP"
done

echo "${LABEL}: synthetic never reported 'up' within ceiling" >&2
exit 1
