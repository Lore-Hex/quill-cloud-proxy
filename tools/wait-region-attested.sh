#!/usr/bin/env bash
# Wait until every running instance matching <name-filter> serves
# GET /attestation with HTTP 200.
#
# Why this exists: `gcloud ... wait-until --stable` only proves the MIG's
# rolling-replace finished — the instances are RUNNING. But a Confidential
# Space workload cannot mint its GCA attestation token until ~5-8 min after
# boot, and the enclave-dns-reconciler only publishes attested instances into
# DNS. So between "MIG stable" and "attestation healthy" the synthetic monitor
# reads the freshly-rolled region as DOWN, and the post-stable canary
# (tools/watchdog.py) trips on that boot transient and rolls a perfectly good
# release back (observed 2026-06-20: europe-west4 up->down->down, then healthy
# ~7 min later). Gating the canary on real attestation health makes it measure
# true steady state instead of the boot window.
#
# Usage: wait-region-attested.sh <instance-name-filter> [label]
#   wait-region-attested.sh quill-enclave-mig-us- us-central1
set -uo pipefail

FILTER="${1:?usage: wait-region-attested.sh <instance-name-filter> [label]}"
LABEL="${2:-$FILTER}"
PROJECT="${QUILL_GCP_PROJECT_ID:-quill-cloud-proxy}"
HOST="${QUILL_ATTEST_HOST:-api.trustedrouter.com}"
ROUNDS="${WAIT_ATTEST_ROUNDS:-24}"   # 24 * 30s = 12 min ceiling
SLEEP="${WAIT_ATTEST_SLEEP:-30}"

for i in $(seq 1 "$ROUNDS"); do
  all=1
  any=0
  for ip in $(gcloud compute instances list --project="$PROJECT" \
                --filter="name~${FILTER}" \
                --format='value(networkInterfaces[0].accessConfigs[0].natIP)' 2>/dev/null); do
    [ -z "$ip" ] && continue
    any=1
    code=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 8 \
             --resolve "${HOST}:443:${ip}" \
             "https://${HOST}/attestation?nonce=deadbeef0000" 2>/dev/null || echo 000)
    [ "$code" = "200" ] || all=0
  done
  if [ "$any" = "1" ] && [ "$all" = "1" ]; then
    echo "${LABEL}: all instances serve /attestation 200 (round ${i})"
    exit 0
  fi
  echo "${LABEL}: waiting for attestation health (round ${i}, all=${all} any=${any})..."
  sleep "$SLEEP"
done

echo "${LABEL}: instances did not reach attestation health within ceiling" >&2
exit 1
