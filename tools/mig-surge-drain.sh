#!/usr/bin/env bash
# Zero-downtime template roll for a regional enclave MIG, in two explicit
# phases. Replaces `rolling-action replace` for the forward roll.
#
# WHY: `rolling-action replace --max-surge=3 --max-unavailable=0` considers a
# new instance done the moment it is RUNNING (this fleet deliberately has no
# MIG health check — GCP HCs cannot probe a Confidential Space enclave, see
# deploy-gcp-mig.sh), and then deletes the old instances. But a Confidential
# Space workload cannot attest until ~5-8 min after boot, and the DNS
# reconciler (tools/reconcile-enclave-dns.py) only publishes ATTESTED
# instances. Net effect of every deploy: the old instances — the only IPs in
# api-<region>.quillrouter.com — were deleted minutes before their
# replacements could enter DNS, so the regional hostname refused connections
# for the whole attestation window. (The canonical api.trustedrouter.com was
# fine: it is drained to other regions before a region rolls. The
# region-pinned hostname has nothing to fail over to.)
#
# INVARIANT this script maintains: the regional A record always contains the
# baseline number of live, attested IPs, and no instance is deleted while a
# resolver answer that contains ONLY dead IPs can still be cached. Sequence:
#
#   surge         grow the MIG so TARGET_SIZE instances exist on the CURRENT
#                 (new) template, alongside the old fleet. Old instances keep
#                 serving and stay in DNS the whole time.
#   wait-attested block until >= TARGET_SIZE current-template instances serve
#                 GET /attestation 200 (template-aware, unlike
#                 wait-region-attested.sh which gates on every instance —
#                 template-awareness is what makes rollback work even when the
#                 instances being rolled AWAY from are crash-looping).
#   (caller)      reconcile-enclave-dns.py --apply  → publishes old+new IPs,
#                 then sleep >= 2xTTL (QUILL_DNS_SETTLE_SECONDS, default 130s
#                 for the reconciler's 60s TTL) so every answer a resolver may
#                 still be caching at drain time contains the new live IPs.
#   drain         delete exactly the instances NOT on the current template.
#                 delete-instances shrinks targetSize back to baseline. A
#                 client holding a cached answer with a dead IP retries the
#                 remaining A records inside the same connect() call
#                 (standard resolver-list iteration), so this is invisible.
#
# Transient capacity: baseline + TARGET_SIZE new instances (2+2 today) — LESS
# than the old replace surge (2 old + up to 3 new), so no new Confidential VM
# stockout exposure.
#
# Usage: mig-surge-drain.sh <surge|wait-attested|drain> <region> <mig-name>
# Env:   PROJECT_ID    (default quill-cloud-proxy)
#        TARGET_SIZE   baseline fleet size (default 2 — keep in sync with
#                      deploy-gcp-mig.sh)
#        QUILL_ATTEST_HOST   SNI/Host for the attestation probe
#                            (default api.trustedrouter.com)
#        WAIT_ATTEST_ROUNDS / WAIT_ATTEST_SLEEP   wait-attested ceiling
#                            (default 24 x 30s = 12 min, matches
#                            wait-region-attested.sh)
set -euo pipefail

CMD="${1:?usage: mig-surge-drain.sh <surge|wait-attested|drain> <region> <mig-name>}"
REGION="${2:?usage: mig-surge-drain.sh <surge|wait-attested|drain> <region> <mig-name>}"
MIG_NAME="${3:?usage: mig-surge-drain.sh <surge|wait-attested|drain> <region> <mig-name>}"

PROJECT_ID="${PROJECT_ID:-quill-cloud-proxy}"
TARGET_SIZE="${TARGET_SIZE:-2}"
ATTEST_HOST="${QUILL_ATTEST_HOST:-api.trustedrouter.com}"
ROUNDS="${WAIT_ATTEST_ROUNDS:-24}"
SLEEP="${WAIT_ATTEST_SLEEP:-30}"

log() { echo "[$(date +%H:%M:%S)] mig-surge-drain ${CMD} ${REGION}: $*" >&2; }
gc() { gcloud --project "$PROJECT_ID" "$@"; }

current_template() {
  local tmpl
  tmpl=$(gc compute instance-groups managed describe "$MIG_NAME" \
    --region="$REGION" --format='value(instanceTemplate.basename())' 2>/dev/null || true)
  if [ -z "$tmpl" ]; then
    tmpl=$(gc compute instance-groups managed describe "$MIG_NAME" \
      --region="$REGION" --format='value(versions[0].instanceTemplate.basename())' 2>/dev/null || true)
  fi
  [ -n "$tmpl" ] || { log "cannot read current instance template"; exit 1; }
  printf '%s' "$tmpl"
}

# Rows: <name>,<zone>,<template-basename>,<instanceStatus>
# (explicit projections: bare `instance` renders as just the zone scope in
# csv/value output, so the URL is never printed whole — don't rely on it)
list_rows() {
  gc compute instance-groups managed list-instances "$MIG_NAME" --region="$REGION" \
    --format='csv[no-heading](name,instance.scope(zones).segment(0),version.instanceTemplate.basename(),instanceStatus)'
}

case "$CMD" in
  surge)
    TMPL=$(current_template)
    current_size=$(gc compute instance-groups managed describe "$MIG_NAME" \
      --region="$REGION" --format='value(targetSize)')
    [ -n "$current_size" ] || { log "cannot read targetSize"; exit 1; }
    on_current=$(list_rows | awk -F, -v t="$TMPL" '$3==t' | wc -l | tr -d ' ')
    need=$(( TARGET_SIZE - on_current ))
    if [ "$need" -le 0 ]; then
      log "already have ${on_current}/${TARGET_SIZE} instances on template ${TMPL}; surge is a no-op"
      exit 0
    fi
    new_size=$(( current_size + need ))
    log "surging ${current_size} -> ${new_size} (+${need} on template ${TMPL}); old fleet keeps serving"
    gc compute instance-groups managed resize "$MIG_NAME" \
      --region="$REGION" --size="$new_size" >/dev/null
    ;;

  wait-attested)
    TMPL=$(current_template)
    for i in $(seq 1 "$ROUNDS"); do
      ok=0
      while IFS=, read -r name zone tmpl _status; do
        [ "$tmpl" = "$TMPL" ] || continue
        [ -n "$name" ] && [ -n "$zone" ] || continue
        ip=$(gc compute instances describe "$name" --zone="$zone" \
          --format='value(networkInterfaces[0].accessConfigs[0].natIP)' 2>/dev/null || true)
        [ -n "$ip" ] || continue
        code=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 8 \
          --resolve "${ATTEST_HOST}:443:${ip}" \
          "https://${ATTEST_HOST}/attestation?nonce=deadbeef0000" 2>/dev/null || echo 000)
        [ "$code" = "200" ] && ok=$((ok + 1))
      done < <(list_rows)
      if [ "$ok" -ge "$TARGET_SIZE" ]; then
        log "${ok}/${TARGET_SIZE} instances on template ${TMPL} attest healthy (round ${i})"
        exit 0
      fi
      log "waiting: ${ok}/${TARGET_SIZE} current-template instances attested (round ${i}/${ROUNDS})"
      sleep "$SLEEP"
    done
    log "current-template instances did not reach attestation health within ceiling"
    exit 1
    ;;

  drain)
    TMPL=$(current_template)
    keep=0
    cull_names=""
    while IFS=, read -r name _zone tmpl _status; do
      [ -n "$name" ] || continue
      if [ "$tmpl" = "$TMPL" ]; then
        keep=$((keep + 1))
      else
        cull_names="${cull_names:+${cull_names},}${name}"
      fi
    done < <(list_rows)
    # Safety: never drain unless a full baseline fleet exists on the current
    # template. Failing here leaves the old fleet serving — a strictly better
    # failure mode than the old replace (which deleted it first).
    if [ "$keep" -lt "$TARGET_SIZE" ]; then
      log "refusing to drain: only ${keep}/${TARGET_SIZE} instances on template ${TMPL}"
      exit 1
    fi
    if [ -z "$cull_names" ]; then
      log "nothing to drain; all instances already on template ${TMPL}"
      exit 0
    fi
    log "draining old-template instances: ${cull_names}"
    gc compute instance-groups managed delete-instances "$MIG_NAME" \
      --region="$REGION" --instances="$cull_names" >/dev/null
    gc compute instance-groups managed wait-until "$MIG_NAME" \
      --region="$REGION" --stable --timeout=600 >/dev/null
    log "drain complete; fleet is ${keep} instances on ${TMPL}"
    ;;

  *)
    echo "unknown command: $CMD (want surge|wait-attested|drain)" >&2
    exit 1
    ;;
esac
