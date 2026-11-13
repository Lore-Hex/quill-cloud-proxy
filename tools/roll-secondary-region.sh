#!/usr/bin/env bash
# Roll one secondary attested gateway region while it is drained from canonical
# traffic. The workflow refreshes its short-lived Route53 credentials before
# each invocation so a long multi-region deploy cannot outlive one AWS session.
set -euo pipefail

if [ "$#" -ne 10 ]; then
  echo "usage: $0 <region> <mig> <instance-filter> <short-name> <api-hosts> <previous-template> <machine-type> <confidential-type> <active|drained> <none|operator|rollout:run-id>" >&2
  exit 2
fi

region="$1"
mig="$2"
instance_filter="$3"
region_short="$4"
api_hosts="$5"
previous_template="$6"
machine_type="$7"
confidential_type="$8"
prior_drain_state="$9"
prior_drain_origin="${10}"

# shellcheck source=tools/enclave-rollout-drain-lib.sh
source tools/enclave-rollout-drain-lib.sh
restore_drain_operation="$(rollout_restore_drain_operation \
  "${region}" "${prior_drain_state}" "${prior_drain_origin}")" || exit $?

: "${IMAGE_REF:?IMAGE_REF is required}"
: "${IMAGE_DIGEST:?IMAGE_DIGEST is required}"
: "${GITHUB_RUN_ID:?GITHUB_RUN_ID is required}"
source "$(dirname "${BASH_SOURCE[0]}")/cloud-rollout-guard.sh"
require_cloud_rollout gcp

# Run alone, this script owns a private lock directory. Run by
# tools/roll-secondary-wave.sh, every region in the wave shares one directory:
# its lock serializes the persistent-drain read-modify-write and DNS
# reconciles across regions (and their recoveries), and its abort file tells
# every peer that one region failed, so none of them promotes afterwards.
wave_dir="${TR_SECONDARY_WAVE_DIR:-}"
if [ -n "${wave_dir}" ]; then
  if [ ! -d "${wave_dir}" ]; then
    echo "${region}: TR_SECONDARY_WAVE_DIR ${wave_dir} is not a directory" >&2
    exit 2
  fi
  lock_dir="${wave_dir}"
  owns_lock_dir=0
else
  lock_dir="$(mktemp -d "${TMPDIR:-/tmp}/tr-secondary-rollout-XXXXXX")"
  owns_lock_dir=1
fi
abort_file="${lock_dir}/abort"
# Exit status reserved for "stopped because a peer region failed".
peer_abort_status=75
# Exit status for "this region's own deadline passed before promotion".
deadline_status=76
# Forward-only deadline (epoch seconds) for the rollout itself, set by the
# wave. It stops rollout steps; it never bounds the recovery that follows.
deadline="${TR_SECONDARY_DEADLINE:-}"
if [ -n "${deadline}" ] && ! [[ "${deadline}" =~ ^[0-9]+$ ]]; then
  echo "${region}: TR_SECONDARY_DEADLINE must be epoch seconds" >&2
  exit 2
fi
# Where the rollout job's drain finalizer learns how this region ended:
# started -> promoted | recovered | recovery-failed. A region left at
# "started" (killed mid-rollout) is never re-added by the finalizer.
state_dir="${TR_ROLLOUT_STATE_DIR:-}"
drain_started=0
rollout_complete=0
promoted=0

record_state() {
  [ -n "${state_dir}" ] || return 0
  mkdir -p "${state_dir}" && printf '%s\n' "$1" > "${state_dir}/${region}"
}
echo "${region}: pre-rollout canonical drain state is ${prior_drain_state}"

# Record the first failing region in the wave. Peers check it before every
# further step and, under the DNS lock, before promotion.
signal_abort() {
  [ -n "${wave_dir}" ] || return 0
  (
    flock 9
    if [ ! -s "${abort_file}" ]; then
      printf '%s\n' "${region}" > "${abort_file}"
    fi
  ) 9>"${lock_dir}/dns-reconcile.lock"
}

peer_failed() {
  [ -n "${wave_dir}" ] && [ -s "${abort_file}" ] && [ "$(cat "${abort_file}")" != "${region}" ]
}

check_not_aborted() {
  # Once this region is back in canonical DNS a later peer failure cannot
  # undo it, exactly as a later region's failure could not in the serial run.
  [ "${promoted}" -eq 1 ] && return 0
  if peer_failed; then
    echo "${region}: stopping before promotion because $(cat "${abort_file}") failed in this wave" >&2
    exit "${peer_abort_status}"
  fi
  if [ -n "${deadline}" ] && [ "$(date +%s)" -ge "${deadline}" ]; then
    echo "${region}: rollout deadline passed before promotion; stopping" >&2
    exit "${deadline_status}"
  fi
}

# Run a long, read-only wait in its own process group and stop it as soon as
# a peer fails or the deadline passes, instead of at the next step boundary.
interruptible() {
  local pid status
  set -m
  "$@" &
  pid=$!
  set +m
  while kill -0 "${pid}" 2>/dev/null; do
    if [ "${promoted}" -eq 0 ] && { peer_failed || { [ -n "${deadline}" ] && [ "$(date +%s)" -ge "${deadline}" ]; }; }; then
      kill -TERM -- "-${pid}" 2>/dev/null || kill -TERM "${pid}" 2>/dev/null || true
      wait "${pid}" 2>/dev/null || true
      check_not_aborted
    fi
    sleep 1
  done
  status=0
  wait "${pid}" || status=$?
  return "${status}"
}

on_exit() {
  local status="$?"
  trap - EXIT
  # Recovery must finish once started: no TERM/INT (a wave's forward, a peer)
  # and no SIGPIPE (a dead log reader) may cut it short. Children inherit the
  # ignored dispositions. A runner's SIGKILL still can; see the finalizer.
  trap '' TERM INT PIPE
  local aborted_by_peer=0
  if [ "${status}" -eq "${peer_abort_status}" ] && peer_failed; then
    aborted_by_peer=1
  fi
  if [ "${status}" -ne 0 ] && [ "${aborted_by_peer}" -ne 1 ]; then
    signal_abort || echo "${region}: could not record the wave abort" >&2
  fi
  if [ "${status}" -ne 0 ] && [ "${drain_started}" -eq 1 ] && [ "${rollout_complete}" -ne 1 ]; then
    if [ "${aborted_by_peer}" -eq 1 ]; then
      echo "${region}: not promoted; restoring and verifying the previous template" >&2
    else
      echo "${region}: rollout failed; restoring and verifying the previous template" >&2
    fi
    if bash tools/recover-gcp-region.sh \
      "${region}" "${mig}" "${instance_filter}" "${api_hosts}" \
      "${previous_template}" "${prior_drain_state}" \
      "${prior_drain_origin}"; then
      record_state recovered
    else
      record_state recovery-failed
      echo "${region}: automatic recovery failed; region remains drained" >&2
    fi
  fi
  if [ "${owns_lock_dir}" -eq 1 ]; then
    rm -rf "${lock_dir}"
  fi
  exit "${status}"
}
trap on_exit EXIT
# Ignore further signals before exiting, not only inside on_exit: a group
# TERM followed at once by the wave's forwarded TERM must not land in on_exit
# before its own ignore and skip the recovery.
trap "trap '' TERM INT PIPE; exit 130" INT
trap "trap '' TERM INT PIPE; exit 143" TERM

reconcile_dns() {
  local lock="${lock_dir}/dns-reconcile.lock"
  (
    flock 9
    QUILL_RECONCILE_APPLY=1 \
    QUILL_API_HOST=api.trustedrouter.com \
    QUILL_DNS_ZONE=trustedrouter-com \
    QUILL_PUBLISH_REGIONAL=1 \
    QUILL_REGIONAL_ZONE=quillrouter-com \
    QUILL_REGIONAL_SUFFIX=quillrouter.com \
    QUILL_ALLOW_DRAINED_REGIONAL_PROMOTION_REGIONS="${QUILL_ALLOW_DRAINED_REGIONAL_PROMOTION_REGIONS:-}" \
      uv run --script tools/reconcile-enclave-dns.py --apply
    python3 tools/sync-route53-api-aliases.py --apply
  ) 9>"${lock}"
}

update_drain() {
  local operation="$1"
  local target_region="$2"
  local origin="${3:-rollout}"
  local lock="${lock_dir}/dns-reconcile.lock"
  local -a drain_args
  (
    flock 9
    # Every end-of-rollout drain change (re-adding the region, or restoring
    # an operator drain) is a promotion decision: refuse it, under the same
    # lock a failing peer takes to record its failure, once any peer failed.
    if ! { [ "${operation}" = "set" ] && [ "${origin}" = "rollout" ]; } && peer_failed; then
      exit "${peer_abort_status}"
    fi
    if [ "${operation}" = "set" ]; then
      drain_args=(--set-drain-region "${target_region}" --drain-origin "${origin}")
      if [ "${origin}" = "rollout" ]; then
        drain_args+=(--github-run-id "${GITHUB_RUN_ID}")
      fi
    else
      drain_args=(--clear-drain-region "${target_region}")
    fi
    QUILL_API_HOST=api.trustedrouter.com \
    QUILL_DNS_ZONE=trustedrouter-com \
      uv run --script tools/reconcile-enclave-dns.py "${drain_args[@]}"
  ) 9>"${lock}"
}

trigger_synthetic_workers() {
  # Trigger both active monitors so the gate does not wait for a stale peer row.
  gcloud scheduler jobs run trusted-router-synthetic-us-central1-every-three-minutes \
    --location=us-central1 --project=quill-cloud-proxy || true
  gcloud scheduler jobs run trusted-router-synthetic-europe-west4-every-three-minutes \
    --location=europe-west4 --project=quill-cloud-proxy || true
}

wait_region_stable_with_dns_refresh() {
  local target_mig="$1"
  local target_region="$2"
  # A size-two MIG can hold each replacement for the full 600s minReady
  # window. Ninety rounds expired seconds before the second replacement
  # became stable in production; 120 leaves bounded provisioning headroom
  # while remaining below the workflow step's 55-minute timeout.
  local wait_rounds=120
  for i in $(seq 1 "${wait_rounds}"); do
    # The longest wait in a rollout (about 25 minutes): a peer's failure or
    # this region's deadline ends it within one round.
    check_not_aborted
    if gcloud compute instance-groups managed wait-until "${target_mig}" \
      --region="${target_region}" --project=quill-cloud-proxy \
      --stable --timeout=10; then
      reconcile_dns
      return 0
    fi
    echo "${target_region} still rolling; refreshing attested DNS membership (${i}/${wait_rounds})"
    reconcile_dns || true
    sleep 5
  done
  echo "${target_region} MIG did not stabilize before timeout" >&2
  return 1
}

rollout_step() {
  local step_status=0
  "$@" || {
    step_status=$?
    if [ "${step_status}" -eq "${peer_abort_status}" ] && peer_failed; then
      check_not_aborted
    fi
    if [ "${step_status}" -eq "${deadline_status}" ]; then
      check_not_aborted
    fi
    echo "${region} rollout step failed (${step_status}): $*" >&2
    exit "${step_status}"
  }
  # A drain change decides under the DNS lock itself; checking again after a
  # promotion succeeded would roll back a region that is already serving.
  case "$1" in
    update_drain) ;;
    *) check_not_aborted ;;
  esac
}

export API_HOST="${api_hosts}"
export REGION_SHORT="${region_short}"
export MACHINE_TYPE="${machine_type}"
export CONF_COMPUTE_TYPE="${confidential_type}"

echo "::group::secondary rollout ${region}"
# A region whose peer already failed is never touched.
check_not_aborted
echo "draining ${region} from canonical API DNS"
record_state started
drain_started=1
rollout_step update_drain set "${region}" rollout
rollout_step reconcile_dns
rollout_step interruptible bash tools/wait-canonical-drained.sh "${region}"
rollout_step bash tools/deploy-gcp-mig.sh "${region}"
rollout_step wait_region_stable_with_dns_refresh "${mig}" "${region}"
rollout_step interruptible bash tools/wait-region-attested.sh "${instance_filter}" "${region}"
rollout_step bash tools/verify-region-before-dns.sh \
  "${region}" "${instance_filter}" "${IMAGE_DIGEST}"

# A first-time region still has a cold CNAME. Only this post-canary reconcile
# may promote it to a region-only A record while canonical traffic stays drained.
QUILL_ALLOW_DRAINED_REGIONAL_PROMOTION_REGIONS="${region}" \
  rollout_step reconcile_dns

if curl -fsS --max-time 15 https://trustedrouter.com/status.json | \
    jq -e --arg region "${region}" \
      '[.. | objects | select(.target_region? == $region)] | length > 0' \
      >/dev/null; then
  trigger_synthetic_workers
  WAIT_UP_SLEEP=10 WAIT_UP_ROUNDS=72 \
    rollout_step interruptible bash tools/wait-region-synthetic-up.sh "${region}" "${region}"
  if ! interruptible python3 tools/watchdog.py \
      --regions "${region}" \
      --duration-min 3 \
      --rollback-after 3 \
      --skip-baseline \
      --initial-grace-sec 120; then
    exit 1
  fi
  check_not_aborted
elif [ -z "${previous_template}" ]; then
  echo "${region}: first deployment has no synthetic target yet; direct per-instance attestation + PONG is the bootstrap gate"
else
  echo "${region}: existing region is missing from synthetic status; failing closed" >&2
  exit 1
fi

if [ "${restore_drain_operation}" = "set" ]; then
  echo "restoring operator drain for ${region}"
  rollout_step update_drain set "${region}" operator
else
  echo "re-adding ${region} to canonical API DNS"
  rollout_step update_drain clear "${region}"
fi
promoted=1
rollout_step reconcile_dns
rollout_complete=1
record_state promoted
echo "${region} rollout healthy"
echo "::endgroup::"
