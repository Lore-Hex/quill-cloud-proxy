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

lock_dir="$(mktemp -d "${TMPDIR:-/tmp}/tr-secondary-rollout-XXXXXX")"
drain_started=0
rollout_complete=0
echo "${region}: pre-rollout canonical drain state is ${prior_drain_state}"

on_exit() {
  local status="$?"
  trap - EXIT
  if [ "${status}" -ne 0 ] && [ "${drain_started}" -eq 1 ] && [ "${rollout_complete}" -ne 1 ]; then
    echo "${region}: rollout failed; restoring and verifying the previous template" >&2
    if ! bash tools/recover-gcp-region.sh \
      "${region}" "${mig}" "${instance_filter}" "${api_hosts}" \
      "${previous_template}" "${prior_drain_state}" \
      "${prior_drain_origin}"; then
      echo "${region}: automatic recovery failed; region remains drained" >&2
    fi
  fi
  rm -rf "${lock_dir}"
  exit "${status}"
}
trap on_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

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
    echo "${region} rollout step failed (${step_status}): $*" >&2
    exit "${step_status}"
  }
}

export API_HOST="${api_hosts}"
export REGION_SHORT="${region_short}"
export MACHINE_TYPE="${machine_type}"
export CONF_COMPUTE_TYPE="${confidential_type}"

echo "::group::secondary rollout ${region}"
echo "draining ${region} from canonical API DNS"
drain_started=1
rollout_step update_drain set "${region}" rollout
rollout_step reconcile_dns
rollout_step bash tools/wait-canonical-drained.sh "${region}"
rollout_step bash tools/deploy-gcp-mig.sh "${region}"
rollout_step wait_region_stable_with_dns_refresh "${mig}" "${region}"
rollout_step bash tools/wait-region-attested.sh "${instance_filter}" "${region}"
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
    rollout_step bash tools/wait-region-synthetic-up.sh "${region}" "${region}"
  if ! python3 tools/watchdog.py \
      --regions "${region}" \
      --duration-min 3 \
      --rollback-after 3 \
      --skip-baseline \
      --initial-grace-sec 120; then
    exit 1
  fi
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
rollout_step reconcile_dns
rollout_complete=1
echo "${region} rollout healthy"
echo "::endgroup::"
