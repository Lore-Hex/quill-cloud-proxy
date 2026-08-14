#!/usr/bin/env bash
# Roll one secondary attested gateway region while it is drained from canonical
# traffic. The workflow refreshes its short-lived Route53 credentials before
# each invocation so a long multi-region deploy cannot outlive one AWS session.
set -euo pipefail

if [ "$#" -ne 8 ]; then
  echo "usage: $0 <region> <mig> <instance-filter> <short-name> <api-hosts> <previous-template> <machine-type> <confidential-type>" >&2
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

: "${IMAGE_REF:?IMAGE_REF is required}"
: "${IMAGE_DIGEST:?IMAGE_DIGEST is required}"

lock_dir="$(mktemp -d "${TMPDIR:-/tmp}/tr-secondary-rollout-XXXXXX")"
trap 'rm -rf "${lock_dir}"' EXIT

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
  local lock="${lock_dir}/dns-reconcile.lock"
  (
    flock 9
    QUILL_API_HOST=api.trustedrouter.com \
    QUILL_DNS_ZONE=trustedrouter-com \
      uv run --script tools/reconcile-enclave-dns.py \
        "--${operation}-drain-region" "${target_region}"
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
  for i in $(seq 1 90); do
    if gcloud compute instance-groups managed wait-until "${target_mig}" \
      --region="${target_region}" --project=quill-cloud-proxy \
      --stable --timeout=10; then
      reconcile_dns
      return 0
    fi
    echo "${target_region} still rolling; refreshing attested DNS membership (${i}/90)"
    reconcile_dns || true
    sleep 5
  done
  echo "${target_region} MIG did not stabilize before timeout" >&2
  return 1
}

rollback_region() {
  local target_region="$1"
  local target_mig="$2"
  local prior_template="$3"
  if [ -z "${prior_template}" ]; then
    echo "no prior ${target_region} template recorded; cannot rollback" >&2
    return 1
  fi
  echo "${target_region} canary failed; pointing MIG back at ${prior_template}" >&2
  gcloud compute instance-groups managed set-instance-template "${target_mig}" \
    --region="${target_region}" --project=quill-cloud-proxy \
    --template="${prior_template}" --quiet
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
rollout_step update_drain set "${region}"
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
    rollback_region "${region}" "${mig}" "${previous_template}"
    exit 1
  fi
elif [ -z "${previous_template}" ]; then
  echo "${region}: first deployment has no synthetic target yet; direct per-instance attestation + PONG is the bootstrap gate"
else
  echo "${region}: existing region is missing from synthetic status; failing closed" >&2
  rollback_region "${region}" "${mig}" "${previous_template}"
  exit 1
fi

echo "re-adding ${region} to canonical API DNS"
rollout_step update_drain clear "${region}"
rollout_step reconcile_dns
echo "${region} rollout healthy"
echo "::endgroup::"
