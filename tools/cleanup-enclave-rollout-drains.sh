#!/usr/bin/env bash
# Clear healthy rollout-created drains at the end of every enclave rollout job.
set -uo pipefail

project="${QUILL_GCP_PROJECT_ID:-quill-cloud-proxy}"
current_run_id="${GITHUB_RUN_ID:?GITHUB_RUN_ID is required}"
cleanup_failed=0

region_mig() {
  case "$1" in
    us-central1) printf '%s\t%s\n' quill-enclave-mig-us quill-enclave-mig-us- ;;
    europe-west4) printf '%s\t%s\n' quill-enclave-mig-eu quill-enclave-mig-eu- ;;
    us-east4) printf '%s\t%s\n' quill-enclave-mig-useast4 quill-enclave-mig-useast4- ;;
    southamerica-east1) printf '%s\t%s\n' quill-enclave-mig-sa quill-enclave-mig-sa- ;;
    *) return 1 ;;
  esac
}

list_drains() {
  QUILL_API_HOST="${QUILL_API_HOST:-api.trustedrouter.com}" \
  QUILL_DNS_ZONE="${QUILL_DNS_ZONE:-trustedrouter-com}" \
    uv run --script tools/reconcile-enclave-dns.py --list-drain-regions
}

clear_drain() {
  local region="$1"
  QUILL_API_HOST="${QUILL_API_HOST:-api.trustedrouter.com}" \
  QUILL_DNS_ZONE="${QUILL_DNS_ZONE:-trustedrouter-com}" \
    uv run --script tools/reconcile-enclave-dns.py \
      --clear-drain-region "${region}"
}

report_uncleared() {
  local region="$1"
  local origin="$2"
  echo "::error::${region} remains drained (origin ${origin}): clear with \`uv run --script tools/reconcile-enclave-dns.py --clear-drain-region ${region}\` followed by \`uv run --script tools/reconcile-enclave-dns.py --apply\`"
  cleanup_failed=1
}

if ! drains="$(list_drains)"; then
  echo "::error::could not read persistent enclave drain state"
  exit 1
fi

while IFS=$'\t' read -r region origin extra; do
  [ -z "${region}" ] && continue
  if [ -n "${extra}" ] || ! [[ "${region}" =~ ^[a-z][a-z0-9-]{1,62}$ ]] || \
      ! [[ "${origin}" =~ ^(operator|rollout:[1-9][0-9]*)$ ]]; then
    echo "::error::invalid persistent drain-list entry '${region}' '${origin}'"
    cleanup_failed=1
    continue
  fi
  [[ "${origin}" == rollout:* ]] || continue

  if ! mapping="$(region_mig "${region}")"; then
    report_uncleared "${region}" "${origin}"
    continue
  fi
  IFS=$'\t' read -r mig instance_filter <<<"${mapping}"

  if ! gcloud compute instance-groups managed wait-until "${mig}" \
      --region="${region}" --project="${project}" --stable \
      --timeout="${ROLLOUT_DRAIN_STABLE_TIMEOUT:-30}"; then
    report_uncleared "${region}" "${origin}"
    continue
  fi
  if ! WAIT_ATTEST_ROUNDS="${ROLLOUT_DRAIN_ATTEST_ROUNDS:-1}" \
      WAIT_ATTEST_SLEEP="${ROLLOUT_DRAIN_ATTEST_SLEEP:-0}" \
      bash tools/wait-region-attested.sh "${instance_filter}" \
        "${region} rollout-drain cleanup"; then
    report_uncleared "${region}" "${origin}"
    continue
  fi

  if [ "${origin}" != "rollout:${current_run_id}" ]; then
    echo "::warning::clearing stale ${origin} drain for healthy ${region}"
  fi
  if ! clear_drain "${region}"; then
    report_uncleared "${region}" "${origin}"
  fi
done <<<"${drains}"

# Reconcile even when no rollout drain was clearable: this makes the finalizer
# a last fail-closed check that persisted drain state and canonical DNS agree.
if ! QUILL_RECONCILE_APPLY=1 \
    QUILL_API_HOST="${QUILL_API_HOST:-api.trustedrouter.com}" \
    QUILL_DNS_ZONE="${QUILL_DNS_ZONE:-trustedrouter-com}" \
    QUILL_PUBLISH_REGIONAL=1 \
    QUILL_REGIONAL_ZONE="${QUILL_REGIONAL_ZONE:-quillrouter-com}" \
    QUILL_REGIONAL_SUFFIX="${QUILL_REGIONAL_SUFFIX:-quillrouter.com}" \
      uv run --script tools/reconcile-enclave-dns.py --apply; then
  echo "::error::failed to apply canonical DNS after rollout-drain cleanup"
  cleanup_failed=1
fi

exit "${cleanup_failed}"
