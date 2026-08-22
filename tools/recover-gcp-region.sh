#!/usr/bin/env bash
# Restore one drained GCP gateway region to its previously verified template.
set -euo pipefail

if [ "$#" -lt 5 ] || [ "$#" -gt 6 ]; then
  echo "usage: $0 <region> <mig> <instance-filter> <api-hosts> <previous-template> [active|drained]" >&2
  exit 2
fi

region="$1"
mig="$2"
instance_filter="$3"
api_hosts="$4"
previous_template="$5"
final_drain_state="${6-active}"
project="${QUILL_GCP_PROJECT_ID:-quill-cloud-proxy}"
primary_host="${QUILL_API_HOST:-api.trustedrouter.com}"
dns_zone="${QUILL_DNS_ZONE:-trustedrouter-com}"
recovery_complete=0

if [ -z "${previous_template}" ]; then
  echo "${region}: no previous template recorded; refusing to mutate DNS or the MIG" >&2
  exit 1
fi
case "${final_drain_state}" in
  active|drained) ;;
  *)
    echo "${region}: invalid final drain state '${final_drain_state}'" >&2
    exit 2
    ;;
esac

update_drain() {
  local operation="$1"
  QUILL_API_HOST="${primary_host}" QUILL_DNS_ZONE="${dns_zone}" \
    uv run --script tools/reconcile-enclave-dns.py \
      "--${operation}-drain-region" "${region}"
}

reconcile_gcp_dns() {
  QUILL_RECONCILE_APPLY=1 \
  QUILL_API_HOST="${primary_host}" \
  QUILL_DNS_ZONE="${dns_zone}" \
  QUILL_PUBLISH_REGIONAL=1 \
  QUILL_REGIONAL_ZONE=quillrouter-com \
  QUILL_REGIONAL_SUFFIX=quillrouter.com \
    uv run --script tools/reconcile-enclave-dns.py --apply
}

sync_backup_dns() {
  python3 tools/sync-route53-api-aliases.py --apply
}

resolve_template_digest() {
  local template="$1"
  local template_json image_ref digest
  template_json="$(gcloud compute instance-templates describe "${template}" \
    --project="${project}" --format=json)"
  image_ref="$(jq -er '.properties.metadata.items[] | select(.key == "tee-image-reference") | .value' \
    <<<"${template_json}")"
  if [[ "${image_ref}" == *@sha256:* ]]; then
    digest="${image_ref##*@}"
  else
    digest="$(gcloud artifacts docker images describe "${image_ref}" \
      --project="${project}" --format='value(image_summary.digest)')"
  fi
  if [[ ! "${digest}" =~ ^sha256:[0-9a-f]{64}$ ]]; then
    echo "could not resolve an immutable digest for ${template}" >&2
    return 1
  fi
  printf '%s\n' "${digest}"
}

on_exit() {
  local status="$?"
  trap - EXIT
  if [ "${status}" -ne 0 ] && [ "${recovery_complete}" -ne 1 ]; then
    echo "${region}: recovery failed; preserving the canonical rollout drain" >&2
    update_drain set >/dev/null 2>&1 || true
    reconcile_gcp_dns >/dev/null 2>&1 || true
  fi
  exit "${status}"
}
trap on_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

echo "${region}: enforcing canonical drain before rollback"
update_drain set
reconcile_gcp_dns
# Backup-domain reconciliation must not prevent restoration of the enclave.
sync_backup_dns || echo "${region}: backup DNS drain sync failed; continuing rollback" >&2
bash tools/wait-canonical-drained.sh "${region}"

current_template="$(gcloud compute instance-groups managed describe "${mig}" \
  --region="${region}" --project="${project}" \
  --format='value(instanceTemplate.basename())')"
if [ "${current_template}" != "${previous_template}" ]; then
  echo "${region}: restoring ${previous_template}"
  gcloud compute instance-groups managed set-instance-template "${mig}" \
    --region="${region}" --project="${project}" \
    --template="${previous_template}" --quiet
else
  echo "${region}: previous template is already selected"
fi

gcloud compute instance-groups managed wait-until "${mig}" \
  --region="${region}" --project="${project}" \
  --stable --timeout="${ROLLBACK_STABLE_TIMEOUT:-1200}"
bash tools/wait-region-attested.sh "${instance_filter}" "${region} rollback"

previous_digest="$(resolve_template_digest "${previous_template}")"
export API_HOST="${api_hosts}"
bash tools/verify-region-before-dns.sh \
  "${region}" "${instance_filter}" "${previous_digest}"

# Prove the accepted-digest reconciler also accepts the restored fleet while it
# remains excluded from canonical traffic, then restore its pre-rollout drain
# state. An intentionally drained region must never be enabled by recovery.
reconcile_gcp_dns
if [ "${final_drain_state}" = "drained" ]; then
  echo "${region}: rollback verified; preserving pre-rollout canonical drain"
  update_drain set
else
  echo "${region}: rollback verified; clearing rollout drain"
  update_drain clear
fi
reconcile_gcp_dns
sync_backup_dns
recovery_complete=1
echo "${region}: previous template restored, attested, and drain state restored to ${final_drain_state}"
