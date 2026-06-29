#!/usr/bin/env bash
# Wait until the authoritative canonical API DNS record no longer includes any
# public IPs from the region about to be rolled, then wait one DNS TTL so normal
# recursive resolvers age out the prior answer.
set -euo pipefail

REGION="${1:-}"
if [ -z "${REGION}" ]; then
  echo "usage: $0 <region>" >&2
  exit 1
fi

PROJECT_ID="${PROJECT_ID:-quill-cloud-proxy}"
DNS_ZONE="${QUILL_DNS_ZONE:-trustedrouter-com}"
API_HOST="${QUILL_API_HOST:-api.trustedrouter.com}"
RECORD="${API_HOST%.}."
TTL_WAIT_SECONDS="${QUILL_DRAIN_TTL_SECONDS:-75}"
MAX_ROUNDS="${QUILL_DRAIN_MAX_ROUNDS:-36}"
SLEEP_SECONDS="${QUILL_DRAIN_SLEEP_SECONDS:-5}"

region_ips() {
  gcloud compute instances list \
    --project="${PROJECT_ID}" \
    --filter="tags.items=quill-enclave AND status=RUNNING AND zone ~ ${REGION}-" \
    --format='value(networkInterfaces[0].accessConfigs[0].natIP)' \
    | sed '/^$/d' \
    | sort -u
}

canonical_ips() {
  gcloud dns record-sets list \
    --project="${PROJECT_ID}" \
    --zone="${DNS_ZONE}" \
    --name="${RECORD}" \
    --type=A \
    --format='value(rrdatas[])' \
    | tr ';' '\n' \
    | sed '/^$/d' \
    | sort -u
}

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/tr-drain-XXXXXX")"
trap 'rm -rf "${tmp_dir}"' EXIT

for round in $(seq 1 "${MAX_ROUNDS}"); do
  region_ips >"${tmp_dir}/region"
  canonical_ips >"${tmp_dir}/canonical"

  if ! comm -12 "${tmp_dir}/region" "${tmp_dir}/canonical" | grep -q .; then
    echo "${REGION} is absent from authoritative ${RECORD}; waiting ${TTL_WAIT_SECONDS}s for DNS TTL drain"
    sleep "${TTL_WAIT_SECONDS}"
    exit 0
  fi

  echo "${REGION} still appears in ${RECORD}; waiting (${round}/${MAX_ROUNDS})"
  sleep "${SLEEP_SECONDS}"
done

echo "${REGION} did not drain from ${RECORD} before timeout" >&2
echo "region IPs:" >&2
cat "${tmp_dir}/region" >&2 || true
echo "canonical IPs:" >&2
cat "${tmp_dir}/canonical" >&2 || true
exit 1
