#!/usr/bin/env bash
# Fail-closed first-region bootstrap gate.
#
# A new regional hostname starts as a CNAME to the canonical API. Asking the
# new VM for that regional certificate cannot work yet: ACME validation follows
# the CNAME to the old fleet. Keep DNS authority out of the enclave and break
# that cycle in this order:
#
#   1. Verify every new VM directly through the already-issued canonical SNI.
#   2. Atomically replace the unpublished cold CNAME with one verified VM IP.
#   3. Let that VM obtain the regional certificate with TLS-ALPN-01.
#   4. Verify attestation, a real settled PONG, and a terminal SSE stream on
#      every VM through the new regional SNI. If the selected instance
#      template enables QUILL_USAGE_HEARTBEAT, the settled authorization must
#      also prove a heartbeat from that VM's boot key.
#
# The caller may publish the full regional A set only after this script exits
# successfully. Any failure after step 2 atomically restores the cold CNAME.
# Existing regions already have an A record, so they skip step 2 and run the
# regional gate directly.
#
# Usage: verify-region-before-dns.sh <region> <instance-name-filter> <image-digest>
set -euo pipefail

TOOLS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=tools/stage-d-gate-lib.sh
source "${TOOLS_DIR}/stage-d-gate-lib.sh"

REGION="${1:?usage: verify-region-before-dns.sh <region> <instance-name-filter> <image-digest>}"
FILTER="${2:?missing instance-name-filter}"
IMAGE_DIGEST="${3:?missing image-digest}"
PROJECT="${QUILL_GCP_PROJECT_ID:-quill-cloud-proxy}"
BOOTSTRAP_HOST="${QUILL_BOOTSTRAP_HOST:-api.quillrouter.com}"
REGIONAL_HOST="api-${REGION}.quillrouter.com"
REGIONAL_RECORD="${REGIONAL_HOST}."
DNS_ZONE="${QUILL_REGIONAL_ZONE:-quillrouter-com}"
DNS_TTL="${QUILL_DNS_TTL:-60}"
MIN_INSTANCES="${MIN_REGION_INSTANCES:-2}"
REGIONAL_CERT_ATTEMPTS="${REGIONAL_CERT_ATTEMPTS:-10}"
REGIONAL_CERT_RETRY_SLEEP="${REGIONAL_CERT_RETRY_SLEEP:-15}"
MIG="${FILTER%-}"
AUTHORIZATION_LOOKUP_BASE_URL="${STAGE_D_AUTHORIZATION_LOOKUP_BASE_URL:-https://trustedrouter.com}"

template_url="$(gcloud compute instance-groups managed describe "${MIG}" \
  --region="${REGION}" --project="${PROJECT}" \
  --format='value(instanceTemplate)')"
template_name="${template_url##*/}"
if [ -z "${template_name}" ]; then
  echo "${REGION}: could not resolve the selected instance template" >&2
  exit 1
fi
template_json="$(gcloud compute instance-templates describe "${template_name}" \
  --project="${PROJECT}" --format=json)"
HEARTBEAT_FLAG="$(jq -r \
  '[.properties.metadata.items[]? | select(.key == "tee-env-QUILL_USAGE_HEARTBEAT") | .value] | if length == 0 then "off" elif length == 1 then .[0] else "duplicate" end' \
  <<<"${template_json}")"
case "${HEARTBEAT_FLAG}" in
  on|off) ;;
  *)
    echo "${REGION}: selected template ${template_name} has invalid QUILL_USAGE_HEARTBEAT metadata '${HEARTBEAT_FLAG}'" >&2
    exit 1
    ;;
esac
echo "${REGION}: selected template ${template_name} has QUILL_USAGE_HEARTBEAT=${HEARTBEAT_FLAG}"

stage_d_select_probe_key "${HEARTBEAT_FLAG}" "${PROJECT}" "${REGION}"

# This is an existing gateway-to-router credential, not the client probe key.
# It is used only to read the content-free authorization facts needed by the
# gate after the public stream has settled.
INTERNAL_GATEWAY_TOKEN="${TRUSTEDROUTER_INTERNAL_TOKEN:-}"
if [ -z "${INTERNAL_GATEWAY_TOKEN}" ]; then
  INTERNAL_GATEWAY_TOKEN="$(gcloud secrets versions access latest \
    --secret=trustedrouter-internal-gateway-token \
    --project="${PROJECT}" 2>/dev/null || true)"
fi
if [ -z "${INTERNAL_GATEWAY_TOKEN}" ]; then
  echo "${REGION}: internal authorization lookup token is unavailable; failing closed" >&2
  exit 1
fi

ips=()
while IFS= read -r ip; do
  [ -n "${ip}" ] && ips+=("${ip}")
done < <(
  gcloud compute instances list \
    --project="${PROJECT}" \
    --filter="name~${FILTER} AND status=RUNNING" \
    --format='value(networkInterfaces[0].accessConfigs[0].natIP)' \
    | sed '/^[[:space:]]*$/d' \
    | sort -u
)

if [ "${#ips[@]}" -lt "${MIN_INSTANCES}" ]; then
  echo "${REGION}: found ${#ips[@]} running instances; require ${MIN_INSTANCES}" >&2
  exit 1
fi

response_dir="$(mktemp -d "${TMPDIR:-/tmp}/tr-region-canary-XXXXXX")"
response_file="${response_dir}/response.json"
promoted_cold_alias=0
cname_value=""
cname_ttl=""

dns_record_json() {
  local type="$1"
  gcloud dns record-sets list \
    --project="${PROJECT}" \
    --zone="${DNS_ZONE}" \
    --name="${REGIONAL_RECORD}" \
    --type="${type}" \
    --format=json
}

run_dns_transaction() {
  local action="$1" transaction_file="$2"
  shift 2
  gcloud dns record-sets transaction "${action}" "$@" \
    --zone="${DNS_ZONE}" \
    --project="${PROJECT}" \
    --transaction-file="${transaction_file}" \
    >/dev/null
}

replace_cold_alias_with_bootstrap_ip() {
  local cname_json transaction_dir transaction_file
  cname_json="$(dns_record_json CNAME)"
  cname_value="$(jq -r '.[0].rrdatas[0] // empty' <<<"${cname_json}")"
  cname_ttl="$(jq -r '.[0].ttl // empty' <<<"${cname_json}")"

  if [ -z "${cname_value}" ]; then
    # Existing regional A record: normal rollout, no first-cert bootstrap.
    if [ "$(jq 'length' <<<"$(dns_record_json A)")" -gt 0 ]; then
      echo "${REGION}: regional A record already exists; skipping cold-alias bootstrap"
      return 1
    fi
    echo "${REGION}: regional DNS has neither a CNAME nor an A record; failing closed" >&2
    exit 1
  fi
  if ! [[ "${cname_ttl}" =~ ^[0-9]+$ ]]; then
    echo "${REGION}: invalid cold CNAME TTL '${cname_ttl}'" >&2
    exit 1
  fi

  transaction_dir="$(mktemp -d "${TMPDIR:-/tmp}/tr-region-dns-XXXXXX")"
  transaction_file="${transaction_dir}/transaction.yaml"
  run_dns_transaction start "${transaction_file}"
  run_dns_transaction remove "${transaction_file}" \
    "${cname_value}" \
    --name="${REGIONAL_RECORD}" --type=CNAME --ttl="${cname_ttl}"
  run_dns_transaction add "${transaction_file}" \
    "${ips[0]}" \
    --name="${REGIONAL_RECORD}" --type=A --ttl="${DNS_TTL}"
  run_dns_transaction execute "${transaction_file}"
  rm -rf "${transaction_dir}"
  promoted_cold_alias=1
  echo "${REGION}: cold CNAME promoted to one pre-verified bootstrap IP ${ips[0]}"
  return 0
}

restore_cold_alias() {
  local a_json transaction_dir transaction_file
  local -a current_ips
  a_json="$(dns_record_json A)"
  current_ips=()
  while IFS= read -r ip; do
    [ -n "${ip}" ] && current_ips+=("${ip}")
  done < <(jq -r '.[0].rrdatas[]?' <<<"${a_json}")
  if [ "${#current_ips[@]}" -eq 0 ] || [ -z "${cname_value}" ]; then
    echo "${REGION}: cannot restore cold CNAME automatically; inspect ${REGIONAL_RECORD}" >&2
    return 1
  fi

  transaction_dir="$(mktemp -d "${TMPDIR:-/tmp}/tr-region-dns-rollback-XXXXXX")"
  transaction_file="${transaction_dir}/transaction.yaml"
  run_dns_transaction start "${transaction_file}"
  run_dns_transaction remove "${transaction_file}" \
    "${current_ips[@]}" \
    --name="${REGIONAL_RECORD}" --type=A --ttl="${DNS_TTL}"
  run_dns_transaction add "${transaction_file}" \
    "${cname_value}" \
    --name="${REGIONAL_RECORD}" --type=CNAME --ttl="${cname_ttl}"
  run_dns_transaction execute "${transaction_file}"
  rm -rf "${transaction_dir}"
  promoted_cold_alias=0
  echo "${REGION}: restored cold CNAME ${REGIONAL_RECORD} -> ${cname_value}" >&2
}

on_exit() {
  local status=$?
  trap - EXIT
  rm -rf "${response_dir}"
  if [ "${status}" -ne 0 ] && [ "${promoted_cold_alias}" = "1" ]; then
    restore_cold_alias || true
  fi
  exit "${status}"
}
trap on_exit EXIT

verify_streaming_authorization() {
  local host="$1" ip="$2" stage="$3"
  local suffix headers stream receipt evidence code request_log_id expected_boot_kid=""
  local idempotency_key attempt lookup_url content_type evidence_state
  local timeout_seconds deadline remaining retry_sleep
  suffix="${stage}-${ip//./-}"
  headers="${response_dir}/${suffix}.headers"
  stream="${response_dir}/${suffix}.sse"
  receipt="${response_dir}/${suffix}.receipt-key.json"
  evidence="${response_dir}/${suffix}.authorization.json"

  if [ "${HEARTBEAT_FLAG}" = "on" ]; then
    curl --silent --show-error --fail \
      --noproxy "${host}" \
      --connect-timeout 10 --max-time 30 \
      --resolve "${host}:443:${ip}" \
      --output "${receipt}" \
      "https://${host}/receipt-key"
    expected_boot_kid="$(jq -er '.kid | select(type == "string" and length > 0)' "${receipt}")"
  fi

  echo "${REGION}: running ${stage} direct streaming canary on ${ip} (Stage D evidence ${HEARTBEAT_FLAG})"
  idempotency_key="stage-d-region-canary-${GITHUB_RUN_ID:-manual}-${REGION}-${stage}-${ip//./-}"
  code="000"
  if ! code="$(curl \
    --silent --show-error --no-buffer \
    --noproxy "${host}" \
    --connect-timeout 10 --max-time 90 \
    --resolve "${host}:443:${ip}" \
    --dump-header "${headers}" \
    --output "${stream}" \
    --write-out '%{http_code}' \
    -H "authorization: Bearer ${STAGE_D_PROBE_KEY}" \
    -H "content-type: application/json" \
    -H "idempotency-key: ${idempotency_key}" \
    -d '{"model":"trustedrouter/monitor","messages":[{"role":"user","content":"reply exactly PONG"}],"max_tokens":32,"stream":true}' \
    "https://${host}/v1/chat/completions")" || [ "${code}" != "200" ]; then
    echo "${REGION}: ${stage} streaming canary on ${ip} returned HTTP ${code}" >&2
    return 1
  fi
  content_type="$(tr -d '\r' <"${headers}" | awk -F ': *' 'tolower($1) == "content-type" { value=tolower($2) } END { print value }')"
  if [[ "${content_type}" != text/event-stream* ]]; then
    echo "${REGION}: ${stage} streaming canary on ${ip} was not text/event-stream" >&2
    return 1
  fi
  python3 tools/verify-stage-d-stream.py stream "${stream}"

  request_log_id="$(tr -d '\r' <"${headers}" | awk -F ': *' 'tolower($1) == "x-request-id" { value=$2 } END { print value }')"
  if ! [[ "${request_log_id}" =~ ^rlog_[0-9a-f]{32}$ ]]; then
    echo "${REGION}: ${stage} stream returned no valid x-request-id" >&2
    return 1
  fi
  lookup_url="${AUTHORIZATION_LOOKUP_BASE_URL}/internal/gateway/authorizations/by-gateway-request-id/${request_log_id}"
  timeout_seconds="${STAGE_D_EVIDENCE_TIMEOUT_SECONDS:-60}"
  retry_sleep="${STAGE_D_EVIDENCE_RETRY_SLEEP:-2}"
  deadline=$((SECONDS + timeout_seconds))
  attempt=0
  while [ "${SECONDS}" -lt "${deadline}" ]; do
    attempt=$((attempt + 1))
    remaining=$((deadline - SECONDS))
    code="000"
    if code="$(curl \
      --silent --show-error \
      --connect-timeout 5 --max-time "${remaining}" \
      --output "${evidence}" \
      --write-out '%{http_code}' \
      -H "x-trustedrouter-internal-token: ${INTERNAL_GATEWAY_TOKEN}" \
      "${lookup_url}")" && [ "${code}" = "200" ]; then
      if ! evidence_state="$(stage_d_evidence_state \
        "${evidence}" "${request_log_id}" "${HEARTBEAT_FLAG}" \
        "${expected_boot_kid}")"; then
        echo "${REGION}: ${stage} stream on ${ip} returned invalid settled authorization evidence" >&2
        return 1
      fi
      if [ "${evidence_state}" = "valid" ]; then
        echo "${REGION}: ${stage} stream on ${ip} has settled local_typed authorization evidence"
        return 0
      fi
    fi
    remaining=$((deadline - SECONDS))
    if [ "${remaining}" -lt 0 ]; then
      remaining=0
    fi
    echo "${REGION}: ${stage} authorization evidence attempt ${attempt} is not settled (HTTP ${code}; ${remaining}s remain)" >&2
    if [ "${remaining}" -gt 0 ]; then
      if [ "${retry_sleep}" -gt "${remaining}" ]; then
        sleep "${remaining}"
      else
        sleep "${retry_sleep}"
      fi
    fi
  done
  echo "${REGION}: ${stage} stream on ${ip} did not settle within ${timeout_seconds}s" >&2
  return 1
}

verify_instance() {
  local host="$1" ip="$2" attempts="$3" stage="$4"
  local attested=0 completed=0 code="000" idempotency_key attempt

  echo "${REGION}: verifying ${stage} attestation on ${ip} with SNI ${host}"
  for attempt in $(seq 1 "${attempts}"); do
    if uv run --script tools/verify-attestation.py \
      --api-host "${host}" \
      --connect-ip "${ip}" \
      --expect-digest "${IMAGE_DIGEST}" \
      --samples 2; then
      attested=1
      break
    fi
    echo "${REGION}: ${stage} attestation attempt ${attempt}/${attempts} on ${ip} failed" >&2
    sleep "${REGIONAL_CERT_RETRY_SLEEP}"
  done
  if [ "${attested}" != "1" ]; then
    echo "${REGION}: ${ip} never passed ${stage} attestation" >&2
    return 1
  fi

  echo "${REGION}: running ${stage} direct inference canary on ${ip}"
  idempotency_key="region-canary-${GITHUB_RUN_ID:-manual}-${REGION}-${stage}-${ip//./-}"
  for attempt in 1 2 3; do
    code="000"
    if code="$(curl \
      --silent --show-error \
      --noproxy "${host}" \
      --max-time 90 \
      --resolve "${host}:443:${ip}" \
      --output "${response_file}" \
      --write-out '%{http_code}' \
      -H "authorization: Bearer ${STAGE_D_PROBE_KEY}" \
      -H "content-type: application/json" \
      -H "idempotency-key: ${idempotency_key}" \
      -d '{"model":"trustedrouter/monitor","messages":[{"role":"user","content":"reply exactly PONG"}],"max_tokens":32}' \
      "https://${host}/v1/chat/completions")" && [ "${code}" = "200" ]; then
      completed=1
      break
    fi
    echo "${REGION}: ${stage} inference attempt ${attempt}/3 on ${ip} returned HTTP ${code}" >&2
    sleep 5
  done
  if [ "${completed}" != "1" ]; then
    echo "${REGION}: ${stage} direct inference canary on ${ip} did not succeed" >&2
    return 1
  fi
  python3 - "${response_file}" <<'PY'
import json
import pathlib
import sys

payload = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
content = payload.get("choices", [{}])[0].get("message", {}).get("content", "")
if str(content).strip() != "PONG":
    raise SystemExit("direct inference canary did not return exact PONG")
PY
  if [ "${stage}" = "regional" ]; then
    verify_streaming_authorization "${host}" "${ip}" "${stage}"
  fi
}

# This gate runs before any DNS mutation. It proves the exact image, live TLS
# binding, and real inference/settlement behavior on every candidate VM.
for ip in "${ips[@]}"; do
  verify_instance "${BOOTSTRAP_HOST}" "${ip}" 3 bootstrap
done

if replace_cold_alias_with_bootstrap_ip; then
  # Do not trigger ACME while recursive resolvers may still follow the old
  # CNAME. A failed authorization is rate-limited; waiting once is cheaper and
  # more reliable than retrying a challenge against stale DNS.
  propagation_wait=$((cname_ttl + 15))
  if [ "${propagation_wait}" -gt 360 ]; then
    propagation_wait=360
  fi
  echo "${REGION}: waiting ${propagation_wait}s for cold CNAME caches to expire"
  sleep "${propagation_wait}"
  regional_attempts="${REGIONAL_CERT_ATTEMPTS}"
else
  regional_attempts=3
fi

# The first handshake may mint the regional certificate. Once it reaches the
# shared GCS cache, every instance must independently pass with that SNI.
for ip in "${ips[@]}"; do
  verify_instance "${REGIONAL_HOST}" "${ip}" "${regional_attempts}" regional
done

# Leave a successful first deployment on its one-IP A record. The reconciler
# immediately after this script independently re-attests the regional SNI and
# expands it to the complete healthy regional set.
promoted_cold_alias=0
echo "${REGION}: ${#ips[@]} instances passed bootstrap and regional attestation/inference/streaming canaries"
