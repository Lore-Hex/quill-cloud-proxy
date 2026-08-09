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
#   4. Verify attestation and a real settled PONG on every VM through the new
#      regional SNI.
#
# The caller may publish the full regional A set only after this script exits
# successfully. Any failure after step 2 atomically restores the cold CNAME.
# Existing regions already have an A record, so they skip step 2 and run the
# regional gate directly.
#
# Usage: verify-region-before-dns.sh <region> <instance-name-filter> <image-digest>
set -euo pipefail

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
SMOKE_KEY="${SMOKE_TEST_API_KEY:-}"

if [ -z "${SMOKE_KEY}" ]; then
  SMOKE_KEY="$(gcloud secrets versions access latest \
    --secret=trustedrouter-synthetic-monitor-api-key \
    --project="${PROJECT}" 2>/dev/null || true)"
fi
if [ -z "${SMOKE_KEY}" ]; then
  echo "${REGION}: synthetic monitor key is unavailable; failing closed" >&2
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

response_file="$(mktemp "${TMPDIR:-/tmp}/tr-region-canary-XXXXXX.json")"
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
  rm -f "${response_file}"
  if [ "${status}" -ne 0 ] && [ "${promoted_cold_alias}" = "1" ]; then
    restore_cold_alias || true
  fi
  exit "${status}"
}
trap on_exit EXIT

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
      -H "authorization: Bearer ${SMOKE_KEY}" \
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
echo "${REGION}: ${#ips[@]} instances passed bootstrap and regional attestation/inference canaries"
