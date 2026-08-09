#!/usr/bin/env bash
# Fail-closed regional bootstrap gate.
#
# Verify every running instance directly, with the future regional hostname as
# SNI, before a cold-region CNAME is promoted to an A record or the region is
# allowed into canonical DNS. This exercises both the cryptographic attestation
# path and one real, billed-and-settled inference request per instance.
#
# Usage: verify-region-before-dns.sh <region> <instance-name-filter> <image-digest>
set -euo pipefail

REGION="${1:?usage: verify-region-before-dns.sh <region> <instance-name-filter> <image-digest>}"
FILTER="${2:?missing instance-name-filter}"
IMAGE_DIGEST="${3:?missing image-digest}"
PROJECT="${QUILL_GCP_PROJECT_ID:-quill-cloud-proxy}"
HOST="api-${REGION}.quillrouter.com"
MIN_INSTANCES="${MIN_REGION_INSTANCES:-2}"
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

mapfile -t ips < <(
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
trap 'rm -f "${response_file}"' EXIT

for ip in "${ips[@]}"; do
  echo "${REGION}: verifying attestation on ${ip}"
  attested=0
  for attempt in 1 2 3; do
    if uv run --script tools/verify-attestation.py \
      --api-host "${HOST}" \
      --connect-ip "${ip}" \
      --expect-digest "${IMAGE_DIGEST}" \
      --samples 2; then
      attested=1
      break
    fi
    echo "${REGION}: attestation attempt ${attempt}/3 on ${ip} failed; waiting for regional certificate readiness" >&2
    sleep 10
  done
  if [ "${attested}" != "1" ]; then
    echo "${REGION}: ${ip} never passed full attestation" >&2
    exit 1
  fi

  echo "${REGION}: running direct inference canary on ${ip}"
  idempotency_key="region-canary-${GITHUB_RUN_ID:-manual}-${REGION}-${ip//./-}"
  completed=0
  for attempt in 1 2 3; do
    code="000"
    if code="$(curl \
      --silent --show-error \
      --noproxy "${HOST}" \
      --max-time 90 \
      --resolve "${HOST}:443:${ip}" \
      --output "${response_file}" \
      --write-out '%{http_code}' \
      -H "authorization: Bearer ${SMOKE_KEY}" \
      -H "content-type: application/json" \
      -H "idempotency-key: ${idempotency_key}" \
      -d '{"model":"trustedrouter/monitor","messages":[{"role":"user","content":"reply exactly PONG"}],"max_tokens":32}' \
      "https://${HOST}/v1/chat/completions")" && [ "${code}" = "200" ]; then
      completed=1
      break
    fi
    echo "${REGION}: direct inference attempt ${attempt}/3 on ${ip} returned HTTP ${code}" >&2
    sleep 5
  done
  if [ "${completed}" != "1" ]; then
    echo "${REGION}: direct inference canary on ${ip} did not succeed" >&2
    exit 1
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
done

echo "${REGION}: ${#ips[@]} instances passed attestation and inference canaries"
