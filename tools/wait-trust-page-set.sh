#!/usr/bin/env bash
set -euo pipefail

expected_digests="${1:?expected comma-separated digest set is required}"
expected_references="${2:?expected comma-separated image-reference set is required}"
attempts="${TR_TRUST_VERIFY_ATTEMPTS:-60}"
sleep_seconds="${TR_TRUST_VERIFY_SLEEP_SECONDS:-15}"
base_url="${TR_TRUST_PAGE_BASE_URL:-https://trust.trustedrouter.com/trust}"
cache_key="${GITHUB_RUN_ID:-local}-$$"

for ((attempt = 1; attempt <= attempts; attempt++)); do
  live_digests="$(curl -fsS --connect-timeout 5 --max-time 15 \
    "${base_url}/accepted-image-digests-gcp.txt?nocache=${cache_key}-${attempt}" || true)"
  live_references="$(curl -fsS --connect-timeout 5 --max-time 15 \
    "${base_url}/accepted-image-references-gcp.txt?nocache=${cache_key}-${attempt}" || true)"

  if [[ "${live_digests}" == "${expected_digests}" && \
        "${live_references}" == "${expected_references}" ]]; then
    echo "public trust page matches the exact expected image set"
    exit 0
  fi

  echo "attempt ${attempt}/${attempts}: public trust set has not converged"
  echo "  expected digests:   ${expected_digests}"
  echo "  live digests:       ${live_digests}"
  echo "  expected references:${expected_references}"
  echo "  live references:    ${live_references}"
  if (( attempt < attempts )); then
    sleep "${sleep_seconds}"
  fi
done

echo "public trust page did not converge to the exact expected image set" >&2
exit 1
