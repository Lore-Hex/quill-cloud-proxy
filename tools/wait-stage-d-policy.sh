#!/usr/bin/env bash
# Wait until the exact committed Stage D policy and its exact-identity bundle
# are both public. Signature verification is repeated on every fetched pair so
# an unsigned or wrongly signed CDN response can never open a rollout gate.
set -euo pipefail

expected_file="${1:?expected committed Stage D policy path is required}"
attempts="${TR_STAGE_D_POLICY_VERIFY_ATTEMPTS:-60}"
sleep_seconds="${TR_STAGE_D_POLICY_VERIFY_SLEEP_SECONDS:-15}"
base_url="${TR_TRUST_PAGE_BASE_URL:-https://trust.trustedrouter.com}"
cache_key="${GITHUB_RUN_ID:-local}-$$"

python3 tools/write-stage-d-policy.py --validate "${expected_file}"
work_dir="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/stage-d-policy-verify-XXXXXX")"
trap 'rm -rf "${work_dir}"' EXIT
# Each fetched pair sits at the path the trust page serves it from, so
# tools/check-trust-signatures.py checks it as the publishers check what they
# publish: a protobuf bundle holding a signing certificate, which cosign
# verifies under publish-trust-gcp.yml's identity.
site="${work_dir}/site"
payload="${site}/gcp/stage-d-accepted.json"
bundle="${payload}.bundle"
mkdir -p "${site}/gcp"

for ((attempt = 1; attempt <= attempts; attempt++)); do
  rm -f "${payload}" "${bundle}"
  url="${base_url}/gcp/stage-d-accepted.json?nocache=${cache_key}-${attempt}"
  bundle_url="${base_url}/gcp/stage-d-accepted.json.bundle?nocache=${cache_key}-${attempt}"
  if curl -fsS --connect-timeout 5 --max-time 15 -o "${payload}" "${url}" &&
     curl -fsS --connect-timeout 5 --max-time 15 -o "${bundle}" "${bundle_url}" &&
     cmp -s "${expected_file}" "${payload}" &&
     python3 tools/check-trust-signatures.py "${site}" >/dev/null; then
    echo "public Stage D policy matches the committed bytes and its bundle verifies under publish-trust-gcp.yml"
    exit 0
  fi
  echo "attempt ${attempt}/${attempts}: exact signed Stage D policy has not converged"
  if (( attempt < attempts )); then
    sleep "${sleep_seconds}"
  fi
done

echo "public Stage D policy or exact-identity bundle did not converge" >&2
exit 1
