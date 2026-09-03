#!/usr/bin/env bash
# Wait until the exact committed Stage D policy and its exact-identity bundle
# are both public. Signature verification is repeated on every fetched pair so
# an unsigned or wrongly signed CDN response can never open a rollout gate.
set -euo pipefail

expected_file="${1:?expected committed Stage D policy path is required}"
attempts="${TR_STAGE_D_POLICY_VERIFY_ATTEMPTS:-60}"
sleep_seconds="${TR_STAGE_D_POLICY_VERIFY_SLEEP_SECONDS:-15}"
base_url="${TR_TRUST_PAGE_BASE_URL:-https://trust.trustedrouter.com}"
identity="https://github.com/Lore-Hex/quill-cloud-proxy/.github/workflows/publish-trust-gcp.yml@refs/heads/main"
issuer="https://token.actions.githubusercontent.com"
cache_key="${GITHUB_RUN_ID:-local}-$$"

python3 tools/write-stage-d-policy.py --validate "${expected_file}"
work_dir="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/stage-d-policy-verify-XXXXXX")"
trap 'rm -rf "${work_dir}"' EXIT

for ((attempt = 1; attempt <= attempts; attempt++)); do
  payload="${work_dir}/stage-d-accepted.json"
  bundle="${payload}.bundle"
  rm -f "${payload}" "${bundle}"
  url="${base_url}/gcp/stage-d-accepted.json?nocache=${cache_key}-${attempt}"
  bundle_url="${base_url}/gcp/stage-d-accepted.json.bundle?nocache=${cache_key}-${attempt}"
  if curl -fsS --connect-timeout 5 --max-time 15 -o "${payload}" "${url}" &&
     curl -fsS --connect-timeout 5 --max-time 15 -o "${bundle}" "${bundle_url}" &&
     cmp -s "${expected_file}" "${payload}" &&
     cosign verify-blob \
       --bundle "${bundle}" \
       --certificate-identity "${identity}" \
       --certificate-oidc-issuer "${issuer}" \
       "${payload}" >/dev/null; then
    echo "public Stage D policy matches the committed bytes and verifies under ${identity}"
    exit 0
  fi
  echo "attempt ${attempt}/${attempts}: exact signed Stage D policy has not converged"
  if (( attempt < attempts )); then
    sleep "${sleep_seconds}"
  fi
done

echo "public Stage D policy or exact-identity bundle did not converge" >&2
exit 1
