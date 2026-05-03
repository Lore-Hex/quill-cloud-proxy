#!/usr/bin/env bash
# Reproducible PCR0 build.
#
# Rebuilds the enclave Docker image deterministically from the current
# checkout, runs nitro-cli describe-eif against it, and prints the PCR0.
# Compare to the value at trust-page/pcr0.txt and at
# https://trust.quill.lorehex.co/pcr0.txt.
#
# Requires:
#   - docker
#   - nitro-cli (only available on Nitro-capable EC2 hosts AS OF 2026-04;
#     for laptop verification we use AWS's reference Nitro builder image
#     which runs on x86 only).
#
# This script is intentionally tiny — every line should be auditable.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/.." && pwd)"
IMAGE_TAG="quill-enclave:verify-$(git -C "$REPO_ROOT" rev-parse --short HEAD)"

cd "$REPO_ROOT/enclave"
docker build --no-cache -t "$IMAGE_TAG" -f Dockerfile.enclave .

if ! command -v nitro-cli >/dev/null 2>&1; then
  cat >&2 <<EOF
nitro-cli not installed. Install via:
  amazon-linux-extras install aws-nitro-enclaves-cli
or use the AWS-provided Nitro Enclaves CLI Docker image.
EOF
  exit 1
fi

EIF_OUT="$REPO_ROOT/enclave/quill.eif"
sudo nitro-cli build-enclave \
  --docker-uri "$IMAGE_TAG" \
  --output-file "$EIF_OUT" \
  | tee "$REPO_ROOT/enclave/eif-measurements.json"

PCR0=$(jq -r '.Measurements.PCR0' "$REPO_ROOT/enclave/eif-measurements.json")

echo
echo "PCR0 (measured): $PCR0"

PUBLISHED_FILE="$REPO_ROOT/trust-page/pcr0.txt"
if [[ -f "$PUBLISHED_FILE" ]]; then
  PUBLISHED=$(cat "$PUBLISHED_FILE")
  echo "PCR0 (published): $PUBLISHED"
  if [[ "$PCR0" == "$PUBLISHED" ]]; then
    echo "MATCH ✓ — the running enclave runs this exact source."
  else
    echo "MISMATCH ✗ — published PCR0 differs from local rebuild." >&2
    exit 1
  fi
fi
