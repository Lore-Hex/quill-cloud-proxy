#!/usr/bin/env bash
# Reproducible OCI build followed by a local Nitro measurement comparison.
# PCR0 also depends on the Nitro CLI/kernel/initramfs, not just this OCI image.
#
# Rebuilds the enclave Docker image deterministically from the current
# checkout, builds an EIF, and prints its PCR0. Compare to the repository's
# trust-page/trust/pcr0-aws.txt. Verify signed release provenance and fresh
# TLS-bound live attestation separately before trusting a running endpoint.
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
SOURCE_REVISION=$(git -C "$REPO_ROOT" rev-parse HEAD)
IMAGE_TAG="quill-enclave:verify-$(git -C "$REPO_ROOT" rev-parse --short HEAD)"

# These MUST match tools/release-aws-enclave.sh exactly. They are baked into the
# image and are therefore part of the measurement: building without them uses
# the Dockerfile defaults (BUILD_TAGS=cloud_aws,llm_bedrock, QUILL_TLS_MODE=acme,
# QUILL_API_HOST=api.quillrouter.com) and produces a DIFFERENT PCR0 that will
# never match what is published. A verifier who saw that mismatch would conclude
# the enclave had been tampered with, when in fact the build was wrong.
#
# If release-aws-enclave.sh changes any of these, this script must change with
# it. tools/test_verify_pcr0_build_args.py fails when the two drift apart.
PLATFORM="linux/amd64"
BUILD_TAGS="cloud_aws,llm_multi"
QUILL_TLS_MODE="acme"
QUILL_API_HOST="api-aws.trustedrouter.com"
QUILL_ACME_DNS_GCP_PROJECT="${QUILL_ACME_DNS_GCP_PROJECT:-quill-cloud-proxy}"
QUILL_ACME_DNS_MANAGED_ZONE="${QUILL_ACME_DNS_MANAGED_ZONE:-trustedrouter-com}"

cd "$REPO_ROOT"
BUILD_DIR="$(mktemp -d)/build"
python3 tools/reproducible_build.py build --plane aws \
  --commit "$SOURCE_REVISION" --output-dir "$BUILD_DIR" \
  --build-arg "BUILD_TAGS=${BUILD_TAGS}" \
  --build-arg "QUILL_TLS_MODE=${QUILL_TLS_MODE}" \
  --build-arg "QUILL_API_HOST=${QUILL_API_HOST}" \
  --build-arg "QUILL_ACME_DNS_GCP_PROJECT=${QUILL_ACME_DNS_GCP_PROJECT}" \
  --build-arg "QUILL_ACME_DNS_MANAGED_ZONE=${QUILL_ACME_DNS_MANAGED_ZONE}"
docker load --input "$BUILD_DIR/image.tar"
docker tag "$(jq -r '."containerimage.config.digest"' "$BUILD_DIR/build-metadata.json")" "$IMAGE_TAG"

if ! command -v nitro-cli >/dev/null 2>&1; then
  cat >&2 <<EOF
nitro-cli not installed. Install via:
  amazon-linux-extras install aws-nitro-enclaves-cli
or use the AWS-provided Nitro Enclaves CLI Docker image.
EOF
  exit 1
fi

EIF_OUT="$REPO_ROOT/enclave-go/quill.eif"
sudo nitro-cli build-enclave \
  --docker-uri "$IMAGE_TAG" \
  --output-file "$EIF_OUT" \
  | tee "$REPO_ROOT/enclave-go/eif-measurements.json"

PCR0=$(jq -r '.Measurements.PCR0' "$REPO_ROOT/enclave-go/eif-measurements.json")

echo
echo "PCR0 (measured): $PCR0"

PUBLISHED_FILE="$REPO_ROOT/trust-page/trust/pcr0-aws.txt"
if [[ -f "$PUBLISHED_FILE" ]]; then
  PUBLISHED=$(cat "$PUBLISHED_FILE")
  echo "PCR0 (published): $PUBLISHED"
  if [[ "$PCR0" == "$PUBLISHED" ]]; then
    echo "MATCH: local EIF PCR0 matches the checked-out measurement record."
    echo "This is not live attestation; separately verify the signed release and live TLS binding."
  else
    echo "MISMATCH: recorded PCR0 differs from local rebuild." >&2
    exit 1
  fi
fi
