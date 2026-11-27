#!/usr/bin/env bash
# Reproducible PCR0 build.
#
# Rebuilds the enclave Docker image deterministically from the current
# checkout, runs nitro-cli describe-eif against it, and prints the PCR0.
# Compare to the signed CI artifact for this exact source commit. The public
# primary may still describe the old image during a staged release.
#
# Requires Docker, Cosign, and the signed CI manifest plus bundle. The builder
# is pinned by that manifest, never whatever nitro-cli a host happens to have.
#
# This script is intentionally tiny — every line should be auditable.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/.." && pwd)"
IMAGE_TAG="quill-enclave:verify-$(git -C "$REPO_ROOT" rev-parse --short HEAD)"
: "${AWS_EIF_MANIFEST:?set the downloaded CI manifest path}"
: "${AWS_EIF_SIGNATURE:?set the CI signature bundle path}"
if [ -n "$(git -C "$REPO_ROOT" status --porcelain -- enclave-go)" ]; then
  echo "Cannot reproduce an uncommitted enclave tree." >&2
  exit 1
fi
VERIFIED=$(python3 "$HERE/aws_eif_manifest.py" verify --manifest "$AWS_EIF_MANIFEST" \
  --signature "$AWS_EIF_SIGNATURE" --expected-source "$(git -C "$REPO_ROOT" rev-parse HEAD)")
BUILDER_IMAGE=$(printf '%s' "$VERIFIED" | python3 -c 'import json,sys; print(json.load(sys.stdin)["builder_image"])')
EXPECTED_PCR0=$(printf '%s' "$VERIFIED" | python3 -c 'import json,sys; print(json.load(sys.stdin)["measurements"]["PCR0"])')

# These MUST match .github/workflows/publish-aws-eif.yml exactly. They are baked into the
# image and are therefore part of the measurement: building without them uses
# the Dockerfile defaults (BUILD_TAGS=cloud_aws,llm_bedrock, QUILL_TLS_MODE=acme,
# QUILL_API_HOST=api.quillrouter.com) and produces a DIFFERENT PCR0 that will
# never match what is published. A verifier who saw that mismatch would conclude
# the enclave had been tampered with, when in fact the build was wrong.
#
# If publish-aws-eif.yml changes any of these, this script must change with
# it. tools/test_verify_pcr0_build_args.py fails when the two drift apart.
PLATFORM="linux/amd64"
BUILD_TAGS="cloud_aws,llm_multi"
QUILL_TLS_MODE="acme"
QUILL_API_HOST="api-aws.trustedrouter.com"
QUILL_ACME_DNS_GCP_PROJECT="quill-cloud-proxy"
QUILL_ACME_DNS_MANAGED_ZONE="trustedrouter-com"

cd "$REPO_ROOT"
bash tools/build-aws-eif-image.sh \
  --platform "$PLATFORM" \
  --file enclave-go/Dockerfile.enclave \
    --build-arg "SOURCE_REVISION=$(git -C "$REPO_ROOT" rev-parse HEAD)" \
  --build-arg "BUILD_TAGS=${BUILD_TAGS}" \
  --build-arg "QUILL_TLS_MODE=${QUILL_TLS_MODE}" \
  --build-arg "QUILL_API_HOST=${QUILL_API_HOST}" \
  --build-arg "QUILL_ACME_DNS_GCP_PROJECT=${QUILL_ACME_DNS_GCP_PROJECT}" \
  --build-arg "QUILL_ACME_DNS_MANAGED_ZONE=${QUILL_ACME_DNS_MANAGED_ZONE}" \
  -t "$IMAGE_TAG" \
  enclave-go

OUTPUT=$(mktemp -d)
trap 'rm -rf "$OUTPUT"' EXIT
docker pull "$BUILDER_IMAGE"
docker run --rm --platform "$PLATFORM" \
  -v /var/run/docker.sock:/var/run/docker.sock -v "$OUTPUT:/output" \
  "$BUILDER_IMAGE" build-enclave --docker-uri "$IMAGE_TAG" --output-file /output/enclave.eif \
  > "$OUTPUT/build.json"
docker run --rm --platform "$PLATFORM" -v "$OUTPUT:/output:ro" \
  "$BUILDER_IMAGE" describe-eif --eif-path /output/enclave.eif > "$OUTPUT/describe.json"
diff <(jq -S '.Measurements' "$OUTPUT/build.json") <(jq -S '.Measurements' "$OUTPUT/describe.json")
test "$(jq -r '.CheckCRC' "$OUTPUT/describe.json")" = true
PCR0=$(jq -r '.Measurements.PCR0' "$OUTPUT/describe.json")
if [ "$PCR0" != "$EXPECTED_PCR0" ]; then
  echo "MISMATCH: rebuilt PCR0 differs from signed CI measurement." >&2
  exit 1
fi

echo
echo "PCR0 (measured): $PCR0"

echo "MATCH: rebuilt source matches the signed CI PCR0. Live instance attestation is a separate check."
