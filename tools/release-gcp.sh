#!/usr/bin/env bash
# Build and publish a formal GCP Confidential Space workload release.
#
# This is the non-manual trust publication path:
#   1. Build/push a versioned Artifact Registry image tag.
#   2. Resolve the immutable OCI digest.
#   3. Update trust-page/image-digest-gcp.txt, image-reference-gcp.txt,
#      and gcp-release.json for commit review/signing/publish.
#
# It uploads nothing to the trust mirror: publish-trust-s3.yml publishes it
# from main once the files are committed.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/.." && pwd)"

PROJECT_ID="${PROJECT_ID:-quill-cloud-proxy}"
REGION="${REGION:-us-central1}"
ARTIFACT_REPO="${ARTIFACT_REPO:-quill}"
IMAGE_NAME="${IMAGE_NAME:-enclave-multi}"
# GCP production is the direct multi-provider gateway. The older
# OpenRouter-only Dockerfile remains for compatibility experiments, but it
# must be selected explicitly with DOCKERFILE=...
DOCKERFILE="${DOCKERFILE:-Dockerfile.enclave.gcp.multi}"
SOURCE_REVISION=$(git -C "$REPO_ROOT" rev-parse HEAD)
COMMIT="$SOURCE_REVISION"
IMAGE_TAG="${IMAGE_TAG:-gcp-release-$COMMIT}"

ARTIFACT_HOST="$REGION-docker.pkg.dev"
IMAGE_REF="$ARTIFACT_HOST/$PROJECT_ID/$ARTIFACT_REPO/$IMAGE_NAME:$IMAGE_TAG"

log() { echo "[$(date +%H:%M:%S)] $*" >&2; }
gc() { gcloud --project "$PROJECT_ID" "$@"; }

[[ "$DOCKERFILE" == Dockerfile.enclave.gcp.multi ]] || { echo 'production requires the measured multi-provider recipe' >&2; exit 1; }
BUILD_EVIDENCE="${BUILD_EVIDENCE:-$(mktemp -d)/builds}"
(
  export DOCKER_CONFIG="$(mktemp -d)"
  trap 'rm -rf "$DOCKER_CONFIG"' EXIT
  gcloud auth print-access-token | docker login -u oauth2accesstoken --password-stdin "$ARTIFACT_HOST" >/dev/null
  python3 "$REPO_ROOT/tools/reproducible_build.py" release --plane gcp \
    --commit "$SOURCE_REVISION" --image "$IMAGE_REF" --output-dir "$BUILD_EVIDENCE"
)

IMAGE_DIGEST="$(gc artifacts docker images describe "$IMAGE_REF" --format='value(image_summary.digest)')"
if [[ -z "$IMAGE_DIGEST" ]]; then
  echo "ERROR: could not resolve image digest for $IMAGE_REF" >&2
  exit 1
fi

python3 "$REPO_ROOT/tools/write-trust-artifacts.py" \
  --out-dir "$REPO_ROOT/trust-page" \
  --commit "$COMMIT" \
  --image-reference "$IMAGE_REF" \
  --image-digest "$IMAGE_DIGEST" \
  --reproducible-build-record "$BUILD_EVIDENCE/1/reproduction.json"

cat <<EOF
GCP release ready.

Image reference: $IMAGE_REF
Image digest:    $IMAGE_DIGEST
Trust files:
  trust-page/image-digest-gcp.txt
  trust-page/accepted-image-digests-gcp.txt
  trust-page/image-reference-gcp.txt
  trust-page/accepted-image-references-gcp.txt
  trust-page/gcp-release.json
EOF
