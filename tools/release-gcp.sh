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
IMAGE_NAME="${IMAGE_NAME:-enclave-openrouter}"
# GCP production is the direct multi-provider gateway. The older
# OpenRouter-only Dockerfile remains for compatibility experiments, but it
# must be selected explicitly with DOCKERFILE=...
DOCKERFILE="${DOCKERFILE:-Dockerfile.enclave.gcp.multi}"
COMMIT="$(git -C "$REPO_ROOT" rev-parse --short HEAD)"
IMAGE_TAG="${IMAGE_TAG:-gcp-release-$COMMIT}"

ARTIFACT_HOST="$REGION-docker.pkg.dev"
IMAGE_REF="$ARTIFACT_HOST/$PROJECT_ID/$ARTIFACT_REPO/$IMAGE_NAME:$IMAGE_TAG"

log() { echo "[$(date +%H:%M:%S)] $*" >&2; }
gc() { gcloud --project "$PROJECT_ID" "$@"; }

log "configuring docker auth for $ARTIFACT_HOST"
gcloud auth configure-docker "$ARTIFACT_HOST" --quiet >/dev/null

if gc artifacts docker images describe "$IMAGE_REF" >/dev/null 2>&1; then
  log "image already exists: $IMAGE_REF"
else
  log "building and pushing $IMAGE_REF"
  (
    cd "$REPO_ROOT/enclave-go"
    docker buildx build \
      --platform linux/amd64 \
      --file "$DOCKERFILE" \
    --build-arg "SOURCE_REVISION=$(git -C "$REPO_ROOT" rev-parse HEAD)" \
      --tag "$IMAGE_REF" \
      --push \
      .
  )
fi

IMAGE_DIGEST="$(gc artifacts docker images describe "$IMAGE_REF" --format='value(image_summary.digest)')"
if [[ -z "$IMAGE_DIGEST" ]]; then
  echo "ERROR: could not resolve image digest for $IMAGE_REF" >&2
  exit 1
fi

python3 "$REPO_ROOT/tools/write-trust-artifacts.py" \
  --out-dir "$REPO_ROOT/trust-page" \
  --commit "$COMMIT" \
  --image-reference "$IMAGE_REF" \
  --image-digest "$IMAGE_DIGEST"

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
