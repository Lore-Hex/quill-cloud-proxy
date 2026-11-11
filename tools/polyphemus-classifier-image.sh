#!/usr/bin/env bash
# Prints the digest-pinned reference of the Polyphemus classifier image for
# the checked-out source, building and pushing it first only if missing.
#
#   tools/polyphemus-classifier-image.sh             # resolve; fail if missing
#   tools/polyphemus-classifier-image.sh --ensure    # build via Cloud Build if missing
#
# The tag is a hash of the committed enclave-go/polyphemus-classifier tree and
# enclave-go/Dockerfile.polyphemus-classifier, so it changes exactly when the
# classifier's inputs do. Normal deploys only pay for one registry lookup.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/.." && pwd)"
PROJECT_ID="${PROJECT_ID:-quill-cloud-proxy}"
REGION="${REGION:-us-central1}"
ARTIFACT_REPO="${ARTIFACT_REPO:-quill}"

log() { echo "[polyphemus-classifier] $*" >&2; }

if [[ -n "$(git -C "$REPO_ROOT" status --porcelain -- enclave-go/polyphemus-classifier enclave-go/Dockerfile.polyphemus-classifier)" ]]; then
  log "ERROR: uncommitted classifier changes; the tag hashes committed source only"
  exit 1
fi
TREE="$(git -C "$REPO_ROOT" rev-parse HEAD:enclave-go/polyphemus-classifier)"
DOCKERFILE_BLOB="$(git -C "$REPO_ROOT" rev-parse HEAD:enclave-go/Dockerfile.polyphemus-classifier)"
SOURCE_HASH="$(printf '%s\n%s\n' "$TREE" "$DOCKERFILE_BLOB" | git hash-object --stdin | cut -c1-24)"
IMAGE="$REGION-docker.pkg.dev/$PROJECT_ID/$ARTIFACT_REPO/polyphemus-classifier:src-$SOURCE_HASH"

digest() {
  gcloud artifacts docker images describe "$IMAGE" --project "$PROJECT_ID" \
    --format='value(image_summary.digest)' 2>/dev/null || true
}

DIGEST="$(digest)"
if [[ -z "$DIGEST" ]]; then
  if [[ "${1:-}" != "--ensure" ]]; then
    log "ERROR: $IMAGE does not exist; rerun with --ensure to build it"
    exit 1
  fi
  log "building $IMAGE (classifier source changed)"
  config="$(mktemp)"
  cat > "$config" <<'EOF'
steps:
  - name: gcr.io/cloud-builders/docker
    entrypoint: bash
    args:
      - -c
      - |
        set -e
        docker buildx create --use --name=classifier-builder
        docker buildx build --platform=linux/amd64 \
          --file=Dockerfile.polyphemus-classifier \
          --tag=${_IMAGE} \
          --push \
          .
options:
  machineType: E2_HIGHCPU_8
timeout: 3600s
EOF
  gcloud builds submit "$REPO_ROOT/enclave-go" \
    --config="$config" \
    --substitutions="_IMAGE=$IMAGE" \
    --project="$PROJECT_ID" \
    --region="$REGION" >&2
  rm -f "$config"
  DIGEST="$(digest)"
  if [[ -z "$DIGEST" ]]; then
    log "ERROR: built $IMAGE but could not resolve its digest"
    exit 1
  fi
fi
log "using $IMAGE@$DIGEST"
echo "${IMAGE%:*}@$DIGEST"
