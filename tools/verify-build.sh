#!/usr/bin/env bash
# verify-build.sh — third-party rebuild verification for the attested gateway.
#
# Proves the binary serving production traffic is built from this open-source
# repository, with no GCP account and no trust in us:
#
#   1. Fetch the published release record (commit + image ref + digest) from
#      the trust page.
#   2. Rebuild the enclave image locally at that commit, mirroring
#      tools/release-gcp.sh exactly (same Dockerfile, same digest-pinned Go
#      toolchain, linux/amd64).
#   3. Pull the published image BY DIGEST (the registry is read-public) and
#      compare the /quill-enclave binary byte-for-byte against your rebuild.
#
# Binary-level comparison — not image-digest comparison — is the robust
# check: the Go build is deterministic (pinned toolchain image digest,
# CGO_ENABLED=0, -trimpath, -ldflags '-s -w'), while OCI image digests can
# legitimately differ across builders because of layer-metadata timestamps.
#
# To close the loop to the RUNNING service, confirm the published digest is
# what production attests to (no account needed):
#
#   NONCE=$(openssl rand -hex 16)
#   curl -s "https://api.quillrouter.com/attestation?nonce=$NONCE" | \
#     python3 tools/verify-attestation.py --expect-digest "$(curl -s https://trust.trustedrouter.com/image-digest-gcp.txt)"
#
# Usage:
#   tools/verify-build.sh                 # verify the live release
#   TRUST_URL=https://... tools/verify-build.sh
#
# Requires: docker (buildx), curl, git, python3. Exit codes: 0 verified,
# 1 wrong checkout, 2 could not pull published image, 3 hash mismatch.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TRUST_URL="${TRUST_URL:-https://trust.trustedrouter.com/gcp-release.json}"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

say() { echo "[verify-build] $*" >&2; }

sha256_file() {
  python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$1"
}

json_field() {
  python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$1" "$2"
}

say "fetching published release record: $TRUST_URL"
curl -fsS "$TRUST_URL" -o "$WORKDIR/release.json"
COMMIT="$(json_field "$WORKDIR/release.json" source_commit)"
IMAGE_REF="$(json_field "$WORKDIR/release.json" image_reference)"
IMAGE_DIGEST="$(json_field "$WORKDIR/release.json" image_digest)"
IMAGE_REPO="${IMAGE_REF%%:*}" # strip the tag; we pull by digest
say "published commit:  $COMMIT"
say "published image:   $IMAGE_REF"
say "published digest:  $IMAGE_DIGEST"

HEAD_COMMIT="$(git -C "$REPO_ROOT" rev-parse --short=7 HEAD)"
case "$HEAD_COMMIT" in
  "$COMMIT"*) ;;
  *)
    say "ERROR: this checkout is $HEAD_COMMIT but the release was built from $COMMIT."
    say "       run:  git -C '$REPO_ROOT' checkout $COMMIT   then re-run this script"
    say "       (or verify in a scratch worktree: git worktree add /tmp/tr-verify $COMMIT)"
    exit 1
    ;;
esac
if [[ -n "$(git -C "$REPO_ROOT" status --porcelain -- enclave-go)" ]]; then
  say "WARNING: enclave-go/ has local modifications — you are verifying YOUR"
  say "         tree, not the pristine $COMMIT. Result may legitimately differ."
fi

LOCAL_TAG="tr-verify-local:$COMMIT"
say "rebuilding the enclave image locally (linux/amd64; first run can take several minutes)"
(
  cd "$REPO_ROOT/enclave-go"
  docker buildx build \
    --platform linux/amd64 \
    --file Dockerfile.enclave.gcp.multi \
    --tag "$LOCAL_TAG" \
    --load \
    . >&2
)

extract_binary() { # $1 = image ref, $2 = output path
  local cid
  cid="$(docker create --platform linux/amd64 "$1")"
  docker cp "$cid:/quill-enclave" "$2" >/dev/null
  docker rm -f "$cid" >/dev/null
}

extract_binary "$LOCAL_TAG" "$WORKDIR/local-quill-enclave"
LOCAL_SHA="$(sha256_file "$WORKDIR/local-quill-enclave")"
say "your rebuild   /quill-enclave sha256: $LOCAL_SHA"

say "pulling the published image by digest"
if ! docker pull --platform linux/amd64 "${IMAGE_REPO}@${IMAGE_DIGEST}" >/dev/null 2>&1; then
  say "could not pull ${IMAGE_REPO}@${IMAGE_DIGEST} from this machine."
  say "your rebuilt binary hash is above; compare it from any machine that can pull:"
  say "  docker pull ${IMAGE_REPO}@${IMAGE_DIGEST}"
  say "  cid=\$(docker create ${IMAGE_REPO}@${IMAGE_DIGEST}); docker cp \"\$cid:/quill-enclave\" /tmp/published-quill-enclave"
  say "  python3 -c 'import hashlib;print(hashlib.sha256(open(\"/tmp/published-quill-enclave\",\"rb\").read()).hexdigest())'"
  exit 2
fi
extract_binary "${IMAGE_REPO}@${IMAGE_DIGEST}" "$WORKDIR/published-quill-enclave"
PUBLISHED_SHA="$(sha256_file "$WORKDIR/published-quill-enclave")"
say "published      /quill-enclave sha256: $PUBLISHED_SHA"

if [[ "$LOCAL_SHA" == "$PUBLISHED_SHA" ]]; then
  echo "VERIFIED: the production attested-gateway binary is byte-identical to one"
  echo "built from commit $COMMIT of this repository on your own machine."
  echo "Final step — confirm production ATTESTS to this exact image digest:"
  echo "  curl -s \"https://api.quillrouter.com/attestation?nonce=\$(openssl rand -hex 16)\""
  echo "  (image_digest in the attestation document must equal $IMAGE_DIGEST)"
  exit 0
fi

echo "MISMATCH: locally rebuilt /quill-enclave differs from the published image."
echo "  local:     $LOCAL_SHA"
echo "  published: $PUBLISHED_SHA"
echo "Check: exact commit checked out, clean enclave-go/ tree, linux/amd64"
echo "platform, and that Docker actually used the digest-pinned golang base."
echo "If all of those hold, this is a finding — please report it."
exit 3
