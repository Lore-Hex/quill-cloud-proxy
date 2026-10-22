#!/bin/sh
# Internal worker: /workspace must be an archive of one committed Git tree.
# Invoked locally in the pinned client container or on an isolated Cloud Build VM.
set -eu
plane=$1 revision=$2 epoch=$3 output=$4
shift 4
case "$plane" in
  gcp) dockerfile=Dockerfile.enclave.gcp.multi ;;
  aws) dockerfile=Dockerfile.enclave ;;
  azure) dockerfile=Dockerfile.enclave.azure.multi ;;
  *) echo 'unsupported build plane' >&2; exit 1 ;;
esac
case "$revision" in *[!0-9a-f]*|'') exit 1 ;; esac
[ "${#revision}" = 40 ] || exit 1
case "$epoch" in *[!0-9]*|'') exit 1 ;; esac
. /workspace/tools/reproducible-build.env
builder="tr-repro-$(cat /proc/sys/kernel/random/uuid)"
trap 'docker buildx rm -f "$builder" >/dev/null 2>&1 || true' EXIT HUP INT TERM
docker buildx create --name "$builder" --driver docker-container \
  --driver-opt "image=$REPRO_BUILDKIT" >/dev/null
# No shared cache, no host toolchain, no build-time attestations in the measured
# image. BuildKit provenance is retained outside the image in build-metadata.json.
export BUILDX_METADATA_PROVENANCE=max
docker buildx build --builder "$builder" --no-cache --platform linux/amd64 \
  --file "/workspace/enclave-go/$dockerfile" \
  --build-arg "SOURCE_REVISION=$revision" --build-arg "SOURCE_DATE_EPOCH=$epoch" \
  --provenance=false --sbom=false \
  --metadata-file /output/build-metadata.json \
  --output "$output,oci-mediatypes=true,compression=gzip,compression-level=6,force-compression=true,rewrite-timestamp=true" \
  "$@" /workspace/enclave-go
