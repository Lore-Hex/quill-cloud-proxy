#!/usr/bin/env bash
# Rebuild a single-platform release on an isolated native x86-64 Linux builder.
# The build input is a committed enclave-go tree, even on a dirty checkout.
set -euo pipefail
plane=${1:?gcp or azure} revision=${2:?full git commit} out=${3:?new output directory}
case "$plane" in
  gcp|azure) ;;
  *) echo "expected gcp or azure" >&2; exit 2 ;;
esac
[[ "$revision" =~ ^[a-f0-9]{40}$ && "$(git rev-parse --verify "${revision}^{commit}")" == "$revision" ]]
[[ "$(docker info --format '{{.OSType}}/{{.Architecture}}')" == linux/x86_64 ]]
mkdir "$out"
out=$(cd "$out" && pwd)
engine='moby/buildkit:v0.34.1@sha256:99368f3e46177c6405b9740e4461d91cee004128daeecca78d4ceac50ec1da5c'
builder=$(docker buildx create --driver docker-container --driver-opt "image=$engine")
trap 'docker buildx rm "$builder" >&2' EXIT
git archive "${revision}:enclave-go" | docker buildx build --builder "$builder" \
  --platform linux/amd64 --file "Dockerfile.enclave.${plane}.multi" --no-cache \
  --build-arg "SOURCE_REVISION=$revision" --build-arg SOURCE_DATE_EPOCH=0 \
  --provenance=false --sbom=false --metadata-file "$out/build.json" \
  --output "type=oci,dest=$out/image.tar,oci-mediatypes=true,compression=gzip,compression-level=6,force-compression=true,rewrite-timestamp=true" -
python3 "$(dirname "$0")/verify_release_oci.py" "$out/image.tar" "$out/build.json" "$plane" "$revision" > "$out/record.json"
