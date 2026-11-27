#!/usr/bin/env bash
# Nitro measures the application ramdisk, including each file's mtime.
set -euo pipefail
image='moby/buildkit:v0.34.1@sha256:99368f3e46177c6405b9740e4461d91cee004128daeecca78d4ceac50ec1da5c'
builder="$(docker buildx create --driver docker-container --driver-opt "image=$image")"
trap 'docker buildx rm "$builder" >&2' EXIT
docker buildx build --builder "$builder" --no-cache --provenance=false --sbom=false \
  --build-arg SOURCE_DATE_EPOCH=0 --output type=docker,rewrite-timestamp=true "$@"
