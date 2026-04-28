#!/usr/bin/env bash
# Build the enclave image file (EIF) and capture its PCR0.
#
# Run this on a Nitro-capable EC2 instance (or any host with nitro-cli +
# docker installed). Invoked from CI on a self-hosted Nitro runner, or
# manually by the operator on the deployment host.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
TAG="${TAG:-quill-enclave:$(git -C "$HERE/.." rev-parse --short HEAD)}"

cd "$HERE"
docker build --no-cache -t "$TAG" -f Dockerfile.enclave .

OUT="$HERE/quill.eif"
sudo nitro-cli build-enclave \
  --docker-uri "$TAG" \
  --output-file "$OUT" \
  > "$HERE/eif-measurements.json"

PCR0=$(jq -r '.Measurements.PCR0' "$HERE/eif-measurements.json")
echo "PCR0: $PCR0"
echo "$PCR0" > "$HERE/../trust-page/pcr0.txt"
