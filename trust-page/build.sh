#!/usr/bin/env bash
# Publishes the static trust page to S3.
#
# Inputs (from CI environment or operator shell):
#   - QUILL_TRUST_BUCKET     S3 bucket backing trust.quill.lorehex.co
#   - QUILL_PCR0             current published PCR0 (32-byte hex from build-eif.sh)
#
# Behavior: writes pcr0.txt with the current value, syncs the trust-page/
# directory to s3://$QUILL_TRUST_BUCKET/, sets cache-control to 60s.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"

if [[ -z "${QUILL_TRUST_BUCKET:-}" ]]; then
  echo "QUILL_TRUST_BUCKET is required" >&2
  exit 2
fi

if [[ -n "${QUILL_PCR0:-}" ]]; then
  echo "$QUILL_PCR0" > "$HERE/pcr0.txt"
fi

aws s3 sync "$HERE" "s3://$QUILL_TRUST_BUCKET/" \
  --exclude "build.sh" \
  --cache-control "max-age=60, public" \
  --content-type "text/html; charset=utf-8"

# Override content-type for pcr0.txt (it's plain text, not HTML).
aws s3 cp "$HERE/pcr0.txt" "s3://$QUILL_TRUST_BUCKET/pcr0.txt" \
  --cache-control "max-age=60, public" \
  --content-type "text/plain; charset=utf-8"

echo "trust page published"
