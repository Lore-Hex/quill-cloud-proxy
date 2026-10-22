#!/usr/bin/env bash
# Verify the signed source mapping, rebuild the COMPLETE image, compare digests.
# Legacy releases fail explicitly; binary-only comparison is not whole-image proof.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="${OUTPUT_DIR:-$(mktemp -d)/rebuild}"
exec python3 "$REPO_ROOT/tools/reproducible_build.py" verify \
  --trust-url "${TRUST_URL:-https://trust.trustedrouter.com/trust/gcp-release.json}" \
  --output-dir "$OUTPUT_DIR"
