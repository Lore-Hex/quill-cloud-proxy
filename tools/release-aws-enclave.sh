#!/usr/bin/env bash
# Publish once in protected-main CI. This command never rolls the fleet.
set -euo pipefail
cd "$(dirname "$0")/.."

case "${1:-}" in
  --verify-only)
    exec python3 tools/capture-plane-measurements.py --plane aws --check-published
    ;;
  --apply)
    if [ -n "$(git status --porcelain)" ]; then
      echo "Refusing release dispatch from a dirty worktree." >&2
      exit 1
    fi
    expected="$(git rev-parse HEAD)"
    current="$(gh api repos/Lore-Hex/quill-cloud-proxy/commits/main --jq .sha)"
    if [ "$expected" != "$current" ]; then
      echo "Use a clean checkout of current merged main before dispatch." >&2
      exit 1
    fi
    gh workflow run publish-aws-eif.yml --repo Lore-Hex/quill-cloud-proxy --ref main
    echo "CI publication requested, not deployed. Wait for the workflow and verify its exact source commit."
    ;;
  "")
    echo "Dry run: --apply dispatches publish-aws-eif.yml on protected main. No local image publication."
    ;;
  *) echo "Usage: $0 [--apply|--verify-only]" >&2; exit 2 ;;
esac

echo "Next: verify the signed CI manifest, stage old+new public admission, wait for trust publication,"
echo "then widen runtime pins before starting an isolated candidate. Candidate PCR0 must equal CI PCR0."
echo "Follow docs/runbook-aws-enclave-release.md; keep AWS's rollout reservation throughout mutations."
