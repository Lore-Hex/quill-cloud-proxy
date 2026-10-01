#!/usr/bin/env bash
# Phased gateway tools require an outer cloud reservation. They must not free
# it between bind, deploy, attest, narrow and final regional verification.
require_cloud_rollout() {
  local cloud="${1:?cloud required}" directory
  directory="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  if [ -z "${TR_DEPLOY_MUTEX_OPERATION:-}" ]; then
    echo "Missing ${cloud} reservation. Run tools/cloud-rollout.py acquire --cloud ${cloud} and export its fence before production mutations." >&2
    return 1
  fi
  python3 "${directory}/cloud-rollout.py" assert --cloud "$cloud"
}
