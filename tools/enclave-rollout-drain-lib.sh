#!/usr/bin/env bash
# Shared policy for restoring a region's pre-rollout canonical drain state.

rollout_restore_drain_operation() {
  local region="${1-}"
  local prior_state="${2-}"
  local prior_origin="${3-}"

  if [ "${prior_state}" = "drained" ] && \
      [[ "${prior_origin}" =~ ^rollout:[1-9][0-9]*$ ]]; then
    echo "::warning::${region} was drained by stale ${prior_origin}; restoring active and dropping the stale rollout drain" >&2
    printf '%s\n' clear
    return 0
  fi

  case "${prior_state}:${prior_origin}" in
    active:none)
      printf '%s\n' clear
      ;;
    drained:operator)
      printf '%s\n' set
      ;;
    *)
      echo "${region}: invalid pre-rollout drain state/origin '${prior_state}/${prior_origin}'; refusing to mutate DNS" >&2
      return 2
      ;;
  esac
}
