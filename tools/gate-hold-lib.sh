# shellcheck shell=bash
# Hold a gateway gate, rather than fail it, while the control plane may be the
# cause; fail closed after a bound. Rules and reasons: tools/gate_hold.py.
#
#   source tools/gate-hold-lib.sh
#   gate_hold <pong|pre-dns|canary|discovery> <region> <command> [args...]
#   gate_status_presence <region> [hold|once]
#                                    prints present, missing or unreadable
#
# The gate command runs exactly as it would without this library. It must be
# an external command or a function that does not rely on errexit (it runs in
# an `||` context). Set GATE_HOLD_BETWEEN to a function name to run it once a
# second while holding (a wave uses this to stop at a peer's failure).
#
# The hold clock is per region and shared by every gate of that region:
# TR_CP_HOLD_MAX_SECONDS (default 1800) bounds the region's total hold.

GATE_HOLD_TOOLS="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

gate_hold_clock_file() {
  printf '%s/cp-hold-started-%s\n' \
    "${TR_CP_HOLD_STATE_DIR:-${TR_ROLLOUT_STATE_DIR:-${TMPDIR:-/tmp}}}" "$1"
}

# gate_hold_wait <region> <reason>: sleep and return 0 while the region may
# still be held; return 1 once its hold bound is spent.
gate_hold_wait() {
  local region="$1" reason="$2" file now started held
  local max="${TR_CP_HOLD_MAX_SECONDS:-1800}" pause="${TR_CP_HOLD_SLEEP_SECONDS:-60}"
  file="$(gate_hold_clock_file "${region}")"
  now="$(date +%s)"
  started="$(cat "${file}" 2>/dev/null || true)"
  if ! [[ "${started}" =~ ^[0-9]+$ ]]; then
    started="${now}"
    mkdir -p "$(dirname "${file}")"
    printf '%s\n' "${started}" > "${file}"
  fi
  held=$((now - started))
  if [ "${held}" -ge "${max}" ]; then
    echo "::error::${region}: ${reason}; held ${held}s of ${max}s; failing closed" >&2
    return 1
  fi
  echo "::warning::${region}: ${reason}; the region stays out of canonical DNS and is re-checked in ${pause}s (${held}s of ${max}s held)" >&2
  for _ in $(seq 1 "${pause}"); do
    if [ -n "${GATE_HOLD_BETWEEN:-}" ]; then "${GATE_HOLD_BETWEEN}"; fi
    sleep 1
  done
  return 0
}

gate_hold_status_json() {
  curl -sS --max-time 15 "${STATUS_URL:-https://trustedrouter.com/status.json}" 2>/dev/null || true
}

gate_hold() {
  local kind="$1" region="$2" since status decision dir
  shift 2
  dir="$(mktemp -d "${TMPDIR:-/tmp}/tr-gate-hold-XXXXXX")"
  while true; do
    since="$(date +%s)"
    python3 "${GATE_HOLD_TOOLS}/cloud-rollout.py" lanes --cloud gcp > "${dir}/before.json" 2>/dev/null || true
    status=0
    # The PONG gate and the classifier judge the same window.
    export WAIT_UP_STARTED_AT="${since}"
    "$@" || status=$?
    unset WAIT_UP_STARTED_AT
    python3 "${GATE_HOLD_TOOLS}/cloud-rollout.py" lanes --cloud gcp > "${dir}/after.json" 2>/dev/null || true
    if [ "${status}" -ne 0 ] || [ "${kind}" = canary ]; then
      gate_hold_status_json > "${dir}/status.json"
    else
      : > "${dir}/status.json"
    fi
    decision="$(python3 "${GATE_HOLD_TOOLS}/gate_hold.py" decide \
      --kind "${kind}" --region "${region}" --status "${status}" --since "${since}" \
      --before "${dir}/before.json" --after "${dir}/after.json" \
      --status-json "${dir}/status.json")" || decision=""
    case "${decision}" in
      pass)
        rm -rf "${dir}"
        return 0 ;;
      inconclusive:*)
        if gate_hold_wait "${region}" "${kind} gate inconclusive: ${decision#inconclusive:}"; then
          continue
        fi
        rm -rf "${dir}"
        if [ "${status}" -ne 0 ]; then return "${status}"; fi
        return 1 ;;
      gateway:*)
        echo "${region}: ${kind} gate failed; attributed to the gateway: ${decision#gateway:}" >&2
        rm -rf "${dir}"
        return "${status}" ;;
      *)
        # No decision (the classifier could not run): the gate's own verdict
        # stands, exactly as it did before this library existed.
        rm -rf "${dir}"
        return "${status}" ;;
    esac
  done
}

# An unreadable status page is the control plane's failure: re-read it within
# the hold bound instead of failing a healthy region at once. A readable page
# that does not list the region is reported as missing, as before. `once`
# reads a single time (a first deployment has no synthetic gate to wait for).
gate_status_presence() {
  local region="$1" mode="${2:-hold}" body
  while true; do
    if body="$(curl -fsS --max-time 15 "${STATUS_URL:-https://trustedrouter.com/status.json}")" \
        && jq -e 'type == "object"' >/dev/null 2>&1 <<<"${body}"; then
      if jq -e --arg region "${region}" \
          '[.. | objects | select(.target_region? == $region)] | length > 0' \
          >/dev/null <<<"${body}"; then
        echo present
      else
        echo missing
      fi
      return 0
    fi
    if [ "${mode}" = once ] || ! gate_hold_wait "${region}" "status.json is unreadable"; then
      echo unreadable
      return 0
    fi
  done
}
