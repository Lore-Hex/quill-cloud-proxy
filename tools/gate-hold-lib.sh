# shellcheck shell=bash
# Hold a gateway gate, rather than fail it, while the control plane may be the
# cause; fail closed at a hard deadline. Rules and reasons: tools/gate_hold.py.
#
#   source tools/gate-hold-lib.sh
#   gate_hold <pong|pre-dns|canary|discovery> <region> <command> [args...]
#   gate_status_presence <region> [hold|once]
#                                    prints present, missing or unreadable
#
# The gate command runs exactly as it would without this library, in its own
# process group so that a deadline or a stop can end it with its children.
#
# Time limits, all hard (an attempt in flight is killed at them):
#   TR_CP_HOLD_ATTEMPT_SECONDS  cap on any one attempt (0: none; default 0)
#   TR_CP_HOLD_MAX_SECONDS      per gate: how long one gate may hold, from its
#                               first inconclusive verdict (default 1800). The
#                               clock is per gate; a gate that passed leaves
#                               nothing behind for the next one.
#   TR_CP_HOLD_BUDGET_SECONDS   per job: total seconds held by all gates of all
#                               regions sharing TR_CP_HOLD_STATE_DIR (default
#                               2700). It keeps the job's worst case inside
#                               GitHub's six-hour limit. Concurrent holds both
#                               count, so a wave spends it twice as fast.
#   TR_CP_HOLD_SLEEP_SECONDS    pause between attempts while holding (60)
# A gate's worst case is therefore one capped attempt, its hold (at most the
# smaller of the two bounds), and two bounded journal reads plus one status
# read (GATE_HOLD_READ_SECONDS each, default 60; status.json 15).
#
# GATE_HOLD_STOP names a function that returns 0 when the gate must stop now
# (a peer region failed, the forward deadline passed). The attempt is then
# killed, the hold is recorded, and GATE_HOLD_ON_STOP runs (it may exit).

GATE_HOLD_TOOLS="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GATE_HOLD_TIMEOUT_STATUS=124

gate_hold_number() {
  # gate_hold_number <name> <default> [allow-zero]: print a validated setting.
  local name="$1" default="$2" zero="${3:-}" value
  value="${!name:-${default}}"
  if [[ "${value}" =~ ^[1-9][0-9]*$ ]] || { [ -n "${zero}" ] && [ "${value}" = 0 ]; }; then
    printf '%s\n' "${value}"
    return 0
  fi
  echo "::error::${name} must be a positive whole number of seconds, not '${value}'" >&2
  return 2
}

gate_hold_monitors() {
  local monitors="${WAIT_UP_MONITOR_REGIONS-us-central1,europe-west4}"
  if ! [[ "${monitors//[[:space:],]/}" =~ [a-z] ]]; then
    echo "::error::WAIT_UP_MONITOR_REGIONS names no monitor region" >&2
    return 2
  fi
  printf '%s\n' "${monitors}"
}

gate_hold_status_url() {
  # Defeat the status page's s-maxage and stale-while-revalidate caching, the
  # way tools/watchdog.py does.
  printf '%s?gate_hold=%s%s%s\n' "${STATUS_URL:-https://trustedrouter.com/status.json}" \
    "$(date +%s)" "$$" "${RANDOM}"
}

gate_hold_curl_status() {
  curl -sS --max-time 15 -H 'Cache-Control: no-cache' -H 'Pragma: no-cache' \
    "$(gate_hold_status_url)" 2>/dev/null
}

# gate_hold_run <deadline|""> <command...>: run a command in its own process
# group. Kill the group at the deadline (status 124) or when GATE_HOLD_STOP
# says so (then GATE_HOLD_ON_STOP runs; status 75 if it returns).
gate_hold_run() {
  local deadline="$1" pid status=0
  shift
  set -m
  "$@" &
  pid=$!
  set +m
  while kill -0 "${pid}" 2>/dev/null; do
    if { [ -n "${deadline}" ] && [ "$(date +%s)" -ge "${deadline}" ]; } \
        || { [ -n "${GATE_HOLD_STOP:-}" ] && "${GATE_HOLD_STOP}"; }; then
      if ! kill -0 "${pid}" 2>/dev/null; then
        break  # it finished on its own just now: its status stands
      fi
      kill -TERM -- "-${pid}" 2>/dev/null || kill -TERM "${pid}" 2>/dev/null || true
      for _ in 1 2 3 4 5 6 7 8 9 10; do
        kill -0 "${pid}" 2>/dev/null || break
        sleep 1
      done
      kill -KILL -- "-${pid}" 2>/dev/null || true
      wait "${pid}" 2>/dev/null || true
      if [ -n "${deadline}" ] && [ "$(date +%s)" -ge "${deadline}" ]; then
        return "${GATE_HOLD_TIMEOUT_STATUS}"
      fi
      return 75
    fi
    sleep 0.2
  done
  wait "${pid}" || status=$?
  return "${status}"
}

gate_hold_min() {
  local best="" value
  for value in "$@"; do
    [ -n "${value}" ] || continue
    if [ -z "${best}" ] || [ "${value}" -lt "${best}" ]; then best="${value}"; fi
  done
  printf '%s\n' "${best}"
}

# Job budget bookkeeping. held-<region> lists finished holds in seconds;
# holding-<region> holds the start of the region's open hold (a region runs one
# gate at a time). Any write that fails makes the caller fail closed.
gate_hold_spent() {
  local dir="$1" now total=0 file value
  now="$(date +%s)"
  for file in "${dir}"/held-*; do
    [ -f "${file}" ] || continue
    while IFS= read -r value; do
      [[ "${value}" =~ ^[0-9]+$ ]] && total=$((total + value))
    done < "${file}"
  done
  for file in "${dir}"/holding-*; do
    [ -f "${file}" ] || continue
    value="$(cat "${file}" 2>/dev/null || true)"
    [[ "${value}" =~ ^[0-9]+$ ]] && total=$((total + now - value))
  done
  printf '%s\n' "${total}"
}

gate_hold_open() {
  local dir="$1" region="$2"
  mkdir -p "${dir}" 2>/dev/null && printf '%s\n' "$(date +%s)" > "${dir}/holding-${region}" 2>/dev/null
}

gate_hold_close() {
  local dir="$1" region="$2" started
  [ -f "${dir}/holding-${region}" ] || return 0
  started="$(cat "${dir}/holding-${region}" 2>/dev/null || true)"
  if [[ "${started}" =~ ^[0-9]+$ ]]; then
    printf '%s\n' "$(( $(date +%s) - started ))" >> "${dir}/held-${region}" || return 1
  fi
  rm -f "${dir}/holding-${region}"
}

gate_hold_lanes() {
  # gate_hold_lanes <file> <deadline|"">: a bounded read of the lane state.
  local out="$1" deadline="$2" read_seconds
  read_seconds="$(gate_hold_number GATE_HOLD_READ_SECONDS 60)" || return 2
  deadline="$(gate_hold_min "$(( $(date +%s) + read_seconds ))" "${deadline}")"
  GATE_HOLD_STOP="" gate_hold_run "${deadline}" \
    gate_hold_write "${out}" python3 "${GATE_HOLD_TOOLS}/cloud-rollout.py" lanes --cloud gcp \
    || : > "${out}"
}

gate_hold_write() {
  local out="$1"
  shift
  "$@" > "${out}" 2>/dev/null
}

gate_hold() {
  local kind="$1" region="$2" max pause cap budget monitors state own_state=0 work
  local since attempt_deadline cut_deadline hold_deadline="" status=1 decision remaining
  local status_after_pause
  shift 2
  max="$(gate_hold_number TR_CP_HOLD_MAX_SECONDS 1800)" || return 2
  pause="$(gate_hold_number TR_CP_HOLD_SLEEP_SECONDS 60)" || return 2
  cap="$(gate_hold_number TR_CP_HOLD_ATTEMPT_SECONDS 0 zero)" || return 2
  budget="$(gate_hold_number TR_CP_HOLD_BUDGET_SECONDS 2700)" || return 2
  monitors="$(gate_hold_monitors)" || return 2
  state="${TR_CP_HOLD_STATE_DIR:-}"
  if [ -z "${state}" ]; then
    state="$(mktemp -d "${TMPDIR:-/tmp}/tr-cp-hold-XXXXXX")" || return 1
    own_state=1
  fi
  work="$(mktemp -d "${TMPDIR:-/tmp}/tr-gate-hold-XXXXXX")" || return 1
  while true; do
    since="$(date +%s)"
    attempt_deadline=""
    if [ "${cap}" -gt 0 ]; then attempt_deadline=$((since + cap)); fi
    # While holding, the gate's own deadline and the job budget cut the attempt.
    cut_deadline=""
    if [ -n "${hold_deadline}" ]; then
      remaining=$((budget - $(gate_hold_spent "${state}")))
      cut_deadline="$(gate_hold_min "${hold_deadline}" "$((since + remaining))")"
      if [ "${since}" -ge "${cut_deadline}" ]; then
        # Never start an attempt that has no time left.
        echo "::error::${region}: ${kind} gate still inconclusive when its hold bound or the job's ran out; failing closed" >&2
        gate_hold_close "${state}" "${region}" || true
        rm -rf "${work}"
        [ "${own_state}" -eq 1 ] && rm -rf "${state}"
        [ "${status}" -ne 0 ] && return "${status}"
        return 1
      fi
    fi
    attempt_deadline="$(gate_hold_min "${attempt_deadline}" "${cut_deadline}")"
    gate_hold_lanes "${work}/before.json" "${attempt_deadline}"
    status=0
    # The PONG gate and the classifier judge the same window.
    export WAIT_UP_STARTED_AT="${since}"
    gate_hold_run "${attempt_deadline}" "$@" || status=$?
    unset WAIT_UP_STARTED_AT
    if [ "${status}" -eq 75 ] && [ -n "${GATE_HOLD_STOP:-}" ]; then
      gate_hold_close "${state}" "${region}" || true
      rm -rf "${work}"
      [ "${own_state}" -eq 1 ] && rm -rf "${state}"
      "${GATE_HOLD_ON_STOP:-:}"
      return 75
    fi
    if [ -n "${cut_deadline}" ] && [ "${status}" -eq "${GATE_HOLD_TIMEOUT_STATUS}" ] \
        && [ "$(date +%s)" -ge "${cut_deadline}" ]; then
      echo "::error::${region}: ${kind} gate still inconclusive at its hold deadline; the attempt in flight was stopped; failing closed" >&2
      gate_hold_close "${state}" "${region}" || true
      rm -rf "${work}"
      [ "${own_state}" -eq 1 ] && rm -rf "${state}"
      return "${status}"
    fi
    if [ "${status}" -eq 0 ] && [ "${kind}" != canary ]; then
      gate_hold_close "${state}" "${region}" || true
      rm -rf "${work}"
      [ "${own_state}" -eq 1 ] && rm -rf "${state}"
      return 0
    fi
    gate_hold_lanes "${work}/after.json" "${cut_deadline}"
    gate_hold_curl_status > "${work}/status.json" || true
    decision="$(WAIT_UP_MONITOR_REGIONS="${monitors}" python3 "${GATE_HOLD_TOOLS}/gate_hold.py" decide \
      --kind "${kind}" --region "${region}" --status "${status}" --since "${since}" \
      --before "${work}/before.json" --after "${work}/after.json" \
      --status-json "${work}/status.json")" || decision=""
    case "${decision}" in
      pass)
        gate_hold_close "${state}" "${region}" || true
        rm -rf "${work}"
        [ "${own_state}" -eq 1 ] && rm -rf "${state}"
        return 0 ;;
      gateway:*)
        echo "${region}: ${kind} gate failed; attributed to the gateway: ${decision#gateway:}" >&2
        gate_hold_close "${state}" "${region}" || true
        rm -rf "${work}"
        [ "${own_state}" -eq 1 ] && rm -rf "${state}"
        [ "${status}" -ne 0 ] && return "${status}"
        return 1 ;;
      inconclusive:*)
        if [ -z "${hold_deadline}" ]; then
          if ! gate_hold_open "${state}" "${region}"; then
            echo "::error::${region}: cannot record the control-plane hold in ${state}; failing closed" >&2
            rm -rf "${work}"
            [ "${status}" -ne 0 ] && return "${status}"
            return 1
          fi
          hold_deadline=$(( $(date +%s) + max ))
        fi
        status_after_pause=0
        gate_hold_pause "${region}" "${kind} gate inconclusive: ${decision#inconclusive:}" \
          "${hold_deadline}" "${state}" "${budget}" "${pause}" "${max}" || status_after_pause=$?
        if [ "${status_after_pause}" -eq 0 ]; then
          continue
        fi
        gate_hold_close "${state}" "${region}" || true
        rm -rf "${work}"
        [ "${own_state}" -eq 1 ] && rm -rf "${state}"
        if [ "${status_after_pause}" -eq 75 ]; then
          "${GATE_HOLD_ON_STOP:-:}"
          return 75
        fi
        [ "${status}" -ne 0 ] && return "${status}"
        return 1 ;;
      *)
        gate_hold_close "${state}" "${region}" || true
        rm -rf "${work}"
        [ "${own_state}" -eq 1 ] && rm -rf "${state}"
        if [ "${status}" -eq 0 ]; then
          # Only a canary pass reaches here; without a decision it cannot be
          # confirmed against a moving control plane.
          echo "::error::${region}: the classifier could not decide a ${kind} pass; failing closed" >&2
          return 1
        fi
        return "${status}" ;;
    esac
  done
}

# gate_hold_pause <region> <reason> <deadline> <state> <budget> <pause> <max>:
# 0 to run the gate again, 1 when the bound is spent, 75 when told to stop.
gate_hold_pause() {
  local region="$1" reason="$2" deadline="$3" state="$4" budget="$5" pause="$6" max="$7"
  local now spent
  now="$(date +%s)"
  spent="$(gate_hold_spent "${state}")"
  if [ "${now}" -ge "${deadline}" ] || [ "${spent}" -ge "${budget}" ]; then
    echo "::error::${region}: ${reason}; this gate's hold bound (${max}s) or the job's (${budget}s, ${spent}s spent) is reached; failing closed" >&2
    return 1
  fi
  echo "::warning::${region}: ${reason}; the region stays out of canonical DNS and the gate re-runs in ${pause}s (hold ends at $(( deadline - now ))s from now; job budget ${spent}s of ${budget}s)" >&2
  for _ in $(seq 1 "${pause}"); do
    if [ -n "${GATE_HOLD_STOP:-}" ] && "${GATE_HOLD_STOP}"; then return 75; fi
    [ "$(date +%s)" -ge "${deadline}" ] && break
    sleep 1
  done
  return 0
}

# An unreadable status page is the control plane's failure: re-read it within
# the hold bounds instead of failing a healthy region at once. A readable page
# that does not list the region is reported as missing, as before. `once`
# reads a single time (a first deployment has no synthetic gate to wait for).
# Its hold counts against the job budget like any gate's.
gate_status_presence() {
  local region="$1" mode="${2:-hold}" body max pause budget state deadline="" result
  max="$(gate_hold_number TR_CP_HOLD_MAX_SECONDS 1800)" || { echo unreadable; return 0; }
  pause="$(gate_hold_number TR_CP_HOLD_SLEEP_SECONDS 60)" || { echo unreadable; return 0; }
  budget="$(gate_hold_number TR_CP_HOLD_BUDGET_SECONDS 2700)" || { echo unreadable; return 0; }
  state="${TR_CP_HOLD_STATE_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/tr-cp-hold-XXXXXX")}"
  while true; do
    if body="$(curl -fsS --max-time 15 -H 'Cache-Control: no-cache' -H 'Pragma: no-cache' \
          "$(gate_hold_status_url)")" \
        && jq -e 'type == "object"' >/dev/null 2>&1 <<<"${body}"; then
      if jq -e --arg region "${region}" \
          '[.. | objects | select(.target_region? == $region)] | length > 0' \
          >/dev/null <<<"${body}"; then
        result=present
      else
        result=missing
      fi
      break
    fi
    result=unreadable
    [ "${mode}" = once ] && break
    if [ -z "${deadline}" ]; then
      if ! gate_hold_open "${state}" "${region}"; then
        echo "::error::${region}: cannot record the control-plane hold in ${state}; failing closed" >&2
        break
      fi
      deadline=$(( $(date +%s) + max ))
    fi
    gate_hold_pause "${region}" "status.json is unreadable" "${deadline}" \
      "${state}" "${budget}" "${pause}" "${max}" || break
  done
  gate_hold_close "${state}" "${region}" || true
  echo "${result}"
}
