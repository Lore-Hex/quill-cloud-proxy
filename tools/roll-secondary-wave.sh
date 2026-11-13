#!/usr/bin/env bash
# Roll several secondary gateway regions at once, one worker per region.
#
#   tools/roll-secondary-wave.sh -- <10 roll-secondary-region.sh args> [-- <10 args> ...]
#
# Each worker is tools/roll-secondary-region.sh, with every per-region gate
# (drain, stable, attested, per-instance verify, synthetic wait, per-region
# watchdog) and its own automatic recovery. In a wave it also:
#
#   * shares one lock for the persistent-drain read-modify-write and DNS
#     reconciles, including recoveries, so concurrent regions cannot lose each
#     other's drain updates;
#   * shares an abort file: the first region to fail records itself there, and
#     no peer promotes afterwards. A peer still before promotion stops at
#     once (its MIG wait and read-only waits are cut short), restores its
#     previous template and drain state, and exits 75; a peer not yet started
#     is left untouched; a peer that already promoted keeps the release.
#     Unlike the serial rollout, this means a region can be rolled back while
#     healthy: if US East fails before Europe promotes, Europe is restored too.
#   * stops its rollout steps at a forward-only deadline
#     (TR_SECONDARY_WORKER_TIMEOUT seconds from the wave start, exit 76).
#     Recovery is never bounded by it and ignores TERM, INT and SIGPIPE once
#     it starts; only the step's own timeout or a runner SIGKILL can stop it.
#
# Each worker writes to its own log file, which this script tails with a
# "[region]" prefix, so a dead reader can never SIGPIPE a worker. A final
# per-region verdict attributes each result to its region. Exit 0 only if
# every region promoted. On a GitHub cancel or step timeout the runner kills
# the whole process tree within seconds; a region it kills mid-rollout keeps
# its drain (the finalizer refuses to re-add a region left at "started").
set -euo pipefail

usage() {
  echo "usage: $0 -- <region> <mig> <instance-filter> <short-name> <api-hosts> <previous-template> <machine-type> <confidential-type> <active|drained> <none|operator|rollout:run-id> [-- ...]" >&2
  exit 2
}

[ "$#" -ge 11 ] && [ "$1" = "--" ] || usage
# Ten worker arguments per region, stored flat: region i is all_args[10i..10i+9].
all_args=()
regions=()
while [ "$#" -gt 0 ]; do
  [ "$1" = "--" ] || usage
  shift
  [ "$#" -ge 10 ] || usage
  for seen in ${regions[@]+"${regions[@]}"}; do
    if [ "${seen}" = "$1" ]; then
      echo "region $1 appears twice in one wave" >&2
      exit 2
    fi
  done
  regions+=("$1")
  all_args+=("$1" "$2" "$3" "$4" "$5" "$6" "$7" "$8" "$9" "${10}")
  shift 10
done

# Stage D flags are per region. A bare flag would apply to every region in the
# wave, so it is refused; each region reads <REGION_KEY>_<FLAG> instead
# (europe-west4 -> EUROPE_WEST4_QUILL_USAGE_HEARTBEAT), which must be on or off.
stage_d_flags=(QUILL_USAGE_HEARTBEAT QUILL_TERMINATE_AT_CAP)
for flag in "${stage_d_flags[@]}"; do
  if [ -n "${!flag+set}" ]; then
    echo "${flag} is set for the whole wave; set it per region (<REGION_KEY>_${flag})" >&2
    exit 2
  fi
done
region_key() {
  printf '%s' "$1" | tr 'a-z-' 'A-Z_'
}
for region in "${regions[@]}"; do
  for flag in "${stage_d_flags[@]}"; do
    name="$(region_key "${region}")_${flag}"
    case "${!name-}" in
      on|off) ;;
      *) echo "${region}: ${name} must be on or off" >&2; exit 2 ;;
    esac
  done
done

wave_dir="$(mktemp -d "${TMPDIR:-/tmp}/tr-secondary-wave-XXXXXX")"
: > "${wave_dir}/dns-reconcile.lock"
export TR_SECONDARY_WAVE_DIR="${wave_dir}"
timeout_seconds="${TR_SECONDARY_WORKER_TIMEOUT:-}"
if [ -n "${timeout_seconds}" ]; then
  if ! [[ "${timeout_seconds}" =~ ^[1-9][0-9]*$ ]]; then
    echo "TR_SECONDARY_WORKER_TIMEOUT must be a positive number of seconds" >&2
    exit 2
  fi
  export TR_SECONDARY_DEADLINE="$(( $(date +%s) + timeout_seconds ))"
fi

pids=()
readers=()
stop_readers() {
  sleep 1
  for reader in ${readers[@]+"${readers[@]}"}; do
    kill "${reader}" 2>/dev/null || true
  done
}
# A TERM or INT to this script alone (an operator, or a parent that signals
# only it): pass TERM to every worker, whose own trap then restores its
# region with further signals ignored, and wait for those recoveries.
forward_term() {
  # Ignore, not reset: a second TERM or INT (a group signal, a repeated
  # cancel) must not kill the wave while its workers are still recovering.
  trap '' TERM INT
  echo "secondary wave interrupted; stopping workers so each can recover" >&2
  for pid in ${pids[@]+"${pids[@]}"}; do
    kill -TERM "${pid}" 2>/dev/null || true
  done
  for pid in ${pids[@]+"${pids[@]}"}; do
    wait "${pid}" 2>/dev/null || true
  done
  stop_readers
  exit 143
}
trap forward_term TERM INT
echo "secondary wave: ${regions[*]} in parallel"
for index in "${!regions[@]}"; do
  args=("${all_args[@]:$((index * 10)):10}")
  region="${args[0]}"
  key="$(region_key "${region}")"
  heartbeat_name="${key}_QUILL_USAGE_HEARTBEAT"
  terminate_name="${key}_QUILL_TERMINATE_AT_CAP"
  log="${wave_dir}/${region}.log"
  : > "${log}"
  QUILL_USAGE_HEARTBEAT="${!heartbeat_name}" QUILL_TERMINATE_AT_CAP="${!terminate_name}" \
    "${BASH}" tools/roll-secondary-region.sh "${args[@]}" >>"${log}" 2>&1 &
  pids+=("$!")
  # Killing tail ends its awk too (EOF); the worker writes to the file only.
  tail -n +1 -f "${log}" > >(awk -v prefix="[${region}] " '{ print prefix $0; fflush() }') &
  readers+=("$!")
done

statuses=()
for pid in "${pids[@]}"; do
  if wait "${pid}"; then
    statuses+=(0)
  else
    statuses+=("$?")
  fi
done
# Let the prefixing readers drain before the summary.
stop_readers

failed_first=""
if [ -s "${wave_dir}/abort" ]; then
  failed_first="$(cat "${wave_dir}/abort")"
fi
overall=0
echo "secondary wave verdicts:"
for index in "${!regions[@]}"; do
  region="${regions[${index}]}"
  status="${statuses[${index}]}"
  if [ "${status}" -eq 0 ]; then
    verdict="promoted"
  elif [ "${status}" -eq 75 ] && [ -n "${failed_first}" ] && [ "${failed_first}" != "${region}" ]; then
    verdict="not promoted: stopped by a peer, ${failed_first} failed first; previous template and drain state restored if it had started"
    overall=1
  elif [ "${status}" -eq 76 ]; then
    verdict="FAILED: its rollout deadline passed before promotion; it ran its own recovery"
    overall=1
  else
    verdict="FAILED (exit ${status}); this region's own gate or step failed and it ran its own recovery"
    overall=1
  fi
  echo "  ${region}: ${verdict}"
done
rm -rf "${wave_dir}"
exit "${overall}"
