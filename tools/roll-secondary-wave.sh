#!/usr/bin/env bash
# Roll several secondary gateway regions at once, one worker per region.
#
#   tools/roll-secondary-wave.sh -- <10 roll-secondary-region.sh args> [-- <10 args> ...]
#
# Each worker is the unchanged tools/roll-secondary-region.sh, with every
# per-region gate (drain, stable, attested, per-instance verify, synthetic
# wait, per-region watchdog) and its own automatic recovery. The wave adds:
#
#   * one shared lock for the persistent-drain read-modify-write and DNS
#     reconciles, including recoveries, so concurrent regions cannot lose each
#     other's drain updates;
#   * a shared abort file: the first region to fail records itself there, and
#     no peer promotes afterwards. A peer that has not yet re-entered canonical
#     DNS stops, restores its previous template and drain state, and exits 75;
#     a peer not yet started is left untouched. The end state matches the
#     serial rollout, where a failure meant later regions never changed.
#
# Output lines carry a "[region]" prefix and a final per-region verdict, so
# each result is attributable to its region. Exit 0 only if every region
# promoted.
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
if [ -n "${timeout_seconds}" ] && ! command -v timeout >/dev/null 2>&1; then
  echo "TR_SECONDARY_WORKER_TIMEOUT is set but timeout(1) is not installed" >&2
  exit 2
fi

pids=()
# A cancelled or timed-out step signals this script: pass TERM to every
# worker, whose own trap then restores its region, and wait for them.
forward_term() {
  trap - TERM INT
  echo "secondary wave interrupted; stopping workers so each can recover" >&2
  for pid in ${pids[@]+"${pids[@]}"}; do
    kill -TERM "${pid}" 2>/dev/null || true
  done
  wait || true
  exit 143
}
trap forward_term TERM INT
echo "secondary wave: ${regions[*]} in parallel"
for index in "${!regions[@]}"; do
  args=("${all_args[@]:$((index * 10)):10}")
  region="${args[0]}"
  # The worker's TERM trap runs its recovery, so the per-worker timeout
  # signals TERM and leaves the step's own timeout room for that recovery.
  if [ -n "${timeout_seconds}" ]; then
    runner=(timeout --signal=TERM "${timeout_seconds}" "${BASH}")
  else
    runner=("${BASH}")
  fi
  key="$(region_key "${region}")"
  heartbeat_name="${key}_QUILL_USAGE_HEARTBEAT"
  terminate_name="${key}_QUILL_TERMINATE_AT_CAP"
  QUILL_USAGE_HEARTBEAT="${!heartbeat_name}" QUILL_TERMINATE_AT_CAP="${!terminate_name}" \
    "${runner[@]}" tools/roll-secondary-region.sh "${args[@]}" \
    > >(awk -v prefix="[${region}] " '{ print prefix $0; fflush() }') 2>&1 &
  pids+=("$!")
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
sleep 1

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
    verdict="not promoted: ${failed_first} failed first; previous template and drain state restored if it had started"
    overall=1
  else
    verdict="FAILED (exit ${status}); this region's own gate or step failed and it ran its own recovery"
    overall=1
  fi
  echo "  ${region}: ${verdict}"
done
rm -rf "${wave_dir}"
exit "${overall}"
