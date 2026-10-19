#!/usr/bin/env bash
# Regional CPU autoscaler for one attested gateway MIG, and the holds that keep
# it from acting while the group is drained, rolled, recovered, or relieved.
#
# It scales OUT only (mode ONLY_SCALE_OUT). Traffic reaches a gateway VM only
# through DNS, with no load balancer to drain it, so an autoscaler scale-in
# would delete a VM that DNS still points at. Scale-in is left to a separate
# job that removes a VM from DNS before deleting it (a follow-up, not built
# yet); until then a group grown by a spike stays at its size.
#
# Nothing reserves capacity behind the fleet: Compute Engine does not offer
# reservations for Confidential VMs with Intel TDX. Warm capacity is the
# autoscaler's minimum, spread over the group's zones.
#
# Usage: gcp-mig-autoscaler.sh <command> <region> <mig>
#
#   apply    Create or update the autoscaler to the policy below with mode
#            ONLY_SCALE_OUT, then read it back. An autoscaler that already
#            matches is left untouched, so a second run changes nothing.
#            Callers run it only after the region's rollout completed: its
#            gates passed and its canonical drain state was restored.
#   suspend  Mode OFF, which freezes the group's size. Callers run it before the
#            region is drained or its template changes: every VM in the region
#            must pass the rollout's attestation gate, including one added
#            mid-rollout, and the rollout's time budget is sized for the group
#            it starts with. A group with no autoscaler is left alone.
#   resume   Mode ONLY_SCALE_OUT for an autoscaler that exists. It never creates
#            one and never changes the rest of the policy, so a verified
#            recovery undoes its rollout's suspend without applying the failed
#            commit's policy.
#   detach   Delete the autoscaler and keep the group's current size, for
#            tools/relieve-mig-stockout.py, which resizes the group and deletes
#            VMs by name. `apply` attaches it again.
#   mode     Print the autoscaler's mode (ONLY_SCALE_OUT, OFF, ON) or "none".
#
# AUTOSCALER_MIN_REPLICAS, AUTOSCALER_MAX_REPLICAS, AUTOSCALER_TARGET_CPU and
# AUTOSCALER_COOL_DOWN_SECONDS override the policy for one run; the next
# `apply` without them converges the group back to the defaults below.
set -euo pipefail

usage() {
  echo "usage: $0 <apply|suspend|resume|detach|mode> <region> <mig>" >&2
  exit 2
}

[ "$#" -eq 3 ] || usage
command_name="$1"
region="$2"
mig="$3"
case "${command_name}" in
  apply|suspend|resume|detach|mode) ;;
  *) usage ;;
esac
if ! [[ "${region}" =~ ^[a-z]+-[a-z]+[0-9]+$ ]]; then
  echo "invalid region '${region}'" >&2
  exit 2
fi
if ! [[ "${mig}" =~ ^[a-z]([-a-z0-9]*[a-z0-9])?$ ]]; then
  echo "invalid MIG name '${mig}'" >&2
  exit 2
fi

PROJECT_ID="${PROJECT_ID:-quill-cloud-proxy}"
MIN_REPLICAS="${AUTOSCALER_MIN_REPLICAS:-2}"
MAX_REPLICAS="${AUTOSCALER_MAX_REPLICAS:-8}"
TARGET_CPU="${AUTOSCALER_TARGET_CPU:-0.60}"
# The initialization period: seconds the autoscaler ignores a new VM. A
# Confidential Space VM attests and enters DNS about 5-8 minutes after boot.
COOL_DOWN_SECONDS="${AUTOSCALER_COOL_DOWN_SECONDS:-480}"
READBACK_ATTEMPTS="${AUTOSCALER_READBACK_ATTEMPTS:-6}"
READBACK_SLEEP_SECONDS="${AUTOSCALER_READBACK_SLEEP_SECONDS:-5}"
if ! [[ "${READBACK_ATTEMPTS}" =~ ^[1-9][0-9]*$ ]] || ! [[ "${READBACK_SLEEP_SECONDS}" =~ ^[0-9]+$ ]]; then
  echo "AUTOSCALER_READBACK_ATTEMPTS/AUTOSCALER_READBACK_SLEEP_SECONDS must be integers" >&2
  exit 2
fi

log() { echo "[gcp-mig-autoscaler] ${region}/${mig}: $*" >&2; }
fail() {
  log "$*"
  exit 1
}

validate_policy() {
  local variable
  for variable in MIN_REPLICAS MAX_REPLICAS COOL_DOWN_SECONDS; do
    if ! [[ "${!variable}" =~ ^[1-9][0-9]{0,5}$ ]]; then
      echo "AUTOSCALER_${variable}='${!variable}' must be a positive integer" >&2
      exit 2
    fi
  done
  # tools/verify-region-before-dns.sh fails a rolled region with fewer than two
  # running VMs, so a smaller floor could never pass its own rollout gate.
  if [ "${MIN_REPLICAS}" -lt 2 ] || [ "${MIN_REPLICAS}" -gt "${MAX_REPLICAS}" ]; then
    echo "autoscaler replicas must satisfy 2 <= min (${MIN_REPLICAS}) <= max (${MAX_REPLICAS})" >&2
    exit 2
  fi
  if ! [[ "${TARGET_CPU}" =~ ^(0?\.[0-9]+|1(\.0*)?)$ ]] ||
      ! awk -v cpu="${TARGET_CPU}" 'BEGIN { exit !(cpu > 0) }'; then
    echo "AUTOSCALER_TARGET_CPU='${TARGET_CPU}' must be in (0, 1]" >&2
    exit 2
  fi
}

# Reads `gcloud ... managed describe --format=json`, which embeds the attached
# autoscaler under "autoscaler" (the group's own status names it too). Prints
# "<attached> <policy> <mode> <name>":
#   attached  present | none
#   policy    match (every field below, and mode ONLY_SCALE_OUT) | drift | -
#   mode      the autoscaler's mode | -     (the API's default mode is ON)
#   name      the autoscaler's name | -
# scaleInControl is not compared: this autoscaler never scales in.
# With "explain" as the 5th argument, each field that differs goes to stderr.
STATE_PY="$(cat <<'PY'
import json
import sys

want_min, want_max, want_cpu, want_cool, explain = sys.argv[1:6]
group = json.loads(sys.stdin.read())
autoscaler = group.get("autoscaler")
url = (group.get("status") or {}).get("autoscaler") or ""
if not autoscaler and not url:
    print("none - - -")
    raise SystemExit(0)
if not isinstance(autoscaler, dict):
    print("present drift UNKNOWN", url.rsplit("/", 1)[-1] or "-")
    if explain == "explain":
        print("the group names an autoscaler that could not be read", file=sys.stderr)
    raise SystemExit(0)
policy = autoscaler.get("autoscalingPolicy") or {}
mode = policy.get("mode") or "ON"
cpu = policy.get("cpuUtilization") or {}
have = {
    "mode": mode,
    "minNumReplicas": policy.get("minNumReplicas"),
    "maxNumReplicas": policy.get("maxNumReplicas"),
    "cpuUtilization.utilizationTarget": cpu.get("utilizationTarget"),
    "cpuUtilization.predictiveMethod": cpu.get("predictiveMethod") or "NONE",
    "coolDownPeriodSec": policy.get("coolDownPeriodSec"),
    "other signals": sorted(
        key for key in ("customMetricUtilizations", "loadBalancingUtilization", "scalingSchedules")
        if policy.get(key)
    ),
}
want = {
    "mode": "ONLY_SCALE_OUT",
    "minNumReplicas": int(want_min),
    "maxNumReplicas": int(want_max),
    "cpuUtilization.utilizationTarget": float(want_cpu),
    "cpuUtilization.predictiveMethod": "NONE",
    "coolDownPeriodSec": int(want_cool),
    "other signals": [],
}


def same(have_value, want_value):
    if isinstance(want_value, float):
        return (
            isinstance(have_value, (int, float))
            and not isinstance(have_value, bool)
            and abs(have_value - want_value) < 1e-9
        )
    return have_value == want_value


drift = [key for key in want if not same(have[key], want[key])]
if explain == "explain":
    for key in drift:
        print(f"  {key}: {have[key]!r}, policy wants {want[key]!r}", file=sys.stderr)
print("present", "drift" if drift else "match", mode, autoscaler.get("name") or "-")
PY
)"

attached=""
policy=""
mode=""
name=""

load_state() {
  local described state_line
  described="$(gcloud --project "${PROJECT_ID}" compute instance-groups managed describe "${mig}" \
    --region="${region}" --format=json)"
  state_line="$(python3 -c "${STATE_PY}" "${MIN_REPLICAS}" "${MAX_REPLICAS}" "${TARGET_CPU}" \
    "${COOL_DOWN_SECONDS}" "${1:-quiet}" <<<"${described}")"
  read -r attached policy mode name <<<"${state_line}"
}

# A change counts only once it reads back: configured is not working. Usage:
# read_back <attached> <policy|any> <mode|any>
read_back() {
  local want_attached="$1" want_policy="$2" want_mode="$3" attempt=1
  while :; do
    load_state
    if [ "${attached}" = "${want_attached}" ] &&
        { [ "${want_policy}" = any ] || [ "${policy}" = "${want_policy}" ]; } &&
        { [ "${want_mode}" = any ] || [ "${mode}" = "${want_mode}" ]; }; then
      return 0
    fi
    if [ "${attempt}" -ge "${READBACK_ATTEMPTS}" ]; then
      return 1
    fi
    attempt=$((attempt + 1))
    sleep "${READBACK_SLEEP_SECONDS}"
  done
}

cmd_apply() {
  local summary
  validate_policy
  summary="mode ONLY_SCALE_OUT, ${MIN_REPLICAS}-${MAX_REPLICAS} VMs, CPU target ${TARGET_CPU}, initialization ${COOL_DOWN_SECONDS}s"
  load_state explain
  if [ "${policy}" = match ]; then
    log "autoscaler ${name} already reads ${summary}; nothing to change"
    return 0
  fi
  if [ "${attached}" = none ]; then
    log "creating the autoscaler: ${summary}"
  else
    log "updating autoscaler ${name} (mode ${mode}) to: ${summary}"
  fi
  # set-autoscaling replaces the whole policy, so every field is passed. No
  # scale-in control: in this mode the autoscaler never removes a VM.
  gcloud --project "${PROJECT_ID}" compute instance-groups managed set-autoscaling "${mig}" \
    --region="${region}" \
    --mode=only-scale-out \
    --min-num-replicas="${MIN_REPLICAS}" \
    --max-num-replicas="${MAX_REPLICAS}" \
    --target-cpu-utilization="${TARGET_CPU}" \
    --cool-down-period="${COOL_DOWN_SECONDS}s" \
    --quiet >/dev/null
  read_back present match ONLY_SCALE_OUT || fail "the autoscaler does not read back as: ${summary}"
  log "autoscaler ${name} reads back as: ${summary}"
}

cmd_suspend() {
  load_state
  if [ "${attached}" = none ]; then
    log "no autoscaler is attached; the group's size is already fixed"
    return 0
  fi
  if [ "${mode}" = OFF ]; then
    log "autoscaler ${name} is already off; the group's size is fixed"
    return 0
  fi
  log "turning autoscaler ${name} off (was ${mode}); the group's size is fixed until resume or apply"
  gcloud --project "${PROJECT_ID}" compute instance-groups managed update-autoscaling "${mig}" \
    --region="${region}" --mode=off --quiet >/dev/null
  read_back present any OFF || fail "autoscaler ${name} does not read back as off"
}

cmd_resume() {
  load_state
  if [ "${attached}" = none ]; then
    log "no autoscaler is attached; nothing to resume (only apply creates one)"
    return 0
  fi
  if [ "${mode}" = ONLY_SCALE_OUT ]; then
    log "autoscaler ${name} already scales out only"
    return 0
  fi
  log "setting autoscaler ${name} to scale out only (was ${mode})"
  gcloud --project "${PROJECT_ID}" compute instance-groups managed update-autoscaling "${mig}" \
    --region="${region}" --mode=only-scale-out --quiet >/dev/null
  read_back present any ONLY_SCALE_OUT || fail "autoscaler ${name} does not read back as scaling out only"
}

cmd_detach() {
  load_state
  if [ "${attached}" = none ]; then
    log "no autoscaler is attached; nothing to detach"
    return 0
  fi
  log "deleting autoscaler ${name} (mode ${mode}); the group keeps its current size"
  gcloud --project "${PROJECT_ID}" compute instance-groups managed stop-autoscaling "${mig}" \
    --region="${region}" --quiet >/dev/null
  read_back none any any || fail "the group still reads as autoscaled after stop-autoscaling"
}

cmd_mode() {
  load_state
  if [ "${attached}" = none ]; then
    echo none
  else
    echo "${mode}"
  fi
}

case "${command_name}" in
  apply) cmd_apply ;;
  suspend) cmd_suspend ;;
  resume) cmd_resume ;;
  detach) cmd_detach ;;
  mode) cmd_mode ;;
esac
