#!/usr/bin/env bash
# Offline tests for tools/gcp-mig-autoscaler.sh and for how each script that
# rolls, drains, recovers or relieves a GCP enclave MIG holds its autoscaler.
#
# gcloud is a stateful fake (one regional MIG and its autoscaler) for the
# autoscaler commands and for the real MIG block of tools/deploy-gcp-mig.sh.
# The secondary rollout, recovery and drain cleanup run with their children
# stubbed, as in test-enclave-rollout-drains.sh, and the order of what they
# ran is asserted.
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "${root}"

python="$(command -v python3)"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/gcp-mig-autoscaler-test-XXXXXX")"
trap 'rm -rf "${tmp}"' EXIT
mkdir "${tmp}/fake" "${tmp}/stub"
ln -s "${python}" "${tmp}/fake/python3"

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

# ---------------------------------------------------------------------------
# The fake: what Compute holds for quill-enclave-mig-uswest1, changed only by
# the calls a real gcloud would make. Unknown calls and flags are errors.
cat >"${tmp}/fake/gcloud" <<'EOF'
#!/usr/bin/env python3
import json
import os
import sys

argv = sys.argv[1:]
with open(os.environ["GCLOUD_LOG"], "a", encoding="utf-8") as log:
    log.write("gcloud " + " ".join(argv) + "\n")
args = argv
if args[:1] == ["--project"]:
    if args[1] != "quill-cloud-proxy":
        sys.exit(f"fake gcloud: unexpected project {args[1]}")
    args = args[2:]
with open(os.environ["GCLOUD_STATE"], encoding="utf-8") as handle:
    state = json.load(handle)
mig = state["mig"]
faults = state.get("faults") or {}
API = "https://www.googleapis.com/compute/v1/projects/quill-cloud-proxy"


def die(message, code=1):
    print(f"ERROR: (fake gcloud) {message}", file=sys.stderr)
    sys.exit(code)


def parse(rest, allowed=None):
    flags = {}
    for arg in rest:
        if not arg.startswith("--"):
            die(f"unexpected argument {arg!r}", 2)
        key, _, value = arg[2:].partition("=")
        if allowed is not None and key not in allowed:
            die(f"unrecognized arguments: {arg}", 2)
        flags[key] = value
    return flags


def the_group(name, flags):
    if mig is None or name != mig["name"] or flags.get("region") != mig["region"]:
        die(f"The resource '{API}/regions/{flags.get('region')}/instanceGroupManagers/{name}' was not found")


def described():
    group = {
        "name": mig["name"],
        "region": f"{API}/regions/{mig['region']}",
        "targetSize": mig["targetSize"],
        "instanceTemplate": f"{API}/global/instanceTemplates/{mig['template']}",
        "distributionPolicy": {
            "targetShape": "BALANCED",
            "zones": [{"zone": f"{API}/zones/{zone}"} for zone in mig["zones"]],
        },
        "status": {"isStable": True},
    }
    autoscaler = mig.get("autoscaler")
    if autoscaler:
        # gcloud's describe embeds the attached autoscaler; the group names it.
        group["status"]["autoscaler"] = f"{API}/regions/{mig['region']}/autoscalers/{autoscaler['name']}"
        group["autoscaler"] = {
            "name": autoscaler["name"],
            "status": "ACTIVE",
            "target": f"{API}/regions/{mig['region']}/instanceGroupManagers/{mig['name']}",
            "autoscalingPolicy": autoscaler["policy"],
        }
    return group


def require_autoscaler():
    if not mig.get("autoscaler"):
        die(f"no autoscaler targets {mig['name']}")


beta = args[:1] == ["beta"]
if beta:
    args = args[1:]
if args[:3] == ["compute", "instance-groups", "managed"] and len(args) >= 5:
    verb, name, rest = args[3], args[4], args[5:]
    if verb == "describe" and not beta:
        flags = parse(rest, {"region", "format"})
        the_group(name, flags)
        if flags.get("format", "json") != "json":
            die(f"unsupported --format={flags['format']}", 2)
        print(json.dumps(described()))
    elif verb == "set-autoscaling" and not beta:
        flags = parse(rest, {
            "region", "mode", "min-num-replicas", "max-num-replicas", "target-cpu-utilization",
            "cool-down-period", "scale-in-control", "quiet",
        })
        the_group(name, flags)
        if "max-num-replicas" not in flags:
            die("argument --max-num-replicas: Must be specified.", 2)
        # gcloud replaces the whole policy; only an unspecified mode is kept.
        previous = (mig.get("autoscaler") or {}).get("policy") or {}
        policy = {"maxNumReplicas": int(flags["max-num-replicas"])}
        policy["mode"] = flags["mode"].upper().replace("-", "_") if "mode" in flags else previous.get("mode", "ON")
        if "min-num-replicas" in flags:
            policy["minNumReplicas"] = int(flags["min-num-replicas"])
        if "target-cpu-utilization" in flags:
            policy["cpuUtilization"] = {"utilizationTarget": float(flags["target-cpu-utilization"]), "predictiveMethod": "NONE"}
        if "cool-down-period" in flags:
            policy["coolDownPeriodSec"] = int(flags["cool-down-period"].removesuffix("s"))
        if "scale-in-control" in flags:
            control = dict(part.split("=", 1) for part in flags["scale-in-control"].split(","))
            fixed = int(control["max-scaled-in-replicas"])
            policy["scaleInControl"] = {
                "maxScaledInReplicas": {"fixed": fixed, "calculated": fixed},
                "timeWindowSec": int(control["time-window"]),
            }
        if not faults.get("set_autoscaling_is_lost"):
            name_in_use = (mig.get("autoscaler") or {}).get("name") or mig["name"] + "-x7k2"
            mig["autoscaler"] = {"name": name_in_use, "policy": policy}
    elif verb == "update-autoscaling" and not beta:
        flags = parse(rest, {"region", "mode", "quiet"})
        the_group(name, flags)
        require_autoscaler()
        if not faults.get("mode_updates_are_lost"):
            mig["autoscaler"]["policy"]["mode"] = flags["mode"].upper().replace("-", "_")
    elif verb == "stop-autoscaling" and not beta:
        flags = parse(rest, {"region", "quiet"})
        the_group(name, flags)
        require_autoscaler()
        mig["autoscaler"] = None
    elif verb == "resize" and not beta:
        flags = parse(rest, {"region", "size"})
        the_group(name, flags)
        if mig.get("autoscaler"):
            die("this model refuses any manual resize of an autoscaled group")
        mig["targetSize"] = int(flags["size"])
    elif verb == "set-instance-template" and not beta:
        flags = parse(rest, {"region", "template"})
        the_group(name, flags)
        mig["template"] = flags["template"]
    elif verb == "update" and beta:
        flags = parse(rest)
        the_group(name, flags)
        mig["maxSurge"] = int(flags["update-policy-max-surge"])
    elif verb == "create" and beta:
        flags = parse(rest)
        if mig is not None:
            die(f"{name} already exists")
        state["mig"] = {
            "name": name, "region": flags["region"], "targetSize": int(flags["size"]),
            "zones": flags["zones"].split(","), "template": flags["template"],
            "autoscaler": None, "maxSurge": int(flags["update-policy-max-surge"]),
        }
    else:
        die(f"unexpected gcloud call: {argv}", 3)
else:
    die(f"unexpected gcloud call: {argv}", 3)
with open(os.environ["GCLOUD_STATE"], "w", encoding="utf-8") as handle:
    json.dump(state, handle)
EOF
chmod +x "${tmp}/fake/gcloud"

state="${tmp}/state.json"
gcloud_log="${tmp}/gcloud.log"
export GCLOUD_STATE="${state}" GCLOUD_LOG="${gcloud_log}"
policy_on='{"name": "quill-enclave-mig-uswest1-x7k2", "policy": {"mode": "ON", "minNumReplicas": 2, "maxNumReplicas": 8, "coolDownPeriodSec": 120, "cpuUtilization": {"utilizationTarget": 0.6, "predictiveMethod": "NONE"}, "scaleInControl": {"maxScaledInReplicas": {"fixed": 1, "calculated": 1}, "timeWindowSec": 600}}}'

# set_state <size> <zones> <autoscaler JSON|null|absent> [faults JSON]
set_state() {
  "${python}" - "$@" >"${state}" <<'PY'
import json
import sys

size, zones, autoscaler = sys.argv[1:4]
faults = json.loads(sys.argv[4]) if len(sys.argv) > 4 else {}
mig = None
if autoscaler != "absent":
    mig = {
        "name": "quill-enclave-mig-uswest1", "region": "us-west1", "targetSize": int(size),
        "zones": zones.split(","), "template": "quill-enclave-tpl-uswest1-041",
        "autoscaler": json.loads(autoscaler), "maxSurge": 3,
    }
print(json.dumps({"mig": mig, "faults": faults}))
PY
  : >"${gcloud_log}"
}

# state_get <Python expression over `mig`>: strings raw, anything else as JSON.
state_get() {
  "${python}" - "$1" "${state}" <<'PY'
import json
import sys

mig = json.load(open(sys.argv[2], encoding="utf-8"))["mig"]
value = eval(sys.argv[1], {"mig": mig})
print(value if isinstance(value, str) else json.dumps(value))
PY
}

expect_state() {
  local actual
  actual="$(state_get "$1")"
  [ "${actual}" = "$2" ] || fail "state ${1} reads '${actual}', want '$2'"
}

# The calls that change a group's autoscaler or size.
mutations() {
  grep -E 'managed (set-autoscaling|update-autoscaling|stop-autoscaling|resize) ' "${gcloud_log}" || true
}

expect_mutations() {
  local count
  count="$(mutations | grep -c . || true)"
  [ "${count}" -eq "$1" ] || fail "${2}: expected $1 mutating call(s), saw ${count}: $(mutations)"
}

expect_status() {
  [ "${status}" -eq "$1" ] || fail "${2}: exit ${status}, want $1; stderr: $(cat "${tmp}/err")"
}

# run_autoscaler <command> [VAR=value ...]
run_autoscaler() {
  local command_name="$1"
  shift
  status=0
  env PATH="${tmp}/fake:/usr/bin:/bin" AUTOSCALER_READBACK_SLEEP_SECONDS=0 ${1+"$@"} \
    /bin/bash tools/gcp-mig-autoscaler.sh "${command_name}" us-west1 quill-enclave-mig-uswest1 \
    >"${tmp}/out" 2>"${tmp}/err" || status=$?
}

# --- 1. The autoscaler commands ---------------------------------------------
set_state 2 us-west1-a,us-west1-b null
run_autoscaler mode
expect_status 0 "mode without an autoscaler"
[ "$(cat "${tmp}/out")" = none ] || fail "mode printed '$(cat "${tmp}/out")', want none"

for command_name in suspend resume detach; do
  set_state 2 us-west1-a,us-west1-b null
  run_autoscaler "${command_name}"
  expect_status 0 "${command_name} without an autoscaler"
  expect_mutations 0 "${command_name} without an autoscaler"
done
grep -Fq 'nothing to detach' "${tmp}/err" || fail "detach did not say there was nothing to detach"
expect_state 'mig["autoscaler"]' null

# apply creates the autoscaler with exactly the policy, in the group's region.
set_state 2 us-west1-a,us-west1-b null
run_autoscaler apply
expect_status 0 "apply (create)"
expect_mutations 1 "apply (create)"
grep -Fxq 'gcloud --project quill-cloud-proxy compute instance-groups managed set-autoscaling quill-enclave-mig-uswest1 --region=us-west1 --mode=on --min-num-replicas=2 --max-num-replicas=8 --target-cpu-utilization=0.60 --cool-down-period=120s --scale-in-control=max-scaled-in-replicas=1,time-window=600 --quiet' \
  "${gcloud_log}" || fail "apply did not create the autoscaler with the policy's flags: $(mutations)"
grep -Fq 'creating the autoscaler' "${tmp}/err" || fail "apply did not say it created the autoscaler"
expect_state 'mig["autoscaler"]["policy"]["mode"]' ON
expect_state 'mig["autoscaler"]["policy"]["minNumReplicas"]' 2
expect_state 'mig["autoscaler"]["policy"]["maxNumReplicas"]' 8
expect_state 'mig["autoscaler"]["policy"]["cpuUtilization"]["utilizationTarget"]' 0.6
expect_state 'mig["autoscaler"]["policy"]["coolDownPeriodSec"]' 120
expect_state 'mig["autoscaler"]["policy"]["scaleInControl"]["maxScaledInReplicas"]["fixed"]' 1
expect_state 'mig["autoscaler"]["policy"]["scaleInControl"]["timeWindowSec"]' 600
expect_state 'mig["targetSize"]' 2

# A second apply converges without a call.
: >"${gcloud_log}"
run_autoscaler apply
expect_status 0 "apply (second run)"
expect_mutations 0 "apply (second run)"
grep -Fq 'already reads mode ON, 2-8 VMs, CPU target 0.60, cool-down 120s, scale-in at most 1 VM per 600s; nothing to change' \
  "${tmp}/err" || fail "the second apply did not report convergence: $(cat "${tmp}/err")"

# suspend freezes the size (mode OFF); a second suspend is a no-op.
: >"${gcloud_log}"
run_autoscaler suspend
expect_status 0 "suspend"
expect_mutations 1 "suspend"
grep -Fxq 'gcloud --project quill-cloud-proxy compute instance-groups managed update-autoscaling quill-enclave-mig-uswest1 --region=us-west1 --mode=off --quiet' \
  "${gcloud_log}" || fail "suspend did not turn the autoscaler off: $(mutations)"
expect_state 'mig["autoscaler"]["policy"]["mode"]' OFF
: >"${gcloud_log}"
run_autoscaler suspend
expect_mutations 0 "suspend (second run)"
run_autoscaler mode
[ "$(cat "${tmp}/out")" = OFF ] || fail "mode printed '$(cat "${tmp}/out")', want OFF"

# apply lifts a suspend, then converges.
: >"${gcloud_log}"
run_autoscaler apply
expect_status 0 "apply (suspended)"
expect_mutations 1 "apply (suspended)"
expect_state 'mig["autoscaler"]["policy"]["mode"]' ON
: >"${gcloud_log}"
run_autoscaler apply
expect_mutations 0 "apply after lifting a suspend"

# resume turns a suspended autoscaler on without touching its policy.
run_autoscaler suspend
: >"${gcloud_log}"
run_autoscaler resume
expect_status 0 "resume"
expect_mutations 1 "resume"
grep -Fxq 'gcloud --project quill-cloud-proxy compute instance-groups managed update-autoscaling quill-enclave-mig-uswest1 --region=us-west1 --mode=on --quiet' \
  "${gcloud_log}" || fail "resume did not turn the autoscaler on: $(mutations)"
expect_state 'mig["autoscaler"]["policy"]["mode"]' ON
: >"${gcloud_log}"
run_autoscaler resume
expect_mutations 0 "resume (second run)"

# Drift in any field, including an extra signal, converges in one call.
set_state 4 us-west1-a,us-west1-b '{"name": "quill-enclave-mig-uswest1-x7k2", "policy": {"mode": "ONLY_SCALE_OUT", "minNumReplicas": 3, "maxNumReplicas": 12, "coolDownPeriodSec": 60, "cpuUtilization": {"utilizationTarget": 0.8}, "customMetricUtilizations": [{"metric": "example"}]}}'
run_autoscaler apply
expect_status 0 "apply (drift)"
expect_mutations 1 "apply (drift)"
for field in mode minNumReplicas maxNumReplicas coolDownPeriodSec cpuUtilization.utilizationTarget \
    scaleInControl.maxScaledInReplicas.fixed scaleInControl.timeWindowSec 'other signals'; do
  grep -Fq "  ${field}: " "${tmp}/err" || fail "apply did not report drift in ${field}: $(cat "${tmp}/err")"
done
expect_state 'mig["autoscaler"]["policy"]["maxNumReplicas"]' 8
expect_state '"customMetricUtilizations" in mig["autoscaler"]["policy"]' false
expect_state 'mig["autoscaler"]["name"]' quill-enclave-mig-uswest1-x7k2
expect_state 'mig["targetSize"]' 4

# A one-run override applies; the next plain apply converges back.
: >"${gcloud_log}"
run_autoscaler apply AUTOSCALER_MAX_REPLICAS=10
expect_mutations 1 "apply (override)"
expect_state 'mig["autoscaler"]["policy"]["maxNumReplicas"]' 10
: >"${gcloud_log}"
run_autoscaler apply
expect_mutations 1 "apply (back to the defaults)"
expect_state 'mig["autoscaler"]["policy"]["maxNumReplicas"]' 8

# detach deletes the autoscaler and keeps the size.
: >"${gcloud_log}"
run_autoscaler detach
expect_status 0 "detach"
grep -Fxq 'gcloud --project quill-cloud-proxy compute instance-groups managed stop-autoscaling quill-enclave-mig-uswest1 --region=us-west1 --quiet' \
  "${gcloud_log}" || fail "detach did not stop autoscaling: $(mutations)"
expect_state 'mig["autoscaler"]' null
expect_state 'mig["targetSize"]' 4

# A change that does not read back fails: configured is not working.
set_state 2 us-west1-a,us-west1-b "${policy_on}" '{"mode_updates_are_lost": true}'
run_autoscaler suspend AUTOSCALER_READBACK_ATTEMPTS=2
expect_status 1 "suspend whose change is lost"
grep -Fq 'does not read back as off' "${tmp}/err" || fail "a lost suspend was not reported: $(cat "${tmp}/err")"
set_state 2 us-west1-a,us-west1-b null '{"set_autoscaling_is_lost": true}'
run_autoscaler apply AUTOSCALER_READBACK_ATTEMPTS=2
expect_status 1 "apply whose change is lost"
grep -Fq 'the autoscaler does not read back as' "${tmp}/err" || fail "a lost apply was not reported: $(cat "${tmp}/err")"

# A bad policy or argument is refused before any gcloud call.
for override in AUTOSCALER_MIN_REPLICAS=1 AUTOSCALER_MIN_REPLICAS=9 AUTOSCALER_MAX_REPLICAS=x \
    AUTOSCALER_TARGET_CPU=0 AUTOSCALER_TARGET_CPU=0.0 AUTOSCALER_TARGET_CPU=1.5 \
    AUTOSCALER_TARGET_CPU=60 AUTOSCALER_COOL_DOWN_SECONDS=2m AUTOSCALER_SCALE_IN_MAX_REPLICAS=0 \
    AUTOSCALER_SCALE_IN_WINDOW_SECONDS=-600; do
  set_state 2 us-west1-a,us-west1-b null
  run_autoscaler apply "${override}"
  expect_status 2 "apply with ${override}"
  [ ! -s "${gcloud_log}" ] || fail "apply with ${override} called gcloud: $(cat "${gcloud_log}")"
done
status=0
env PATH="${tmp}/fake:/usr/bin:/bin" /bin/bash tools/gcp-mig-autoscaler.sh scale us-west1 quill-enclave-mig-uswest1 \
  >"${tmp}/out" 2>"${tmp}/err" || status=$?
expect_status 2 "an unknown command"
for target in "US-WEST1 quill-enclave-mig-uswest1" "us-west1 quill_enclave" "us-west1 -mig"; do
  status=0
  # shellcheck disable=SC2086 # two words on purpose: region and MIG
  env PATH="${tmp}/fake:/usr/bin:/bin" /bin/bash tools/gcp-mig-autoscaler.sh mode ${target} \
    >"${tmp}/out" 2>"${tmp}/err" || status=$?
  expect_status 2 "mode ${target}"
done
[ ! -s "${gcloud_log}" ] || fail "an invalid command line called gcloud: $(cat "${gcloud_log}")"

# --- 2. tools/deploy-gcp-mig.sh: the real MIG block --------------------------
grep -Fxq 'default_machine_type="c3-standard-8"' tools/deploy-gcp-mig.sh ||
  fail "the default machine type is not c3-standard-8"
# shellcheck disable=SC2016 # the script's literal text
grep -Fq -- '--machine-type="$MACHINE_TYPE"' tools/deploy-gcp-mig.sh ||
  fail "the instance template does not use MACHINE_TYPE"
awk '/^# 2\. Create or update the MIG\.$/ { on = 1 } /^cat <<EOF$/ { on = 0 } on' \
  tools/deploy-gcp-mig.sh >"${tmp}/mig-block.sh"
# shellcheck disable=SC2016 # the script's literal text
grep -Fq 'gc beta compute instance-groups managed update "$MIG_NAME"' "${tmp}/mig-block.sh" ||
  fail "the MIG block of deploy-gcp-mig.sh was not found"

# run_deploy_block: the block, with what the script set before it.
run_deploy_block() {
  {
    echo 'set -euo pipefail'
    printf 'SCRIPT_DIR=%q\n' "${root}/tools"
    cat <<'EOF'
PROJECT_ID=quill-cloud-proxy
REGION=us-west1
MIG_NAME=quill-enclave-mig-uswest1
TEMPLATE=quill-enclave-tpl-uswest1-042
TARGET_SIZE="${TARGET_SIZE:-2}"
MAX_SURGE="${MAX_SURGE:-3}"
MAX_UNAVAILABLE=0
MIN_READY=600s
MIG_ZONES=us-west1-a,us-west1-b
MIG_ZONE_ARGS=(--zones=us-west1-a,us-west1-b)
CONF_COMPUTE_TYPE=TDX
MACHINE_TYPE=c3-standard-8
log() { echo "[deploy] $*" >&2; }
gc() { gcloud --project "$PROJECT_ID" "$@"; }
EOF
    cat "${tmp}/mig-block.sh"
    # shellcheck disable=SC2016 # expanded by the block, not here
    echo 'echo "size: ${size_summary}"'
  } >"${tmp}/deploy-block.sh"
  status=0
  env PATH="${tmp}/fake:/usr/bin:/bin" AUTOSCALER_READBACK_SLEEP_SECONDS=0 \
    /bin/bash "${tmp}/deploy-block.sh" >"${tmp}/out" 2>"${tmp}/err" || status=$?
}

# Empty when absent; never a failing status, so the caller can say what is missing.
line_of() { grep -n -F -m1 -- "$1" "$2" | cut -d: -f1 || true; }
last_line_of() { grep -n -F -- "$1" "$2" | tail -1 | cut -d: -f1 || true; }
# expect_order <log> <first> <second> ...: each appears, in this order.
expect_order() {
  local log="$1" previous=0 previous_text="(start)" line
  shift
  for text in "$@"; do
    line="$(line_of "${text}" "${log}")"
    [ -n "${line}" ] || fail "missing from $(basename "${log}"): ${text}"
    [ "${line}" -gt "${previous}" ] || fail "'${text}' (line ${line}) is not after '${previous_text}' (line ${previous})"
    previous="${line}"
    previous_text="${text}"
  done
}

# An autoscaled group: suspended before the rollout begins, never resized, and
# no autoscaler created or changed here (the caller applies it after the gates).
set_state 5 us-west1-a,us-west1-b "${policy_on}"
run_deploy_block
expect_status 0 "deploy of an autoscaled group"
expect_order "${gcloud_log}" \
  'managed update-autoscaling quill-enclave-mig-uswest1 --region=us-west1 --mode=off' \
  'beta compute instance-groups managed update quill-enclave-mig-uswest1' \
  'managed set-instance-template quill-enclave-mig-uswest1 --region=us-west1 --template=quill-enclave-tpl-uswest1-042'
expect_mutations 1 "deploy of an autoscaled group"
expect_state 'mig["autoscaler"]["policy"]["mode"]' OFF
expect_state 'mig["targetSize"]' 5
# Two zones, five VMs: each zone may surge three, so two readiness holds at most.
expect_state 'mig["maxSurge"]' 6
grep -Fq 'size: 5, autoscaler suspended until: bash tools/gcp-mig-autoscaler.sh apply us-west1 quill-enclave-mig-uswest1' \
  "${tmp}/out" || fail "the deploy summary does not say how the autoscaler is re-enabled: $(cat "${tmp}/out")"

# An autoscaled group of eight in three zones surges four per zone.
set_state 8 us-west1-a,us-west1-b,us-west1-c "${policy_on}"
run_deploy_block
expect_status 0 "deploy of an 8-VM autoscaled group"
expect_state 'mig["maxSurge"]' 12
expect_state 'mig["targetSize"]' 8

# Today's fleet: two VMs, no autoscaler. Nothing about autoscaling changes, the
# surge stays MAX_SURGE and the size already matches TARGET_SIZE.
set_state 2 us-west1-a,us-west1-b null
run_deploy_block
expect_status 0 "deploy of a 2-VM group"
expect_mutations 0 "deploy of a 2-VM group"
expect_state 'mig["maxSurge"]' 3
expect_state 'mig["autoscaler"]' null
grep -Fq 'size: 2' "${tmp}/out" || fail "the 2-VM deploy summary is wrong: $(cat "${tmp}/out")"

# A group with no autoscaler is still reconciled to TARGET_SIZE, after the
# template change, as before autoscaling.
set_state 3 us-west1-a,us-west1-b null
run_deploy_block
expect_status 0 "deploy of a 3-VM group with no autoscaler"
expect_order "${gcloud_log}" \
  'managed set-instance-template quill-enclave-mig-uswest1' \
  'managed resize quill-enclave-mig-uswest1 --region=us-west1 --size=2'
expect_mutations 1 "deploy of a 3-VM group with no autoscaler"
expect_state 'mig["maxSurge"]' 4
expect_state 'mig["targetSize"]' 2

# A new group is created at TARGET_SIZE with no autoscaler.
set_state 0 - absent
run_deploy_block
expect_status 0 "deploy that creates the group"
grep -Fq 'beta compute instance-groups managed create quill-enclave-mig-uswest1 ' "${gcloud_log}" ||
  fail "the group was not created"
grep -Eq 'autoscaling' "${gcloud_log}" && fail "creating the group touched autoscaling: $(cat "${gcloud_log}")"
expect_state 'mig["targetSize"]' 2
expect_state 'mig["autoscaler"]' null

# TARGET_SIZE is refused below the two VMs a rolled region must have.
awk '/^TARGET_SIZE="\$\{TARGET_SIZE:-2\}"$/ { on = 1 } /^MAX_SURGE=/ { on = 0 } on' \
  tools/deploy-gcp-mig.sh >"${tmp}/target-size.sh"
grep -Fq 'exit 1' "${tmp}/target-size.sh" || fail "the TARGET_SIZE guard was not found"
for value in 1 0 abc 2x -3; do
  if TARGET_SIZE="${value}" /bin/bash -eu "${tmp}/target-size.sh" 2>/dev/null; then
    fail "TARGET_SIZE=${value} was accepted"
  fi
done
TARGET_SIZE=3 /bin/bash -eu "${tmp}/target-size.sh" || fail "TARGET_SIZE=3 was refused"
/bin/bash -eu "${tmp}/target-size.sh" || fail "the default TARGET_SIZE was refused"

# --- 3. Rollout, recovery and drain cleanup, children stubbed ----------------
command_log="${tmp}/commands.log"
export COMMAND_LOG="${command_log}"
# FAIL_ON fails the call whose logged line contains it.
cat >"${tmp}/stub/bash" <<'EOF'
#!/bin/bash
echo "bash $*" >>"${COMMAND_LOG}"
case "bash $*" in
  *"${FAIL_ON:-<nothing fails>}"*) exit 1 ;;
esac
EOF
cat >"${tmp}/stub/uv" <<'EOF'
#!/bin/bash
echo "uv $*" >>"${COMMAND_LOG}"
case "$*" in
  *--list-drain-regions*) cat "${DRAIN_LIST:-/dev/null}" ;;
  *--clear-drain-region*) if [ "${CLEAR_FAILS:-0}" = 1 ]; then exit 1; fi ;;
esac
EOF
cat >"${tmp}/stub/python3" <<'EOF'
#!/bin/bash
echo "python3 $*" >>"${COMMAND_LOG}"
EOF
cat >"${tmp}/stub/gcloud" <<'EOF'
#!/bin/bash
echo "gcloud $*" >>"${COMMAND_LOG}"
case "$*" in
  *"instance-groups managed describe"*) echo "new-template" ;;
  *"instance-templates describe"*)
    printf '%s\n' '{"properties":{"metadata":{"items":[{"key":"tee-image-reference","value":"registry.example/enclave@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}]}}}'
    ;;
  *wait-until*) [ "${STABLE:-1}" = 1 ] ;;
esac
EOF
cat >"${tmp}/stub/curl" <<'EOF'
#!/bin/bash
echo "{\"regions\": [{\"target_region\": \"${SYNTHETIC_REGION:-us-east4}\"}]}"
EOF
printf '#!/bin/bash\nexit 0\n' >"${tmp}/stub/flock"
chmod +x "${tmp}/stub/"*
: >"${tmp}/no-pending.txt"

# run_secondary <previous-template> [VAR=value ...]
run_secondary() {
  local previous="$1"
  shift
  : >"${command_log}"
  status=0
  env PATH="${tmp}/stub:/usr/bin:/bin" GITHUB_RUN_ID=33807667585 \
    TR_DEPLOY_MUTEX_OPERATION=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
    IMAGE_REF=registry.example/enclave:new \
    IMAGE_DIGEST=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa ${1+"$@"} \
    /bin/bash tools/roll-secondary-region.sh us-east4 quill-enclave-mig-useast4 quill-enclave-mig-useast4- \
      useast4 api.quillrouter.com,api-us-east4.quillrouter.com "${previous}" c3-standard-8 TDX active none \
      >"${tmp}/out" 2>"${tmp}/err" || status=$?
}

suspend_east='bash tools/gcp-mig-autoscaler.sh suspend us-east4 quill-enclave-mig-useast4'
apply_east='bash tools/gcp-mig-autoscaler.sh apply us-east4 quill-enclave-mig-useast4'

# A healthy secondary rollout: suspended before its drain, applied only after
# every gate passed and the region was back in canonical DNS.
run_secondary quill-enclave-tpl-useast4-282
expect_status 0 "secondary rollout"
expect_order "${command_log}" \
  "${suspend_east}" \
  '--set-drain-region us-east4 --drain-origin rollout' \
  'bash tools/deploy-gcp-mig.sh us-east4' \
  'wait-until quill-enclave-mig-useast4 --region=us-east4' \
  'bash tools/wait-region-attested.sh quill-enclave-mig-useast4- us-east4' \
  'bash tools/verify-region-before-dns.sh us-east4' \
  'python3 tools/watchdog.py --regions us-east4' \
  '--clear-drain-region us-east4' \
  "${apply_east}"
[ "$(last_line_of 'tools/reconcile-enclave-dns.py --apply' "${command_log}")" -lt \
  "$(line_of "${apply_east}" "${command_log}")" ] || fail "apply ran before the final DNS reconcile"
[ "$(grep -c 'gcp-mig-autoscaler.sh' "${command_log}")" -eq 2 ] ||
  fail "the rollout touched the autoscaler other than once each: $(grep 'gcp-mig-autoscaler.sh' "${command_log}")"

# A failed gate recovers the region and never applies the autoscaler.
run_secondary quill-enclave-tpl-useast4-282 FAIL_ON=verify-region-before-dns.sh
[ "${status}" -ne 0 ] || fail "a failed gate did not fail the rollout"
expect_order "${command_log}" "${suspend_east}" '--set-drain-region us-east4' \
  'bash tools/recover-gcp-region.sh us-east4 quill-enclave-mig-useast4'
grep -Fq "${apply_east}" "${command_log}" && fail "a failed rollout applied the autoscaler"

# An apply that fails after the region verified fails the step but never
# rolls the region back.
run_secondary quill-enclave-tpl-useast4-282 FAIL_ON="${apply_east}"
[ "${status}" -ne 0 ] || fail "a failed apply did not fail the rollout step"
expect_order "${command_log}" '--clear-drain-region us-east4' "${apply_east}"
grep -Fq 'recover-gcp-region.sh' "${command_log}" && fail "a failed apply rolled back a verified region"

# A first deployment has no group to suspend; its autoscaler is created last.
run_secondary "" SYNTHETIC_REGION=europe-west4
expect_status 0 "first deployment"
grep -Fq 'gcp-mig-autoscaler.sh suspend' "${command_log}" && fail "a first deployment suspended a group"
expect_order "${command_log}" 'bash tools/verify-region-before-dns.sh us-east4' \
  '--clear-drain-region us-east4' "${apply_east}"

# run_recovery [VAR=value ...]
run_recovery() {
  : >"${command_log}"
  status=0
  env PATH="${tmp}/stub:/usr/bin:/bin" GITHUB_RUN_ID=33807667585 ${1+"$@"} \
    /bin/bash tools/recover-gcp-region.sh europe-west4 quill-enclave-mig-eu quill-enclave-mig-eu- \
      api.trustedrouter.com,api-europe-west4.quillrouter.com old-template active none \
      >"${tmp}/out" 2>"${tmp}/err" || status=$?
}

suspend_eu='bash tools/gcp-mig-autoscaler.sh suspend europe-west4 quill-enclave-mig-eu'
resume_eu='bash tools/gcp-mig-autoscaler.sh resume europe-west4 quill-enclave-mig-eu'

# Recovery suspends the autoscaler before its drain, keeps it off through the
# rollback, and resumes it only after the rollback verified and the drain state
# was restored.
run_recovery
expect_status 0 "recovery"
expect_order "${command_log}" \
  "${suspend_eu}" \
  '--set-drain-region europe-west4' \
  'wait-canonical-drained.sh europe-west4' \
  'set-instance-template quill-enclave-mig-eu --region=europe-west4' \
  'bash tools/verify-region-before-dns.sh europe-west4' \
  '--clear-drain-region europe-west4' \
  "${resume_eu}"
[ "$(last_line_of 'reconcile-enclave-dns.py' "${command_log}")" -lt "$(line_of "${resume_eu}" "${command_log}")" ] ||
  fail "recovery resumed the autoscaler before its last DNS change"
grep -Fq 'gcp-mig-autoscaler.sh apply' "${command_log}" && fail "recovery applied the failed commit's policy"

run_recovery FAIL_ON=verify-region-before-dns.sh
[ "${status}" -ne 0 ] || fail "a failed rollback verification passed"
grep -Fq "${resume_eu}" "${command_log}" && fail "an unverified rollback resumed the autoscaler"

run_recovery FAIL_ON="${suspend_eu}"
expect_status 0 "recovery whose suspend failed"
grep -Fq 'set-instance-template quill-enclave-mig-eu' "${command_log}" || fail "a failed suspend blocked the rollback"
grep -Fq 'could not suspend the autoscaler of quill-enclave-mig-eu; rolling back anyway' "${tmp}/err" ||
  fail "a failed suspend was not reported"

run_recovery FAIL_ON="${resume_eu}"
expect_status 0 "recovery whose resume failed"
grep -Fq '::error::europe-west4: rollback verified, but the autoscaler of quill-enclave-mig-eu stays off' "${tmp}/err" ||
  fail "a failed resume was not reported"

# run_cleanup <drain list line> [VAR=value ...]
run_cleanup() {
  printf '%b\n' "$1" >"${tmp}/drains.txt"
  shift
  : >"${command_log}"
  status=0
  env PATH="${tmp}/stub:/usr/bin:/bin" DRAIN_LIST="${tmp}/drains.txt" GITHUB_RUN_ID=33807667585 \
    QUILL_GCP_ENCLAVE_PENDING_INVENTORY="${tmp}/no-pending.txt" ${1+"$@"} \
    /bin/bash tools/cleanup-enclave-rollout-drains.sh >"${tmp}/out" 2>&1 || status=$?
}

resume_east='bash tools/gcp-mig-autoscaler.sh resume us-east4 quill-enclave-mig-useast4'

# The finalizer resumes the autoscaler of a region whose drain it clears.
run_cleanup 'us-east4\trollout:33800000001'
expect_status 0 "cleanup of a healthy stale rollout drain"
expect_order "${command_log}" 'bash tools/wait-region-attested.sh quill-enclave-mig-useast4-' \
  '--clear-drain-region us-east4' "${resume_east}"

run_cleanup 'us-east4\trollout:33800000001' STABLE=0
[ "${status}" -ne 0 ] || fail "an unstable region's drain cleanup passed"
grep -Fq 'gcp-mig-autoscaler.sh' "${command_log}" && fail "an uncleared drain resumed the autoscaler"

run_cleanup 'us-east4\trollout:33800000001' CLEAR_FAILS=1
[ "${status}" -ne 0 ] || fail "a failed drain clear passed the cleanup"
grep -Fq 'gcp-mig-autoscaler.sh' "${command_log}" && fail "a drain that was not cleared resumed the autoscaler"

run_cleanup 'europe-west4\toperator'
expect_status 0 "cleanup with an operator drain"
grep -Fq 'gcp-mig-autoscaler.sh' "${command_log}" && fail "an operator drain resumed the autoscaler"

run_cleanup 'us-east4\trollout:33800000001' FAIL_ON="${resume_east}"
[ "${status}" -ne 0 ] || fail "a failed resume did not fail the cleanup"
grep -Fq '::error::us-east4: drain cleared, but the autoscaler of quill-enclave-mig-useast4 stays off' "${tmp}/out" ||
  fail "a failed resume in the cleanup was not reported: $(cat "${tmp}/out")"

# --- 4. The workflows --------------------------------------------------------
"${python}" - <<'PY'
import re
from pathlib import Path


class Workflow:
    def __init__(self, path):
        self.path = path
        self.text = Path(path).read_text(encoding="utf-8")
        self.names = re.findall(r"^      - name: (.+)$", self.text, re.MULTILINE)

    def step(self, name):
        marker = f"      - name: {name}\n"
        assert self.text.count(marker) == 1, f"{self.path}: step {name!r} is missing or not unique"
        start = self.text.index(marker)
        end = self.text.find("\n      - name: ", start + 1)
        return self.text[start:] if end == -1 else self.text[start:end]

    def assert_order(self, order):
        positions = [self.text.index(f"      - name: {name}\n") for name in order if self.step(name)]
        assert positions == sorted(positions), f"{self.path}: steps out of order: {order}"


workflow = Workflow(".github/workflows/deploy-enclave-gcp.yml")
deploy = workflow.text
order = [
    "Capture pre-rollout templates (for rollback)",
    "Suspend us-central1 autoscaling for its rollout",
    "Drain us-central1 from canonical API DNS",
    "Roll the GCP MIG (us-central1)",
    "Wait for us-central1 MIG to be stable",
    "Wait for us-central1 instances to attest healthy",
    "Blocking per-instance streaming gate (us-central1)",
    "Canary gate — watch us-central1 only (post-stable)",
    "Restore us-central1 canonical drain state",
    "Recover us-central1 after any failed rollout step",
    "Apply us-central1 autoscaling after its rollout",
    "Roll Europe GCP MIG",
]
workflow.assert_order(order)
suspend = workflow.step("Suspend us-central1 autoscaling for its rollout")
assert "run: bash tools/gcp-mig-autoscaler.sh suspend us-central1 quill-enclave-mig-us" in suspend
assert "\n        if:" not in suspend and "continue-on-error" not in suspend
apply = workflow.step("Apply us-central1 autoscaling after its rollout")
assert "if: ${{ success() && steps.canary_us.outcome == 'success' }}" in apply
assert "run: bash tools/gcp-mig-autoscaler.sh apply us-central1 quill-enclave-mig-us" in apply
assert "continue-on-error" not in apply
for path in ("tools/gcp-mig-autoscaler.sh", "tools/tests/test-gcp-mig-autoscaler.sh"):
    assert f'      - "{path}"\n' in deploy, f"{path} does not trigger the deploy workflow"
assert "run: tools/tests/test-gcp-mig-autoscaler.sh" in workflow.step("Test the MIG autoscaler and its rollout holds (offline)")
assert deploy.count("            c3-standard-8 \\\n") == 3, "every secondary TDX rollout uses c3-standard-8"
assert "c3-standard-4" not in deploy

stockout = Workflow(".github/workflows/relieve-mig-stockout.yml")
order = [
    "Check the inputs",
    "Detach the autoscaler",
    "Add the replacement and wait until it attests",
    "Delete the VM in the zone",
    "Remove the named VM",
    "Clear the drain if the region is healthy, and reconcile DNS",
    "Attach the autoscaler again",
    "Say why the autoscaler stays detached",
    "Show the result",
]
stockout.assert_order(order)
detach = stockout.step("Detach the autoscaler")
assert 'run: bash tools/gcp-mig-autoscaler.sh detach "${REGION}" "${MIG}"' in detach
assert "\n        if:" not in detach, "both modes need a fixed-size group"
attach = stockout.step("Attach the autoscaler again")
assert "if: ${{ success() }}" in attach
assert 'run: bash tools/gcp-mig-autoscaler.sh apply "${REGION}" "${MIG}"' in attach
assert "if: ${{ failure() && steps.detach.outcome == 'success' }}" in stockout.step("Say why the autoscaler stays detached")
PY

# The relief tool refuses an autoscaled group in both modes and names the detach.
"${python}" tools/test_relieve_mig_stockout.py \
  RelieveMigStockoutTests.test_an_autoscaled_group_is_refused_in_both_modes_with_the_detach_command \
  >"${tmp}/out" 2>&1 || fail "relief tool refusal test failed: $(cat "${tmp}/out")"

echo "gcp MIG autoscaler tests passed"
