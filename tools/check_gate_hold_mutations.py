#!/usr/bin/env python3
"""Remove each gate-hold rule in turn on a disposable COPY; its test must fail.

Usage: python3 tools/check_gate_hold_mutations.py [name ...]
The baseline and the restored copy must pass each named test; a mutant that
does not compile or times out is build-broken, not detected.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PY = "tools/gate_hold.py"
LIB = "tools/gate-hold-lib.sh"
VERIFY = "tools/verify-region-before-dns.sh"
SECONDARY = "tools/roll-secondary-region.sh"
WORKFLOW = ".github/workflows/deploy-enclave-gcp.yml"
MUTATIONS = [
    ("canary pass never checked", PY,
     '        if kind != "canary":\n            return "pass"',
     '        if True:\n            return "pass"',
     "PassingGates.test_a_canary_pass_while_the_control_plane_moved_needs_fresh_evidence"),
    ("canary evidence ignores monitors", PY,
     "    expected = {(m.strip(), p) for m in monitors if m.strip() for p in GATEWAY_ONLY_PROBES}",
     '    expected = {("us-central1", p) for p in GATEWAY_ONLY_PROBES}',
     "PassingGates.test_a_canary_pass_while_the_control_plane_moved_needs_fresh_evidence"),
    ("canary failure held", PY,
     '    if kind == "canary":\n        return "gateway", "the canary reads only enclave-answered probes"',
     '    if False:\n        return "gateway", "the canary reads only enclave-answered probes"',
     "GatewayFailures.test_a_failed_canary_is_always_the_gateways"),
    ("every pre-dns failure held", PY,
     '    if kind == "pre-dns" and status != CP_DEPENDENT_STATUS:',
     '    if False:',
     "GatewayFailures.test_a_pre_dns_failure_outside_the_request_path_is_the_gateways"),
    ("enclave-only failure held", PY,
     "        own = gateway_only_failure(payload, region, since, monitors)\n        if own:",
     "        own = gateway_only_failure(payload, region, since, monitors)\n        if False:",
     "GatewayFailures.test_the_latest_enclave_only_failure_is_the_gateways_even_while_moving"),
    ("any enclave blip blamed", PY,
     "        if key not in latest or created > latest[key][0]:",
     "        if key not in latest or _status(row) in FAILING:",
     "GatewayFailures.test_an_early_enclave_blip_that_recovered_is_not_blamed"),
    ("stale enclave failure blamed", PY,
     "        if (row.get(\"target_region\") != region or created is None or created < since",
     "        if (row.get(\"target_region\") != region or created is None",
     "GatewayFailures.test_a_stale_enclave_failure_is_not_this_windows"),
    ("held lease ignored", PY,
     '            if entry["held"]:\n                return f"a {lane} lease is held',
     '            if False:\n                return f"a {lane} lease is held',
     "InconclusiveFailures.test_a_control_plane_lease_at_either_end_is_inconclusive"),
    ("public surface lane ignored", PY,
     'MOVING_LANES = ("control-plane", "public-surface")',
     'MOVING_LANES = ("control-plane",)',
     "InconclusiveFailures.test_a_control_plane_lease_at_either_end_is_inconclusive"),
    ("epochs ignored", PY,
     '        if before["lanes"][lane].get("epoch") != after["lanes"][lane].get("epoch"):',
     "        if False:",
     "InconclusiveFailures.test_a_lease_granted_and_released_inside_the_window_is_inconclusive"),
    ("unreadable lanes read as still", PY,
     '        return "the control-plane lane state is unreadable"',
     "        return None",
     "InconclusiveFailures.test_unreadable_or_changed_lane_state_is_inconclusive"),
    ("format change ignored", PY,
     '        return "the journal format changed during the window"',
     "        pass",
     "InconclusiveFailures.test_unreadable_or_changed_lane_state_is_inconclusive"),
    ("unreadable status page blamed on the gateway", PY,
     '        return "status.json is unreadable (the control plane serves it)"',
     "        return None",
     "InconclusiveFailures.test_an_unreadable_status_page_is_inconclusive"),
    ("control-plane probes ignored", PY,
     "        if monitor in expected and probe in CONTROL_PLANE_PROBES and _status(row) in FAILING:",
     "        if False:",
     "InconclusiveFailures.test_a_fresh_control_plane_probe_down_is_inconclusive"),
    ("trust_degraded read as up", PY,
     'FAILING = frozenset({"down", "trust_degraded"})', 'FAILING = frozenset({"down"})',
     "InconclusiveFailures.test_a_fresh_control_plane_probe_down_is_inconclusive"),
    ("stale control-plane probe counted", PY,
     "        if not _fresh(row, since):\n            continue\n        monitor",
     "        if False:\n            continue\n        monitor",
     "InconclusiveFailures.test_a_stale_control_plane_probe_down_does_not_count"),
    ("silent monitor ignored", PY,
     "    for monitor in sorted(expected - ingesting):", "    for monitor in []:",
     "InconclusiveFailures.test_a_monitor_that_ingested_nothing_is_inconclusive"),
    ("samples ignored", PY,
     "    rows = [*(checks if isinstance(checks, list) else []), *(samples if isinstance(samples, list) else [])]",
     "    rows = [*(checks if isinstance(checks, list) else [])]",
     "InconclusiveFailures.test_samples_are_read_as_well_as_current_checks"),
    ("still control plane held anyway", PY,
     '    return "gateway", "the control plane was still and healthy for the whole window"',
     '    return "inconclusive", "always"',
     "GatewayFailures.test_a_failure_with_a_still_healthy_control_plane_is_the_gateways"),
    ("hold passes a failed gate", LIB,
     '        if gate_hold_wait "${region}" "${kind} gate inconclusive: ${decision#inconclusive:}"; then\n          continue\n        fi',
     '        if gate_hold_wait "${region}" "${kind} gate inconclusive: ${decision#inconclusive:}"; then\n          return 0\n        fi',
     "Library.test_a_failure_while_the_control_plane_moves_holds_then_passes_only_when_the_gate_does"),
    ("hold never ends", LIB,
     '  if [ "${held}" -ge "${max}" ]; then', '  if false; then',
     "Library.test_a_failure_while_the_control_plane_keeps_moving_fails_closed_after_the_bound"),
    ("bound spent returns success", LIB,
     '        if [ "${status}" -ne 0 ]; then return "${status}"; fi\n        return 1 ;;',
     '        return 0 ;;',
     "Library.test_a_canary_that_passed_blind_while_moving_reruns_then_fails_closed"),
    ("hold clock per gate", LIB,
     '  started="$(cat "${file}" 2>/dev/null || true)"', '  started=""',
     "Library.test_the_hold_clock_is_shared_by_a_regions_gates"),
    ("gateway failure swallowed", LIB,
     '        echo "${region}: ${kind} gate failed; attributed to the gateway: ${decision#gateway:}" >&2\n        rm -rf "${dir}"\n        return "${status}" ;;',
     '        echo "${region}: ${kind} gate failed; attributed to the gateway: ${decision#gateway:}" >&2\n        rm -rf "${dir}"\n        return 0 ;;',
     "Library.test_a_gateway_failure_fails_at_once_with_the_gates_status"),
    ("missing decision passes", LIB,
     "        # stands, exactly as it did before this library existed.\n        rm -rf \"${dir}\"\n        return \"${status}\" ;;",
     "        # stands, exactly as it did before this library existed.\n        rm -rf \"${dir}\"\n        return 0 ;;",
     "Library.test_no_decision_leaves_the_gates_own_verdict"),
    ("between hook skipped", LIB,
     '    if [ -n "${GATE_HOLD_BETWEEN:-}" ]; then "${GATE_HOLD_BETWEEN}"; fi',
     "    :",
     "Library.test_holding_runs_the_between_hook_and_it_can_stop_the_hold"),
    ("window not shared with the gate", LIB,
     '    export WAIT_UP_STARTED_AT="${since}"', '    export WAIT_UP_STARTED_AT=0',
     "Library.test_the_gate_and_the_classifier_judge_the_same_window"),
    ("presence fails a healthy region at once", LIB,
     '    if [ "${mode}" = once ] || ! gate_hold_wait "${region}" "status.json is unreadable"; then',
     '    if true; then',
     "Library.test_presence_recovers_when_the_page_comes_back"),
    ("presence once holds", LIB,
     '    if [ "${mode}" = once ] || ! gate_hold_wait "${region}" "status.json is unreadable"; then',
     '    if ! gate_hold_wait "${region}" "status.json is unreadable"; then',
     "Library.test_presence_once_never_holds"),
    ("inference failure looks like the gateway's", VERIFY,
     '    echo "${REGION}: ${stage} direct inference canary on ${ip} did not succeed" >&2\n    return "${CP_DEPENDENT_STATUS}"',
     '    echo "${REGION}: ${stage} direct inference canary on ${ip} did not succeed" >&2\n    return 1',
     "Wiring.test_request_path_failures_carry_the_control_plane_status"),
    ("attestation failure looks like the control plane's", VERIFY,
     '    echo "${REGION}: ${ip} never passed ${stage} attestation" >&2\n    return 1',
     '    echo "${REGION}: ${ip} never passed ${stage} attestation" >&2\n    return "${CP_DEPENDENT_STATUS}"',
     "Wiring.test_request_path_failures_carry_the_control_plane_status"),
    ("secondary pong gate unwrapped", SECONDARY,
     'rollout_step gate_hold pong "${region}" interruptible bash',
     'rollout_step interruptible bash',
     "Wiring.test_every_control_plane_dependent_gate_is_held_not_failed"),
    ("us-central1 pre-dns gate unwrapped", WORKFLOW,
     "          gate_hold pre-dns us-central1 bash tools/verify-region-before-dns.sh",
     "          bash tools/verify-region-before-dns.sh",
     "Wiring.test_every_control_plane_dependent_gate_is_held_not_failed"),
    ("worker deadline too short for the hold", WORKFLOW,
     'TR_SECONDARY_WORKER_TIMEOUT: "5100"', 'TR_SECONDARY_WORKER_TIMEOUT: "3300"',
     "Wiring.test_timeouts_leave_room_for_the_hold_bound"),
]


def main(names: set[str]) -> int:
    results = []
    with tempfile.TemporaryDirectory(prefix="gate-hold-mutations-") as directory:
        copy = Path(directory) / "repo"
        copy.mkdir()
        shutil.copytree(ROOT / "tools", copy / "tools", ignore=shutil.ignore_patterns("__pycache__"))
        shutil.copytree(ROOT / ".github", copy / ".github")

        def run(test: str) -> str:
            completed = subprocess.run(  # noqa: S603 - fixed test command on the copy
                [sys.executable, "tools/test_gate_hold.py", test], cwd=copy,
                env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
                capture_output=True, text=True, timeout=240, check=False,
            )
            output = completed.stdout + completed.stderr
            if "SyntaxError" in output or "ImportError" in output:
                return "build-broken"
            return "survived" if completed.returncode == 0 else "red"

        for name, relative, old, new, test in MUTATIONS:
            if names and name not in names:
                continue
            path = copy / relative
            original = path.read_text()
            assert original.count(old) == 1, f"{name}: anchor found {original.count(old)} times"
            assert run(test) == "survived", f"baseline failed: {name}"
            try:
                path.write_text(original.replace(old, new))
                if path.suffix == ".py":
                    compile(path.read_text(), str(path), "exec")
                result = run(test)
            except (SyntaxError, subprocess.TimeoutExpired):
                result = "build-broken"
            finally:
                path.write_text(original)
            assert run(test) == "survived", f"restore failed: {name}"
            results.append({"mutation": name, "result": result, "gate": test})
            print(json.dumps(results[-1]), flush=True)
    killed = sum(r["result"] == "red" for r in results)
    print(f"{killed}/{len(results)} mutants killed")
    return 0 if killed == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main(set(sys.argv[1:])))
