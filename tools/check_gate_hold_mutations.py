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
    # Classifier (tools/gate_hold.py)
    ("canary pass never checked", PY,
     '        if kind != "canary":\n            return "pass"',
     '        if True:\n            return "pass"',
     "PassingGates.test_a_canary_pass_while_the_control_plane_moved_needs_fresh_evidence"),
    ("canary evidence ignores monitors", PY,
     "    expected = {(m.strip(), p) for m in monitors if m.strip() for p in GATEWAY_ONLY_PROBES}",
     '    expected = {("us-central1", p) for p in GATEWAY_ONLY_PROBES}',
     "PassingGates.test_a_canary_pass_while_the_control_plane_moved_needs_fresh_evidence"),
    ("canary evidence accepts other regions", PY,
     '        if row.get("target_region") != region or key not in expected or created is None or created < since:',
     '        if key not in expected or created is None or created < since:',
     "PassingGates.test_a_blind_canary_pass_counts_only_this_regions_rows"),
    ("canary evidence accepts failing rows", PY,
     '            return "gateway", f"the latest {probe} from {monitor} read {status}"',
     '            pass',
     "PassingGates.test_a_blind_canary_pass_over_failing_enclave_rows_is_the_gateways"),
    ("canary evidence accepts rows that are not up", PY,
     '    if not_up:\n        return "inconclusive", ", ".join(not_up)',
     '    if False:\n        return "inconclusive", ", ".join(not_up)',
     "PassingGates.test_a_blind_canary_pass_needs_the_latest_rows_up"),
    ("canary failure held", PY,
     '    if kind == "canary":\n        return "gateway", "the canary reads only enclave-answered probes"',
     '    if False:\n        return "gateway", "the canary reads only enclave-answered probes"',
     "GatewayFailures.test_a_failed_canary_is_always_the_gateways"),
    ("every pre-dns failure held", PY,
     '    if kind == "pre-dns" and status not in (CP_DEPENDENT_STATUS, TIMEOUT_STATUS):',
     '    if False:',
     "GatewayFailures.test_a_pre_dns_failure_outside_the_request_path_is_the_gateways"),
    ("pre-dns timeout blamed on the gateway", PY,
     '    if kind == "pre-dns" and status not in (CP_DEPENDENT_STATUS, TIMEOUT_STATUS):',
     '    if kind == "pre-dns" and status != CP_DEPENDENT_STATUS:',
     "GatewayFailures.test_a_pre_dns_timeout_counts_as_a_request_path_failure"),
    ("enclave-only failure held", PY,
     "        own = gateway_only_failure(payload, region, since, monitors)\n        if own:",
     "        own = gateway_only_failure(payload, region, since, monitors)\n        if False:",
     "GatewayFailures.test_the_latest_enclave_only_failure_is_the_gateways_even_while_moving"),
    ("any enclave blip blamed", PY,
     "        if key not in latest or created > latest[key][0]:\n            latest[key] = (created, _status(row))\n    for (monitor, probe), (_, status) in sorted(latest.items()):\n        if status in FAILING:\n            return f\"{probe} from {monitor} read {status}\"",
     "        if key not in latest or _status(row) in FAILING:\n            latest[key] = (created, _status(row))\n    for (monitor, probe), (_, status) in sorted(latest.items()):\n        if status in FAILING:\n            return f\"{probe} from {monitor} read {status}\"",
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
     'MOVING_LANES = ("control-plane", "public-surface")', 'MOVING_LANES = ("control-plane",)',
     "InconclusiveFailures.test_a_control_plane_lease_at_either_end_is_inconclusive"),
    ("epochs ignored", PY,
     '        if before["lanes"][lane].get("epoch") != after["lanes"][lane].get("epoch"):', "        if False:",
     "InconclusiveFailures.test_a_lease_granted_and_released_inside_the_window_is_inconclusive"),
    ("journal id ignored", PY,
     '    if before.get("journal_id") != after.get("journal_id"):', "    if False:",
     "InconclusiveFailures.test_a_recreated_journal_is_inconclusive"),
    ("journal id not required", PY,
     '    if snapshot["schema_version"] == 3 and not (', "    if False and not (",
     "InconclusiveFailures.test_unreadable_or_changed_lane_state_is_inconclusive"),
    ("unreadable lanes read as still", PY,
     '        return "the control-plane lane state is unreadable"', "        return None",
     "InconclusiveFailures.test_unreadable_or_changed_lane_state_is_inconclusive"),
    ("format change ignored", PY,
     '        return "the journal format changed during the window"', "        pass",
     "InconclusiveFailures.test_unreadable_or_changed_lane_state_is_inconclusive"),
    ("unreadable status page blamed on the gateway", PY,
     '        return "status.json is unreadable (the control plane serves it)"', "        return None",
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
    ("empty monitor set accepted by the classifier", PY,
     "    if not monitors:\n        # Every rule would pass vacuously over an empty monitor set.\n        parser.error(",
     "    if False:\n        # Every rule would pass vacuously over an empty monitor set.\n        parser.error(",
     "InconclusiveFailures.test_an_empty_monitor_set_is_rejected"),
    ("still control plane held anyway", PY,
     '    return "gateway", "the control plane was still and healthy for the whole window"',
     '    return "inconclusive", "always"',
     "GatewayFailures.test_a_failure_with_a_still_healthy_control_plane_is_the_gateways"),
    # The hold loop (tools/gate-hold-lib.sh)
    ("hold passes a failed gate", LIB,
     '        if [ "${status_after_pause}" -eq 0 ]; then\n          continue',
     '        if [ "${status_after_pause}" -eq 0 ]; then\n          return 0',
     "Library.test_a_failure_while_the_control_plane_moves_holds_then_passes_only_when_the_gate_does"),
    ("per-gate bound ignored", LIB,
     "          hold_deadline=$(( $(date +%s) + max ))", "          hold_deadline=$(( $(date +%s) + 100000 ))",
     "Library.test_a_failure_while_the_control_plane_keeps_moving_fails_closed_after_the_bound"),
    ("deadline checked only between attempts", LIB,
     '    gate_hold_run "${attempt_deadline}" "$@" || status=$?',
     '    gate_hold_run "" "$@" || status=$?',
     "Library.test_the_hold_deadline_stops_the_attempt_in_flight"),
    ("attempt cap ignored", LIB,
     '    if [ "${cap}" -gt 0 ]; then attempt_deadline=$((since + cap)); fi',
     "    :",
     "Library.test_an_attempt_over_its_cap_is_stopped_and_judged"),
    ("clock shared across a region's gates", LIB,
     "          hold_deadline=$(( $(date +%s) + max ))",
     "          hold_deadline=$(( ${GATE_HOLD_REGION_START:=$(date +%s)} + max ))",
     "Library.test_the_hold_clock_is_per_gate"),
    ("job budget ignored", LIB,
     '  if [ "${now}" -ge "${deadline}" ] || [ "${spent}" -ge "${budget}" ]; then',
     '  if [ "${now}" -ge "${deadline}" ]; then',
     "Library.test_the_job_budget_ends_every_hold"),
    ("hold not recorded", LIB,
     "    printf '%s\\n' \"$(( $(date +%s) - started ))\" >> \"${dir}/held-${region}\" || return 1",
     "    :",
     "Library.test_a_hold_is_recorded_for_the_job_budget"),
    ("unwritable hold record ignored", LIB,
     '          if ! gate_hold_open "${state}" "${region}"; then',
     "          if false; then",
     "Library.test_an_unwritable_hold_record_fails_closed"),
    ("bound spent returns success", LIB,
     '        [ "${status}" -ne 0 ] && return "${status}"\n        return 1 ;;\n      *)',
     '        return 0 ;;\n      *)',
     "Library.test_a_blind_canary_pass_with_no_budget_left_fails_closed"),
    ("gateway failure swallowed", LIB,
     '        [ "${status}" -ne 0 ] && return "${status}"\n        return 1 ;;\n      inconclusive:*)',
     '        return 0 ;;\n      inconclusive:*)',
     "Library.test_a_gateway_failure_fails_at_once_with_the_gates_status"),
    ("missing decision passes a canary", LIB,
     '          echo "::error::${region}: the classifier could not decide a ${kind} pass; failing closed" >&2\n          return 1',
     '          echo "::error::${region}: the classifier could not decide a ${kind} pass; failing closed" >&2\n          return 0',
     "Library.test_no_decision_leaves_a_failure_and_fails_a_canary_pass_closed"),
    ("stop ignored in flight", LIB,
     '    if [ "${cut}" -eq 1 ] || { [ -n "${GATE_HOLD_STOP:-}" ] && "${GATE_HOLD_STOP}"; }; then',
     '    if [ "${cut}" -eq 1 ]; then',
     "Library.test_a_stop_kills_the_attempt_in_flight_and_runs_the_stop_hook"),
    ("stop ignored while holding", LIB,
     '    if [ -n "${GATE_HOLD_STOP:-}" ] && "${GATE_HOLD_STOP}"; then return 75; fi',
     "    :",
     "Library.test_a_stop_while_holding_records_the_hold_and_runs_the_hook"),
    ("overlapping holds not re-read", LIB,
     '    if [ "${cut}" -eq 0 ] && [ -n "${_gh_budget_state:-}" ] && [ $((polls % 5)) -eq 0 ] \\',
     '    if false && [ $((polls % 5)) -eq 0 ] \\',
     "Library.test_overlapping_holds_share_the_budget_as_they_spend_it"),
    ("a gate that changed dns is re-run", LIB,
     '    if [ -e "${work}/no-rerun" ] && [ "${status}" -ne 0 ]; then', "    if false; then",
     "Library.test_a_gate_that_changed_dns_is_never_re_run"),
    ("no grace after a kill", LIB,
     '      for _ in $(seq 1 "${grace}"); do', "      for _ in 1; do",
     "Library.test_a_killed_attempt_gets_its_grace_to_clean_up"),
    ("region spend ignores an open hold", LIB,
     '  [[ "${value}" =~ ^[0-9]+$ ]] && total=$((total + $(date +%s) - value))\n  printf \'%s\\n\' "${total}"\n}\n\ngate_hold_open',
     '  printf \'%s\\n\' "${total}"\n}\n\ngate_hold_open',
     "Library.test_region_spend_counts_finished_and_open_holds"),
    ("window not shared with the gate", LIB,
     '    export WAIT_UP_STARTED_AT="${since}"', '    export WAIT_UP_STARTED_AT=0',
     "Library.test_the_gate_and_the_classifier_judge_the_same_window"),
    ("lane reads unbounded", LIB,
     '  deadline="$(gate_hold_min "$(( $(date +%s) + read_seconds ))" "${deadline}")"',
     "  :",
     "Library.test_a_slow_lane_read_is_cut_off"),
    ("status read cached", LIB,
     "  printf '%s?gate_hold=%s%s%s\\n'", "  printf '%s\\n'",
     "Library.test_status_reads_defeat_caching"),
    ("settings not validated", LIB,
     '  if [[ "${value}" =~ ^[1-9][0-9]*$ ]] || { [ -n "${zero}" ] && [ "${value}" = 0 ]; }; then',
     "  if true; then",
     "Library.test_settings_must_be_whole_seconds"),
    ("empty monitor set accepted by the library", LIB,
     '  if ! [[ "${monitors//[[:space:],]/}" =~ [a-z] ]]; then', "  if false; then",
     "Library.test_an_empty_monitor_set_is_refused_before_the_gate_runs"),
    ("presence fails a healthy region at once", LIB,
     '    gate_hold_pause "${region}" "status.json is unreadable" "${deadline}" \\\n      "${state}" "${budget}" "${pause}" "${max}" || break',
     "    break",
     "Library.test_presence_recovers_when_the_page_comes_back"),
    ("presence once holds", LIB,
     '    [ "${mode}" = once ] && break', "    :",
     "Library.test_presence_once_never_holds"),
    # The gates and the region (verify, roll-secondary, workflow)
    ("inference failure looks like the gateway's", VERIFY,
     '    echo "${REGION}: ${stage} direct inference canary on ${ip} did not succeed" >&2\n    return "${CP_DEPENDENT_STATUS}"',
     '    echo "${REGION}: ${stage} direct inference canary on ${ip} did not succeed" >&2\n    return 1',
     "Wiring.test_request_path_failures_carry_the_control_plane_status"),
    ("attestation failure looks like the control plane's", VERIFY,
     '    echo "${REGION}: ${ip} never passed ${stage} attestation" >&2\n    return 1',
     '    echo "${REGION}: ${ip} never passed ${stage} attestation" >&2\n    return "${CP_DEPENDENT_STATUS}"',
     "Wiring.test_request_path_failures_carry_the_control_plane_status"),
    ("cold bootstrap offered for a re-run", VERIFY,
     "    status=1\n  fi\n  exit \"${status}\"", "    :\n  fi\n  exit \"${status}\"",
     "Wiring.test_a_first_deployment_pre_dns_gate_is_never_re_run"),
    ("first deployment pre-dns re-run", SECONDARY,
     '  rollout_step bash tools/verify-region-before-dns.sh \\\n    "${region}" "${instance_filter}" "${IMAGE_DIGEST}"\nelse',
     '  TR_CP_HOLD_ATTEMPT_SECONDS=720 rollout_step gate_hold pre-dns "${region}" bash tools/verify-region-before-dns.sh \\\n    "${region}" "${instance_filter}" "${IMAGE_DIGEST}"\nelse',
     "OneRegion.test_a_first_deployment_pre_dns_failure_is_not_re_run"),
    ("secondary pong gate unwrapped", SECONDARY,
     'rollout_step gate_hold pong "${region}" bash', 'rollout_step bash',
     "OneRegion.test_a_pong_failure_while_the_control_plane_moves_holds_then_promotes"),
    ("forward deadline ignores holds", SECONDARY,
     '  [ "$(date +%s)" -ge "$((deadline + held))" ]', '  [ "$(date +%s)" -ge "${deadline}" ]',
     "OneRegion.test_holding_extends_the_forward_deadline_by_exactly_the_hold"),
    ("forward deadline never passes", SECONDARY,
     '  [ "$(date +%s)" -ge "$((deadline + held))" ]', "  false",
     "OneRegion.test_work_outside_a_hold_keeps_the_base_deadline"),
    ("a killed pre-dns gate skips the cold restore", VERIFY,
     "trap 'exit 143' TERM\n", "",
     "VerifyColdSwap.test_term_mid_cold_swap_restores_the_cname_and_marks_no_rerun"),
    ("a cold swap is not marked against re-runs", VERIFY,
     '    : > "${GATE_HOLD_NO_RERUN_MARK}" || true', "    :",
     "VerifyColdSwap.test_term_mid_cold_swap_restores_the_cname_and_marks_no_rerun"),
    ("a stuck hold record extends the deadline forever", SECONDARY,
     '  if [ "${held}" -gt "${budget}" ]; then held="${budget}"; fi', "  :",
     "OneRegion.test_a_stuck_hold_record_cannot_extend_the_deadline_forever"),
    ("the cold restore can be interrupted", VERIFY,
     "  trap '' TERM INT\n  rm -rf \"${response_dir}\"", "  rm -rf \"${response_dir}\"",
     "VerifyColdSwap.test_int_and_term_during_the_restore_cannot_cut_it_short"),
    ("stable wait back to 45 minutes", WORKFLOW,
     "        # margin under GitHub's 360-minute limit (see timeout-minutes above).\n        timeout-minutes: 40",
     "        # margin under GitHub's 360-minute limit (see timeout-minutes above).\n        timeout-minutes: 45",
     "Wiring.test_the_rollout_job_ends_before_githubs_limit_in_the_worst_case"),
    ("recovery hides the control-plane cause", SECONDARY,
     '      if [ "${recovery_status}" -eq 65 ]; then', "      if false; then",
     "OneRegion.test_recovery_that_meets_a_bad_control_plane_says_so"),
    ("us-central1 pre-dns gate unwrapped", WORKFLOW,
     "          gate_hold pre-dns us-central1 bash tools/verify-region-before-dns.sh",
     "          bash tools/verify-region-before-dns.sh",
     "Wiring.test_every_control_plane_dependent_gate_is_held_not_failed"),
    ("worker deadline past what its step allows", WORKFLOW,
     'TR_SECONDARY_WORKER_TIMEOUT: "3300"', 'TR_SECONDARY_WORKER_TIMEOUT: "6000"',
     "Wiring.test_timeouts_cover_each_gates_true_worst_case"),
    ("pong step too short for its worst case", WORKFLOW,
     "        # A 12-minute attempt, the 20-minute hold, bounded reads (see above).\n        timeout-minutes: 40",
     "        # A 12-minute attempt, the 20-minute hold, bounded reads (see above).\n        timeout-minutes: 35",
     "Wiring.test_timeouts_cover_each_gates_true_worst_case"),
    ("US West without a deadline", WORKFLOW,
     "          export TR_SECONDARY_DEADLINE\n", "",
     "Wiring.test_us_west_has_a_forward_deadline"),
    ("job limit past the worst case", WORKFLOW,
     "    timeout-minutes: 360", "    timeout-minutes: 355",
     "Wiring.test_the_rollout_job_ends_before_githubs_limit_in_the_worst_case"),
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
