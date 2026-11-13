#!/usr/bin/env python3
"""Gateway gates stay attributable while the control plane may move.

Covers every rule of tools/gate_hold.py, the hold loop in
tools/gate-hold-lib.sh (run for real against stubbed lanes, status.json and
gates), the wiring in the workflow and tools/roll-secondary-region.sh, and the
gateway side of quill-router's interleavings table
(docs/design/component-leases-v3.md). tools/check_gate_hold_mutations.py
removes each rule in turn and requires a named test here to fail.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import gate_hold  # noqa: E402

TEST_BASH = os.environ.get("TR_TEST_BASH", "/bin/bash")
MONITORS = ["us-central1", "europe-west4"]
SINCE = 1_800_000_000.0


def iso(epoch: float) -> str:
    return dt.datetime.fromtimestamp(epoch, dt.UTC).isoformat().replace("+00:00", "Z")


def row(probe: str, monitor: str, status: str = "up", *, target: str | None = None,
        at: float = SINCE + 60) -> dict[str, object]:
    return {"probe_type": probe, "monitor_region": monitor, "status": status,
            "target_region": target, "created_at": iso(at)}


def page(*rows: dict[str, object]) -> dict[str, object]:
    return {"data": {"current": {"checks": list(rows)}, "samples": []}}


def healthy_page(region: str = "us-central1", at: float = SINCE + 60) -> dict[str, object]:
    rows = []
    for monitor in MONITORS:
        rows += [row("gateway_authorize", monitor, at=at), row("gateway_settle", monitor, at=at),
                 row("tls_health", monitor, target=region, at=at),
                 row("attestation_nonce", monitor, target=region, at=at),
                 row("openai_sdk_pong", monitor, "down", target=region, at=at)]
    return page(*rows)


def lanes(version: int = 3, *, held: str | None = None, state: str = "active",
          epochs: dict[str, int] | None = None) -> dict[str, object]:
    epochs = epochs or {}
    out = {}
    for lane in ("control-plane", "gateway", "public-surface"):
        out[lane] = {"held": lane == held or lane == "gateway",
                     "state": state if lane == held else ("active" if lane == "gateway" else None),
                     "epoch": (epochs.get(lane, 4) if version == 3 else None)}
    return {"schema_version": version, "cloud": "gcp", "lanes": out,
            "journal_id": ("j" * 32 if version == 3 else None)}


STILL = lanes()


def decide(kind: str, status: int, *, before: object = STILL, after: object = STILL,
           payload: object = None, region: str = "us-central1") -> str:
    return gate_hold.decide(kind, region, status, SINCE, before, after,
                            healthy_page(region) if payload is None else payload, MONITORS)


class PassingGates(unittest.TestCase):
    def test_a_passing_gate_passes_without_reading_the_control_plane(self) -> None:
        for kind in ("pong", "pre-dns", "discovery"):
            self.assertEqual(gate_hold.decide(kind, "us-central1", 0, SINCE, None, None, None, MONITORS), "pass")

    def test_a_canary_pass_stands_when_the_control_plane_was_still(self) -> None:
        self.assertEqual(decide("canary", 0, payload=page()), "pass")

    def test_a_canary_pass_while_the_control_plane_moved_needs_fresh_evidence(self) -> None:
        moving = lanes(held="control-plane")
        self.assertEqual(decide("canary", 0, after=moving), "pass")
        stale = healthy_page(at=SINCE - 10)
        verdict = decide("canary", 0, after=moving, payload=stale)
        self.assertTrue(verdict.startswith("inconclusive:"), verdict)
        one_monitor = page(row("tls_health", "us-central1", target="us-central1"),
                           row("attestation_nonce", "us-central1", target="us-central1"))
        verdict = decide("canary", 0, after=moving, payload=one_monitor)
        self.assertIn("europe-west4", verdict)
        self.assertTrue(verdict.startswith("inconclusive:"), verdict)

    def test_a_blind_canary_pass_over_failing_enclave_rows_is_the_gateways(self) -> None:
        """Review of #772: fresh rows must be up, not merely present."""
        for snapshot in (lanes(held="control-plane"), None):  # moving, or lanes unreadable
            down = page(*[{**r, "status": "down"} if r["probe_type"] in gate_hold.GATEWAY_ONLY_PROBES else r
                          for r in healthy_page()["data"]["current"]["checks"]])
            verdict = decide("canary", 0, after=snapshot, payload=down)
            self.assertTrue(verdict.startswith("gateway:"), verdict)

    def test_a_blind_canary_pass_needs_the_latest_rows_up(self) -> None:
        moving = lanes(held="control-plane")
        degraded = healthy_page()
        degraded["data"]["current"]["checks"].append(
            row("tls_health", "europe-west4", "degraded", target="us-central1", at=SINCE + 90))
        verdict = decide("canary", 0, after=moving, payload=degraded)
        self.assertTrue(verdict.startswith("inconclusive:"), verdict)
        recovered = healthy_page(at=SINCE + 90)
        recovered["data"]["current"]["checks"].append(
            row("tls_health", "europe-west4", "down", target="us-central1", at=SINCE + 30))
        self.assertEqual(decide("canary", 0, after=moving, payload=recovered), "pass")

    def test_a_blind_canary_pass_counts_only_this_regions_rows(self) -> None:
        moving = lanes(held="control-plane")
        other_region = healthy_page(region="europe-west4")
        verdict = decide("canary", 0, after=moving, payload=other_region)
        self.assertTrue(verdict.startswith("inconclusive:") and "no fresh" in verdict, verdict)

    def test_a_canary_pass_with_an_unreadable_page_while_moving_is_inconclusive(self) -> None:
        verdict = decide("canary", 0, after=lanes(held="control-plane"), payload={"oops": 1})
        self.assertTrue(verdict.startswith("inconclusive:"), verdict)


class GatewayFailures(unittest.TestCase):
    def test_a_failed_canary_is_always_the_gateways(self) -> None:
        verdict = decide("canary", 1, after=lanes(held="control-plane"))
        self.assertTrue(verdict.startswith("gateway:"), verdict)

    def test_a_pre_dns_timeout_counts_as_a_request_path_failure(self) -> None:
        moving = lanes(held="control-plane")
        self.assertTrue(decide("pre-dns", gate_hold.TIMEOUT_STATUS, after=moving).startswith("inconclusive:"))
        self.assertTrue(decide("pre-dns", gate_hold.TIMEOUT_STATUS).startswith("gateway:"))

    def test_a_pre_dns_failure_outside_the_request_path_is_the_gateways(self) -> None:
        for status in (1, 2, 22):
            verdict = decide("pre-dns", status, after=lanes(held="control-plane"))
            self.assertTrue(verdict.startswith("gateway:"), verdict)

    def test_the_latest_enclave_only_failure_is_the_gateways_even_while_moving(self) -> None:
        payload = healthy_page()
        payload["data"]["current"]["checks"].append(
            row("attestation_nonce", "europe-west4", "down", target="us-central1", at=SINCE + 90))
        verdict = decide("pong", 1, after=lanes(held="control-plane"), payload=payload)
        self.assertTrue(verdict.startswith("gateway:attestation_nonce"), verdict)

    def test_an_early_enclave_blip_that_recovered_is_not_blamed(self) -> None:
        payload = healthy_page(at=SINCE + 60)
        payload["data"]["current"]["checks"].append(
            row("tls_health", "us-central1", "down", target="us-central1", at=SINCE + 5))
        verdict = decide("pong", 1, after=lanes(held="control-plane"), payload=payload)
        self.assertTrue(verdict.startswith("inconclusive:"), verdict)

    def test_a_stale_enclave_failure_is_not_this_windows(self) -> None:
        # The only tls_health row from us-central1 predates the window.
        payload = page(*[r for r in healthy_page()["data"]["current"]["checks"]
                         if not (r["probe_type"] == "tls_health" and r["monitor_region"] == "us-central1")],
                       row("tls_health", "us-central1", "down", target="us-central1", at=SINCE - 1))
        verdict = decide("pong", 1, after=lanes(held="control-plane"), payload=payload)
        self.assertTrue(verdict.startswith("inconclusive:"), verdict)

    def test_a_failure_with_a_still_healthy_control_plane_is_the_gateways(self) -> None:
        for kind, status in (("pong", 1), ("pre-dns", gate_hold.CP_DEPENDENT_STATUS), ("discovery", 1)):
            verdict = decide(kind, status)
            self.assertTrue(verdict.startswith("gateway:"), (kind, verdict))

    def test_v2_journal_with_only_the_gateways_lease_is_still(self) -> None:
        v2 = lanes(2)
        self.assertIsNone(gate_hold.control_plane_moved(v2, v2))
        self.assertTrue(decide("pong", 1, before=v2, after=v2).startswith("gateway:"))


class InconclusiveFailures(unittest.TestCase):
    def test_a_control_plane_lease_at_either_end_is_inconclusive(self) -> None:
        for lane in ("control-plane", "public-surface"):
            for before, after in ((lanes(held=lane), STILL), (STILL, lanes(held=lane))):
                verdict = decide("pong", 1, before=before, after=after)
                self.assertEqual(verdict.split(":")[0], "inconclusive", (lane, verdict))
                self.assertIn(lane, verdict)

    def test_a_blocked_control_plane_lease_is_inconclusive(self) -> None:
        verdict = decide("pre-dns", 65, after=lanes(held="control-plane", state="blocked"))
        self.assertIn("blocked", verdict)
        self.assertTrue(verdict.startswith("inconclusive:"))

    def test_a_lease_granted_and_released_inside_the_window_is_inconclusive(self) -> None:
        for lane in ("control-plane", "public-surface"):
            after = lanes(epochs={lane: 5})
            verdict = decide("pong", 1, after=after)
            self.assertTrue(verdict.startswith("inconclusive:"), verdict)
            self.assertIn("granted during the window", verdict)

    def test_unreadable_or_changed_lane_state_is_inconclusive(self) -> None:
        bad = [None, {}, {"schema_version": 3, "lanes": {}},
               {"schema_version": 3, "lanes": {"control-plane": {"held": "no", "epoch": 1},
                                                "public-surface": {"held": False, "epoch": 1}}},
               {"schema_version": 3, "lanes": {"control-plane": {"held": False, "epoch": -1},
                                                "public-surface": {"held": False, "epoch": 1}}},
               {"schema_version": 4, "lanes": STILL["lanes"]}]
        for snapshot in bad:
            verdict = decide("pong", 1, before=snapshot)
            self.assertTrue(verdict.startswith("inconclusive:"), (snapshot, verdict))
        verdict = decide("pong", 1, before=lanes(2), after=lanes(3))
        self.assertIn("format changed", verdict)
        missing_id = {**lanes(), "journal_id": None}
        self.assertTrue(decide("pong", 1, before=missing_id).startswith("inconclusive:"))
        both = decide("pong", 1, before=missing_id, after=missing_id)
        self.assertEqual(both, "inconclusive:the control-plane lane state is unreadable")

    def test_a_recreated_journal_is_inconclusive(self) -> None:
        recreated = {**lanes(), "journal_id": "k" * 32}  # same epochs, new journal
        verdict = decide("pong", 1, after=recreated)
        self.assertEqual(verdict, "inconclusive:the journal was re-created during the window")

    def test_an_empty_monitor_set_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            empty = Path(temp) / "x.json"
            empty.write_text("{}")
            done = subprocess.run(
                [sys.executable, str(ROOT / "tools/gate_hold.py"), "decide", "--kind", "pong",
                 "--region", "r", "--status", "1", "--since", "1", "--before", str(empty),
                 "--after", str(empty), "--status-json", str(empty), "--monitors", " , "],
                capture_output=True, text=True, check=False)
            self.assertEqual(done.returncode, 2)
            self.assertEqual(done.stdout, "")
        self.assertEqual(gate_hold.control_plane_unhealthy(healthy_page(), SINCE, []),
                         "no monitor regions are configured")
        self.assertEqual(gate_hold.canary_evidence(healthy_page(), "us-central1", SINCE, [])[0],
                         "inconclusive")

    def test_an_unreadable_status_page_is_inconclusive(self) -> None:
        for payload in ({}, {"data": "x"}, [1, 2]):
            verdict = decide("pre-dns", 65, payload=payload)
            self.assertTrue(verdict.startswith("inconclusive:status.json"), verdict)

    def test_a_fresh_control_plane_probe_down_is_inconclusive(self) -> None:
        for probe in sorted(gate_hold.CONTROL_PLANE_PROBES):
            for status in ("down", "trust_degraded"):
                payload = healthy_page()
                payload["data"]["current"]["checks"].append(row(probe, "europe-west4", status, at=SINCE + 30))
                verdict = decide("pong", 1, payload=payload)
                self.assertTrue(verdict.startswith(f"inconclusive:{probe}"), verdict)

    def test_a_stale_control_plane_probe_down_does_not_count(self) -> None:
        payload = healthy_page()
        payload["data"]["current"]["checks"].append(row("gateway_settle", "europe-west4", "down", at=SINCE - 1))
        self.assertTrue(decide("pong", 1, payload=payload).startswith("gateway:"))

    def test_a_monitor_that_ingested_nothing_is_inconclusive(self) -> None:
        payload = page(*[r for r in healthy_page()["data"]["current"]["checks"]
                         if r["monitor_region"] == "us-central1"])
        verdict = decide("discovery", 1, payload=payload)
        self.assertEqual(verdict, "inconclusive:monitor europe-west4 ingested nothing since the window began")

    def test_samples_are_read_as_well_as_current_checks(self) -> None:
        payload = {"data": {"current": {"checks": []},
                            "samples": healthy_page()["data"]["current"]["checks"]
                            + [row("gateway_authorize", "us-central1", "down", at=SINCE + 1)]}}
        self.assertTrue(decide("pong", 1, payload=payload).startswith("inconclusive:gateway_authorize"))


# The library, run for real ------------------------------------------------------

LANES_STUB = r'''#!/usr/bin/env python3
import os, sys, time
seq = os.environ["LANES_SEQ"]
lines = open(seq).read().splitlines()
with open(os.environ["LANES_LOG"], "a") as log:
    log.write(" ".join(sys.argv[1:]) + "\n")
if os.environ.get("LANES_SLEEP"):
    time.sleep(int(os.environ["LANES_SLEEP"]))
if not lines:
    sys.exit(1)
print(lines[0])
if len(lines) > 1:
    open(seq, "w").write("\n".join(lines[1:]) + "\n")
'''

# Each token of GATE_CODES is one attempt: an exit status, or sN to sleep N
# seconds and then fail.
GATE_STUB = r'''#!/bin/bash
file="${GATE_CODES}"
if [ -n "${1:-}" ] && [ -f "${GATE_CODES}.$1" ]; then file="${GATE_CODES}.$1"; fi
codes="$(cat "${file}")"
code="${codes%% *}"
rest="${codes#* }"
[ "${rest}" = "${codes}" ] || printf '%s' "${rest}" > "${file}"
echo "gate $* started_at=${WAIT_UP_STARTED_AT:-unset}" >> "${GATE_LOG}"
case "${code}" in
  s*) sleep "${code#s}"; exit 1 ;;
  m*) : > "${GATE_HOLD_NO_RERUN_MARK}"; exit "${code#m}" ;;
  t) trap 'sleep 3; echo cleaned > "${GATE_LOG}.cleaned"; exit 143' TERM
     sleep 60 & wait; exit 1 ;;
esac
exit "${code}"
'''

CURL_STUB = r'''#!/bin/bash
echo "curl $*" >> "${CURL_LOG}"
[ -f "${STATUS_FILE}" ] || exit 7
cat "${STATUS_FILE}"
'''

MOVING = lanes(held="control-plane")


class Library(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = Path(tempfile.mkdtemp(prefix="gate-hold-test-"))
        self.tools = self.temp / "tools"
        self.tools.mkdir()
        shutil.copy2(ROOT / "tools" / "gate-hold-lib.sh", self.tools / "gate-hold-lib.sh")
        shutil.copy2(ROOT / "tools" / "gate_hold.py", self.tools / "gate_hold.py")
        (self.tools / "cloud-rollout.py").write_text(LANES_STUB)
        self.bin = self.temp / "bin"
        self.bin.mkdir()
        for name, body in (("gate", GATE_STUB), ("curl", CURL_STUB)):
            (self.bin / name).write_text(body)
            (self.bin / name).chmod(0o755)
        jq = shutil.which("jq")
        self.path = f"{self.bin}:{Path(jq).parent if jq else '/usr/bin'}:/usr/bin:/bin"
        self.hold = self.temp / "hold"
        self.addCleanup(shutil.rmtree, self.temp, ignore_errors=True)

    def run_lib(self, script: str, *, codes: str = "0", lane_lines: list[object] | None = None,
                status: object | None = None, hold_max: int = 3, env: dict[str, str] | None = None,
                errexit: bool = False, timeout: int = 60) -> tuple[subprocess.CompletedProcess[str], list[str]]:
        (self.temp / "codes").write_text(codes)
        (self.temp / "lanes").write_text("".join(json.dumps(x) + "\n" for x in (lane_lines or [STILL])))
        status_file = self.temp / "status.json"
        if status is not None:
            status_file.write_text(json.dumps(status))
        log = self.temp / "gate.log"
        log.unlink(missing_ok=True)
        completed = subprocess.run(
            [TEST_BASH, "-c", f'set -{"e" if errexit else ""}uo pipefail\n'
                              f'source "{self.tools}/gate-hold-lib.sh"\n{script}'],
            env={"PATH": self.path, "TMPDIR": str(self.temp),
                 "GATE_CODES": str(self.temp / "codes"), "GATE_LOG": str(log),
                 "LANES_SEQ": str(self.temp / "lanes"), "LANES_LOG": str(self.temp / "lanes.log"),
                 "CURL_LOG": str(self.temp / "curl.log"),
                 "STATUS_FILE": str(status_file), "TR_CP_HOLD_STATE_DIR": str(self.hold),
                 "TR_CP_HOLD_MAX_SECONDS": str(hold_max), "TR_CP_HOLD_SLEEP_SECONDS": "1",
                 **(env or {})},
            capture_output=True, text=True, timeout=timeout,
        )
        return completed, (log.read_text().splitlines() if log.exists() else [])

    @staticmethod
    def fresh_page(**kw: object) -> dict[str, object]:
        return healthy_page(at=time.time() + 3600, **kw)  # created after any window start

    def test_a_passing_gate_runs_once_with_its_arguments_unchanged(self) -> None:
        done, log = self.run_lib('gate_hold pong us-central1 gate "a b" c; echo "rc=$?"')
        self.assertIn("rc=0", done.stdout)
        self.assertEqual(len(log), 1)
        self.assertTrue(log[0].startswith("gate a b c started_at="), log)

    def test_the_gate_and_the_classifier_judge_the_same_window(self) -> None:
        done, log = self.run_lib('before=$(date +%s); gate_hold pong r gate; echo "before=$before"')
        started = int(re.search(r"started_at=(\d+)", log[0]).group(1))
        before = int(re.search(r"before=(\d+)", done.stdout).group(1))
        self.assertGreaterEqual(started, before)

    def test_a_gateway_failure_fails_at_once_with_the_gates_status(self) -> None:
        done, log = self.run_lib('gate_hold pong us-central1 gate; echo "rc=$?"', codes="7",
                                 status=self.fresh_page())
        self.assertIn("rc=7", done.stdout)
        self.assertEqual(len(log), 1)
        self.assertIn("attributed to the gateway", done.stderr)

    def test_a_failure_while_the_control_plane_moves_holds_then_passes_only_when_the_gate_does(self) -> None:
        done, log = self.run_lib('gate_hold pong us-central1 gate; echo "rc=$?"', codes="1 1 0",
                                 lane_lines=[MOVING], status=self.fresh_page(), hold_max=30)
        self.assertIn("rc=0", done.stdout)
        self.assertEqual(len(log), 3)
        self.assertEqual(done.stderr.count("::warning::us-central1: pong gate inconclusive"), 2)

    def test_a_failure_while_the_control_plane_keeps_moving_fails_closed_after_the_bound(self) -> None:
        started = time.monotonic()
        done, log = self.run_lib('gate_hold pong us-central1 gate; echo "rc=$?"', codes="9",
                                 lane_lines=[MOVING], status=self.fresh_page(), hold_max=6)
        # The gate's own status, or 124 if the deadline cut the last attempt.
        self.assertRegex(done.stdout, r"rc=(9|124)\b")
        self.assertIn("failing closed", done.stderr)
        self.assertGreaterEqual(len(log), 2)
        self.assertLessEqual(len(log), 8)
        self.assertLess(time.monotonic() - started, 30)

    def test_the_hold_deadline_stops_the_attempt_in_flight(self) -> None:
        """Review of #772: the bound is a hard deadline, not a check between attempts."""
        started = time.monotonic()
        done, log = self.run_lib('gate_hold pong us-central1 gate; echo "rc=$?"', codes="1 s40",
                                 lane_lines=[MOVING], status=self.fresh_page(), hold_max=6)
        elapsed = time.monotonic() - started
        self.assertIn("rc=124", done.stdout)
        self.assertIn("the attempt in flight was stopped", done.stderr)
        self.assertEqual(len(log), 2)
        self.assertLess(elapsed, 25)  # 6 s hold + kill grace, never the 40 s attempt

    def test_an_attempt_over_its_cap_is_stopped_and_judged(self) -> None:
        started = time.monotonic()
        done, log = self.run_lib('gate_hold pong us-central1 gate; echo "rc=$?"', codes="s40",
                                 status=self.fresh_page(), env={"TR_CP_HOLD_ATTEMPT_SECONDS": "2"})
        self.assertIn("rc=124", done.stdout)
        self.assertIn("attributed to the gateway", done.stderr)  # still control plane
        self.assertEqual(len(log), 1)
        self.assertLess(time.monotonic() - started, 20)

    def test_a_canary_that_passed_blind_while_moving_reruns_then_fails_closed(self) -> None:
        stale = healthy_page(at=time.time() - 3600)
        done, log = self.run_lib('gate_hold canary us-central1 gate; echo "rc=$?"', codes="0",
                                 lane_lines=[MOVING], status=stale, hold_max=6)
        self.assertIn("rc=1", done.stdout)
        self.assertIn("failing closed", done.stderr)
        self.assertGreaterEqual(len(log), 2)

    def test_a_blind_canary_pass_with_no_budget_left_fails_closed(self) -> None:
        self.hold.mkdir()
        (self.hold / "held-europe-west4").write_text("100\n")
        stale = healthy_page(at=time.time() - 3600)
        done, log = self.run_lib('gate_hold canary us-central1 gate; echo "rc=$?"', codes="0",
                                 lane_lines=[MOVING], status=stale, hold_max=60,
                                 env={"TR_CP_HOLD_BUDGET_SECONDS": "10"})
        self.assertIn("rc=1", done.stdout)
        self.assertIn("job's (10s", done.stderr)
        self.assertEqual(len(log), 1)

    def test_overlapping_holds_share_the_budget_as_they_spend_it(self) -> None:
        """Review of #772: a wave's two holds must not each spend the budget."""
        (self.temp / "codes.r1").write_text("1 s60")
        (self.temp / "codes.r2").write_text("1 s60")
        script = ("gate_hold pong r1 gate r1 & a=$!\n"
                  "gate_hold pong r2 gate r2 & b=$!\n"
                  'wait "$a"; echo "r1=$?"; wait "$b"; echo "r2=$?"')
        started = time.monotonic()
        done, log = self.run_lib(script, lane_lines=[MOVING], status=self.fresh_page(), hold_max=60,
                                 env={"TR_CP_HOLD_BUDGET_SECONDS": "10", "GATE_HOLD_KILL_GRACE": "2"})
        elapsed = time.monotonic() - started
        self.assertIn("r1=124", done.stdout)
        self.assertIn("r2=124", done.stdout)
        held = sum(int(v) for f in self.hold.glob("held-*") for v in f.read_text().split())
        self.assertLessEqual(held, 10 + 4, held)  # each would have spent ~7 more alone
        self.assertLess(elapsed, 20)

    def test_a_gate_that_changed_dns_is_never_re_run(self) -> None:
        done, log = self.run_lib('gate_hold pre-dns us-central1 gate; echo "rc=$?"', codes="m65 0",
                                 lane_lines=[MOVING], status=self.fresh_page(), hold_max=30)
        self.assertIn("rc=65", done.stdout)
        self.assertIn("it is never re-run", done.stderr)
        self.assertEqual(len(log), 1)

    def test_a_killed_attempt_gets_its_grace_to_clean_up(self) -> None:
        done, log = self.run_lib('gate_hold pong us-central1 gate; echo "rc=$?"', codes="t",
                                 status=self.fresh_page(),
                                 env={"TR_CP_HOLD_ATTEMPT_SECONDS": "2", "GATE_HOLD_KILL_GRACE": "10"})
        self.assertIn("rc=124", done.stdout)
        self.assertTrue((self.temp / "gate.log.cleaned").exists())

    def test_region_spend_counts_finished_and_open_holds(self) -> None:
        self.hold.mkdir()
        (self.hold / "held-r").write_text("5\n7\n")
        (self.hold / "holding-r").write_text(f"{int(time.time()) - 3}\n")
        (self.hold / "held-other").write_text("100\n")
        done, _ = self.run_lib(f'gate_hold_region_spent "{self.hold}" r')
        self.assertIn(int(done.stdout.strip()), (15, 16))

    def test_the_hold_clock_is_per_gate(self) -> None:
        """An earlier gate's hold does not eat into a later gate's bound."""
        # The pause between the gates outlasts the bound, so a clock shared by
        # the region would leave the second gate no time at all.
        script = ('gate_hold pre-dns us-central1 gate; echo "first=$?"\n'
                  "sleep 8\n"
                  'gate_hold pong us-central1 gate; echo "second=$?"')
        done, log = self.run_lib(script, codes="65 0 1 1 1 1 1 1 1 1 1 1", lane_lines=[MOVING],
                                 status=self.fresh_page(), hold_max=6,
                                 env={"TR_CP_HOLD_BUDGET_SECONDS": "100"})
        self.assertIn("first=0", done.stdout)
        self.assertIn("second=1", done.stdout)
        self.assertGreaterEqual(len(log) - 2, 2)  # the second gate held on its own clock

    def test_the_job_budget_ends_every_hold(self) -> None:
        self.hold.mkdir()
        (self.hold / "held-europe-west4").write_text("50\n")  # another region spent it
        done, log = self.run_lib('gate_hold pong us-central1 gate; echo "rc=$?"', codes="1",
                                 lane_lines=[MOVING], status=self.fresh_page(), hold_max=60,
                                 env={"TR_CP_HOLD_BUDGET_SECONDS": "40"})
        self.assertIn("rc=1", done.stdout)
        self.assertIn("job's (40s", done.stderr)
        self.assertEqual(len(log), 1)

    def test_a_hold_is_recorded_for_the_job_budget(self) -> None:
        self.run_lib("gate_hold pong us-central1 gate", codes="1 0", lane_lines=[MOVING],
                     status=self.fresh_page(), hold_max=30)
        self.assertFalse((self.hold / "holding-us-central1").exists())
        held = (self.hold / "held-us-central1").read_text().split()
        self.assertEqual(len(held), 1)
        self.assertGreaterEqual(int(held[0]), 1)

    def test_an_unwritable_hold_record_fails_closed(self) -> None:
        self.hold.write_text("not a directory")
        done, log = self.run_lib('gate_hold pong us-central1 gate; echo "rc=$?"', codes="1 0",
                                 lane_lines=[MOVING], status=self.fresh_page(), hold_max=30)
        self.assertIn("rc=1", done.stdout)
        self.assertIn("cannot record the control-plane hold", done.stderr)
        self.assertEqual(len(log), 1)

    def test_a_stop_kills_the_attempt_in_flight_and_runs_the_stop_hook(self) -> None:
        stop = self.temp / "stop"
        script = (f'should_stop() {{ [ -e "{stop}" ]; }}\n'
                  'on_stop() { echo hook >&2; exit 75; }\n'
                  "GATE_HOLD_STOP=should_stop GATE_HOLD_ON_STOP=on_stop\n"
                  f'( sleep 2; touch "{stop}" ) &\n'
                  'gate_hold pong us-central1 gate; echo "rc=$?"')
        started = time.monotonic()
        done, log = self.run_lib(script, codes="s40", status=self.fresh_page())
        self.assertEqual(done.returncode, 75)
        self.assertIn("hook", done.stderr)
        self.assertEqual(len(log), 1)
        self.assertLess(time.monotonic() - started, 20)

    def test_a_stop_while_holding_records_the_hold_and_runs_the_hook(self) -> None:
        stop = self.temp / "stop"
        script = (f'should_stop() {{ [ -e "{stop}" ]; }}\n'
                  'on_stop() { echo hook >&2; exit 75; }\n'
                  "GATE_HOLD_STOP=should_stop GATE_HOLD_ON_STOP=on_stop\n"
                  f'( sleep 2; touch "{stop}" ) &\n'
                  "gate_hold pong us-central1 gate")
        started = time.monotonic()
        done, log = self.run_lib(script, codes="1 1 1 1 1 1", lane_lines=[MOVING],
                                 status=self.fresh_page(), hold_max=60,
                                 env={"TR_CP_HOLD_SLEEP_SECONDS": "30"})
        self.assertLess(time.monotonic() - started, 15)  # stopped mid-pause, not after it
        self.assertEqual(done.returncode, 75)
        self.assertEqual(len(log), 1)
        self.assertFalse((self.hold / "holding-us-central1").exists())

    def test_no_decision_leaves_a_failure_and_fails_a_canary_pass_closed(self) -> None:
        (self.tools / "gate_hold.py").write_text("import sys\nsys.exit(3)\n")
        for kind, codes, expected in (("pong", "0", "rc=0"), ("pong", "4", "rc=4"), ("canary", "0", "rc=1")):
            done, log = self.run_lib(f'gate_hold {kind} r gate; echo "rc=$?"', codes=codes,
                                     lane_lines=[MOVING])
            self.assertIn(expected, done.stdout, (kind, codes, done.stderr))
            self.assertEqual(len(log), 1)

    def test_under_errexit_like_actions_the_loop_still_decides(self) -> None:
        # GitHub Actions runs `run:` blocks with bash -eo pipefail.
        done, log = self.run_lib("gate_hold pong r gate\necho after", codes="1 1 0",
                                 lane_lines=[MOVING], status=self.fresh_page(), hold_max=30, errexit=True)
        self.assertEqual((done.returncode, done.stdout.strip(), len(log)), (0, "after", 3))
        done, log = self.run_lib("gate_hold pong r2 gate\necho after", codes="9",
                                 lane_lines=[MOVING], status=self.fresh_page(), hold_max=6, errexit=True)
        self.assertIn(done.returncode, (9, 124))
        self.assertEqual(done.stdout.strip(), "")
        self.assertIn("failing closed", done.stderr)
        self.assertGreaterEqual(len(log), 2)
        done, log = self.run_lib("gate_hold pong r3 gate\necho after", codes="7",
                                 status=self.fresh_page(), errexit=True)
        self.assertEqual((done.returncode, len(log)), (7, 1))

    def test_lanes_are_read_around_every_judged_attempt(self) -> None:
        self.run_lib("gate_hold pong r gate", codes="0")
        self.assertEqual((self.temp / "lanes.log").read_text().splitlines(), ["lanes --cloud gcp"])
        (self.temp / "lanes.log").unlink()
        self.run_lib("gate_hold pong r gate", codes="3", status=self.fresh_page())
        self.assertEqual((self.temp / "lanes.log").read_text().splitlines(),
                         ["lanes --cloud gcp", "lanes --cloud gcp"])

    def test_a_slow_lane_read_is_cut_off(self) -> None:
        started = time.monotonic()
        done, log = self.run_lib('gate_hold pong r gate; echo "rc=$?"', codes="0",
                                 env={"LANES_SLEEP": "40", "GATE_HOLD_READ_SECONDS": "2"})
        self.assertIn("rc=0", done.stdout)
        self.assertLess(time.monotonic() - started, 20)

    def test_status_reads_defeat_caching(self) -> None:
        self.run_lib("gate_hold pong r gate", codes="3", status=self.fresh_page())
        self.run_lib("gate_status_presence r", status={"checks": []})
        reads = (self.temp / "curl.log").read_text().splitlines()
        self.assertEqual(len(reads), 2)
        for line in reads:
            self.assertRegex(line, r"status\.json\?gate_hold=\d+")
            self.assertIn("Cache-Control: no-cache", line)

    def test_settings_must_be_whole_seconds(self) -> None:
        for name, value in (("TR_CP_HOLD_MAX_SECONDS", "abc"), ("TR_CP_HOLD_MAX_SECONDS", "0"),
                            ("TR_CP_HOLD_SLEEP_SECONDS", "1.5"), ("TR_CP_HOLD_BUDGET_SECONDS", "-1"),
                            ("TR_CP_HOLD_ATTEMPT_SECONDS", "x")):
            done, log = self.run_lib('gate_hold pong r gate; echo "rc=$?"', env={name: value})
            self.assertIn("rc=2", done.stdout, name)
            self.assertIn(name, done.stderr)
            self.assertEqual(log, [], name)
        done, log = self.run_lib('gate_hold pong r gate; echo "rc=$?"',
                                 env={"TR_CP_HOLD_ATTEMPT_SECONDS": "0"})
        self.assertIn("rc=0", done.stdout)

    def test_an_empty_monitor_set_is_refused_before_the_gate_runs(self) -> None:
        for monitors in ("", " , "):
            done, log = self.run_lib('gate_hold pong r gate; echo "rc=$?"',
                                     env={"WAIT_UP_MONITOR_REGIONS": monitors})
            self.assertIn("rc=2", done.stdout)
            self.assertEqual(log, [])

    def test_presence_reads_the_page(self) -> None:
        done, _ = self.run_lib("gate_status_presence us-east4",
                               status={"checks": [{"target_region": "us-east4"}]})
        self.assertEqual(done.stdout.strip(), "present")
        done, _ = self.run_lib("gate_status_presence us-west1",
                               status={"checks": [{"target_region": "us-east4"}]})
        self.assertEqual(done.stdout.strip(), "missing")

    def test_presence_holds_on_an_unreadable_page_and_then_reports_it(self) -> None:
        done, _ = self.run_lib("gate_status_presence us-east4", hold_max=2)
        self.assertEqual(done.stdout.strip(), "unreadable")
        self.assertIn("::warning::us-east4: status.json is unreadable", done.stderr)
        self.assertIn("failing closed", done.stderr)
        self.assertTrue((self.hold / "held-us-east4").exists())  # counted in the job budget

    def test_presence_respects_the_job_budget(self) -> None:
        self.hold.mkdir()
        (self.hold / "held-us-central1").write_text("99\n")
        done, _ = self.run_lib("gate_status_presence us-east4", hold_max=30,
                               env={"TR_CP_HOLD_BUDGET_SECONDS": "10"})
        self.assertEqual(done.stdout.strip(), "unreadable")
        self.assertNotIn("::warning::", done.stderr)

    def test_presence_recovers_when_the_page_comes_back(self) -> None:
        status_file = self.temp / "status.json"
        script = (f'( sleep 2; echo \'{{"checks": [{{"target_region": "us-east4"}}]}}\' > "{status_file}" ) &\n'
                  "gate_status_presence us-east4")
        done, _ = self.run_lib(script, hold_max=30)
        self.assertEqual(done.stdout.strip(), "present")

    def test_presence_once_never_holds(self) -> None:
        started = time.monotonic()
        done, _ = self.run_lib("gate_status_presence us-west1 once", hold_max=30)
        self.assertEqual(done.stdout.strip(), "unreadable")
        self.assertLess(time.monotonic() - started, 5)
        self.assertNotIn("::warning::", done.stderr)


# Wiring --------------------------------------------------------------------------

WORKFLOW = (ROOT / ".github/workflows/deploy-enclave-gcp.yml").read_text()
SECONDARY = (ROOT / "tools/roll-secondary-region.sh").read_text()
VERIFY = (ROOT / "tools/verify-region-before-dns.sh").read_text()


def step(name: str) -> str:
    start = WORKFLOW.index(f"      - name: {name}\n")
    return WORKFLOW[start: WORKFLOW.index("\n\n", start)]


class Wiring(unittest.TestCase):
    def test_every_control_plane_dependent_gate_is_held_not_failed(self) -> None:
        for name, call in (
            ("Blocking per-instance streaming gate (us-central1)",
             "gate_hold pre-dns us-central1 bash tools/verify-region-before-dns.sh"),
            ("Wait for us-central1 synthetic up",
             "gate_hold pong us-central1 bash tools/wait-region-synthetic-up.sh us-central1 us-central1"),
            ("Canary gate — watch us-central1 only (post-stable)",
             "gate_hold canary us-central1 python3 tools/watchdog.py --regions us-central1"),
            ("Verify image discovery on attested origin", "gate_hold discovery all image_discovery"),
        ):
            body = step(name)
            self.assertIn("source tools/gate-hold-lib.sh", body, name)
            self.assertIn(call, body, name)
            self.assertIn("TR_CP_HOLD_STATE_DIR: ${{ runner.temp }}/tr-cp-hold", body, name)
            self.assertRegex(body, r'TR_CP_HOLD_ATTEMPT_SECONDS: "\d+"', name)
        for call in ('rollout_step gate_hold pre-dns "${region}" bash tools/verify-region-before-dns.sh',
                     'rollout_step gate_hold pong "${region}" bash tools/wait-region-synthetic-up.sh',
                     'gate_hold canary "${region}" python3 tools/watchdog.py',
                     'presence="$(gate_status_presence "${region}" "${presence_mode}")"',
                     "GATE_HOLD_STOP=gate_should_stop", "GATE_HOLD_ON_STOP=check_not_aborted"):
            self.assertIn(call, SECONDARY)
        self.assertNotIn("curl -fsS --max-time 15 https://trustedrouter.com/status.json", SECONDARY)

    def test_a_first_deployment_pre_dns_gate_is_never_re_run(self) -> None:
        start = SECONDARY.index('if [ -z "${previous_template}" ]; then\n  # A first deployment')
        block = SECONDARY[start: SECONDARY.index("\nfi\n", start)]
        first, existing = block.split("\nelse\n")
        self.assertIn("rollout_step bash tools/verify-region-before-dns.sh", first)
        self.assertNotIn("gate_hold", first)
        self.assertIn("gate_hold pre-dns", existing)
        # And the gate itself never offers a run with DNS side effects for a re-run.
        self.assertIn('if [ "${status}" -eq "${CP_DEPENDENT_STATUS}" ] && [ "${cold_bootstrap}" = "1" ]; then\n'
                      '    echo "${REGION}: first-deployment bootstrap failed on the request path; not offered for a re-run" >&2\n'
                      '    status=1\n', VERIFY)
        self.assertIn("if replace_cold_alias_with_bootstrap_ip; then\n  cold_bootstrap=1\n", VERIFY)

    # Outside a hold: the first attempt's two lane reads, status.json and
    # decide. After it: the final status read and decide, the kill grace
    # (GATE_HOLD_KILL_GRACE), and the step's own setup (the PONG step triggers
    # two monitor jobs).
    READS = (60 + 60 + 15 + 5) + (15 + 5 + 30) + 60

    def test_timeouts_cover_each_gates_true_worst_case(self) -> None:
        """Review of #772: a capped attempt, the whole hold, and bounded reads."""
        env = yaml.safe_load(WORKFLOW)["jobs"]["rollout"]["env"]
        hold = min(int(env["TR_CP_HOLD_MAX_SECONDS"]), int(env["TR_CP_HOLD_BUDGET_SECONDS"]))
        budget = int(env["TR_CP_HOLD_BUDGET_SECONDS"])
        for name in ("Blocking per-instance streaming gate (us-central1)",
                     "Wait for us-central1 synthetic up",
                     "Canary gate — watch us-central1 only (post-stable)",
                     "Verify image discovery on attested origin"):
            body = step(name)
            cap = int(re.search(r'TR_CP_HOLD_ATTEMPT_SECONDS: "(\d+)"', body).group(1))
            minutes = int(re.search(r"timeout-minutes: (\d+)", body).group(1))
            self.assertGreater(cap, 0, name)
            self.assertGreaterEqual(minutes * 60, cap + hold + self.READS, name)
        for name in ("Roll Europe and US East GCP MIGs in parallel", "Roll US West GCP MIG"):
            body = step(name)
            forward = int(re.search(r'(?:TR_SECONDARY_WORKER_TIMEOUT|TR_US_WEST_FORWARD_SECONDS): "(\d+)"',
                                    body).group(1))
            minutes = int(re.search(r"timeout-minutes: (\d+)", body).group(1))
            # The forward deadline grows by at most the job budget, and
            # recovery keeps its 45 minutes after that.
            self.assertGreaterEqual(minutes * 60, forward + budget + 45 * 60, name)

    def test_a_regions_forward_deadline_grows_only_by_its_own_holds(self) -> None:
        start = SECONDARY.index("forward_deadline_passed() {")
        body = SECONDARY[start: SECONDARY.index("\n}\n", start)]
        self.assertIn('held="$(gate_hold_region_spent "${TR_CP_HOLD_STATE_DIR}" "${region}")"', body)
        self.assertIn('[ "$(date +%s)" -ge "$((deadline + held))" ]', body)
        self.assertNotIn('date +%s)" -ge "${deadline}"', SECONDARY)
        self.assertEqual(SECONDARY.count("forward_deadline_passed"), 4)  # definition and three uses

    def test_us_west_has_a_forward_deadline(self) -> None:
        body = step("Roll US West GCP MIG")
        self.assertIn('TR_SECONDARY_DEADLINE="$(( $(date +%s) + TR_US_WEST_FORWARD_SECONDS ))"', body)
        self.assertIn("export TR_SECONDARY_DEADLINE", body)
        self.assertLess(body.index("export TR_SECONDARY_DEADLINE"),
                        body.index("bash tools/roll-secondary-region.sh"))

    def test_the_rollout_job_ends_before_githubs_limit_in_the_worst_case(self) -> None:
        """From enforced limits only: every step's timeout, gate caps, the budget."""
        job = yaml.safe_load(WORKFLOW)["jobs"]["rollout"]
        limit = job["timeout-minutes"]
        self.assertLess(limit, 360)
        untimed = [s.get("name") or s.get("uses") for s in job["steps"] if "timeout-minutes" not in s]
        self.assertEqual(untimed, [])
        budget = int(job["env"]["TR_CP_HOLD_BUDGET_SECONDS"]) / 60
        gates = {"Blocking per-instance streaming gate (us-central1)", "Wait for us-central1 synthetic up",
                 "Canary gate — watch us-central1 only (post-stable)", "Verify image discovery on attested origin"}
        wave_name, west_name = "Roll Europe and US East GCP MIGs in parallel", "Roll US West GCP MIG"
        primary_recovery = {"Refresh AWS credentials for primary recovery",
                            "Recover us-central1 after any failed rollout step"}
        steps = [(s.get("name") or s.get("uses"), s) for s in job["steps"]]
        names = [n for n, _ in steps]

        def cost(name: str, s: dict) -> float:
            if name in gates:  # the attempt and its reads; its hold is in the budget
                return (int(s["env"]["TR_CP_HOLD_ATTEMPT_SECONDS"]) + self.READS) / 60
            return float(s["timeout-minutes"])

        def forward(s: dict) -> float:
            env = s["env"]
            return int(env.get("TR_SECONDARY_WORKER_TIMEOUT") or env["TR_US_WEST_FORWARD_SECONDS"]) / 60

        always = {"Clear healthy rollout-created canonical drains"}
        runner = 3  # job setup, post steps and the gaps between steps

        def path(until: str, failing: str | None) -> float:
            """Every step up to `until`; `failing` costs its whole limit, the
            secondaries before it their forward deadlines, plus the budget."""
            total = runner + budget
            for name, s in steps[: names.index(until) + 1]:
                if name in primary_recovery and failing != "primary":
                    continue
                if name in (wave_name, west_name):
                    total += cost(name, s) if name == failing else forward(s)
                else:
                    total += cost(name, s)
            for name in always:
                if names.index(name) > names.index(until):
                    total += cost(name, dict(steps)[name])
            return total

        primary_fails = path("Recover us-central1 after any failed rollout step", "primary")
        wave_fails = path(wave_name, wave_name)
        west_fails = path(west_name, west_name)
        all_pass = path("Smoke test enclave inference (non-blocking)", None)
        worst = max(primary_fails, wave_fails, west_fails, all_pass)
        self.assertLessEqual(worst, limit, (primary_fails, wave_fails, west_fails, all_pass))

    def test_request_path_failures_carry_the_control_plane_status(self) -> None:
        start = VERIFY.index("verify_streaming_authorization() {")
        streaming = VERIFY[start: VERIFY.index("\n}\n", start)]
        self.assertNotIn("return 1", streaming)
        self.assertEqual(streaming.count('return "${CP_DEPENDENT_STATUS}"'), 7)
        start = VERIFY.index("verify_instance() {")
        instance = VERIFY[start: VERIFY.index("\n}\n", start)]
        # Attestation is the enclave's alone; inference goes through the control plane.
        self.assertEqual(instance.count("return 1"), 1)
        self.assertLess(instance.index("never passed ${stage} attestation"), instance.index("return 1"))
        self.assertIn('did not succeed" >&2\n    return "${CP_DEPENDENT_STATUS}"', instance)
        self.assertIn(f"CP_DEPENDENT_STATUS={gate_hold.CP_DEPENDENT_STATUS}\n", VERIFY)

    def test_recovery_names_a_control_plane_failure(self) -> None:
        recover = (ROOT / "tools/recover-gcp-region.sh").read_text()
        self.assertIn('if [ "${status}" -eq 65 ]; then', recover)
        self.assertIn('if [ "${recovery_status}" -eq 65 ]; then', SECONDARY)
        self.assertIn("re-run tools/recover-gcp-region.sh", SECONDARY)

    def test_new_files_trigger_a_gateway_rollout_and_run_in_ci(self) -> None:
        for path in ("tools/gate-hold-lib.sh", "tools/gate_hold.py"):
            self.assertIn(f'      - "{path}"\n', WORKFLOW)
        ci = (ROOT / ".github/workflows/ci.yml").read_text()
        self.assertIn("python3 tools/test_gate_hold.py", ci)


# One region, run for real ---------------------------------------------------------

REGION_BASH_STUB = r'''#!/bin/bash
echo "bash $*" >> "${COMMAND_LOG}"
pop() {  # pop the next status for this step from its codes file
  local file="${STEP_CODES}/$1" codes code
  [ -f "${file}" ] || return 0
  codes="$(cat "${file}")"; code="${codes%% *}"
  [ "${codes#* }" = "${codes}" ] || printf '%s' "${codes#* }" > "${file}"
  return "${code}"
}
case "$1" in
  tools/wait-region-attested.sh) sleep "${SLOW_ATTEST:-0}" ;;
  tools/verify-region-before-dns.sh) pop verify ;;
  tools/wait-region-synthetic-up.sh) pop pong ;;
  tools/recover-gcp-region.sh) pop recover ;;
esac
'''

REGION_PYTHON_STUB = r'''#!/bin/bash
case "$1" in
  */gate_hold.py) exec "${REAL_PYTHON}" "$@" ;;
esac
echo "python3 $*" >> "${COMMAND_LOG}"
case "$*" in
  *"cloud-rollout.py lanes"*) cat "${LANES_FILE}" ;;
  *"tools/watchdog.py"*) exit "${WATCHDOG_STATUS:-0}" ;;
esac
exit 0
'''


class OneRegion(unittest.TestCase):
    """tools/roll-secondary-region.sh with the real library and classifier."""

    def roll(self, *, lanes_now: object, pong: str = "0", verify: str = "0", recover: str = "0",
             watchdog: int = 0, status: object | None = None, previous: str = "quill-enclave-tpl-uswest1-1",
             hold_max: int = 3, deadline_in: int | None = None, slow_attest: int = 0
             ) -> tuple[subprocess.CompletedProcess[str], str, str]:
        temp = Path(tempfile.mkdtemp(prefix="one-region-"))
        self.addCleanup(shutil.rmtree, temp, ignore_errors=True)
        bin_dir, codes, state = temp / "bin", temp / "codes", temp / "state"
        for directory in (bin_dir, codes, state):
            directory.mkdir()
        for name, value in (("pong", pong), ("verify", verify), ("recover", recover)):
            (codes / name).write_text(value)
        (temp / "lanes.json").write_text(json.dumps(lanes_now))
        (temp / "status.json").write_text(json.dumps(
            status if status is not None else healthy_page("us-west1", at=time.time() + 3600)))
        stubs = {
            "bash": REGION_BASH_STUB,
            "python3": REGION_PYTHON_STUB,
            "gcloud": '#!/bin/bash\necho "gcloud $*" >> "${COMMAND_LOG}"\n',
            "uv": '#!/bin/bash\necho "uv $*" >> "${COMMAND_LOG}"\n',
            "flock": "#!/bin/bash\nexit 0\n",
            "curl": '#!/bin/bash\ncat "${STATUS_FILE}"\n',
        }
        for name, body in stubs.items():
            (bin_dir / name).write_text(body)
            (bin_dir / name).chmod(0o755)
        jq = shutil.which("jq")
        self.assertIsNotNone(jq, "jq is required, as in CI")
        log = temp / "commands.log"
        done = subprocess.run(
            [TEST_BASH, str(ROOT / "tools/roll-secondary-region.sh"), "us-west1",
             "quill-enclave-mig-uswest1", "quill-enclave-mig-uswest1-", "uswest1",
             "api.quillrouter.com,api-us-west1.quillrouter.com", previous, "c3-standard-4", "TDX",
             "active", "none"],
            cwd=ROOT, capture_output=True, text=True, timeout=120,
            env={"PATH": f"{bin_dir}:{Path(jq).parent}:/usr/bin:/bin", "TMPDIR": str(temp),
                 "COMMAND_LOG": str(log), "STEP_CODES": str(codes), "REAL_PYTHON": sys.executable,
                 "LANES_FILE": str(temp / "lanes.json"), "STATUS_FILE": str(temp / "status.json"),
                 "WATCHDOG_STATUS": str(watchdog), "GITHUB_RUN_ID": "33807667585",
                 "TR_DEPLOY_MUTEX_OPERATION": "a" * 32, "IMAGE_REF": "registry.example/enclave:new",
                 "IMAGE_DIGEST": "sha256:" + "a" * 64, "TR_ROLLOUT_STATE_DIR": str(state),
                 "TR_CP_HOLD_STATE_DIR": str(temp / "hold"), "TR_CP_HOLD_MAX_SECONDS": str(hold_max),
                 "TR_CP_HOLD_SLEEP_SECONDS": "1", "TR_CP_HOLD_BUDGET_SECONDS": "100",
                 "SLOW_ATTEST": str(slow_attest),
                 **({"TR_SECONDARY_DEADLINE": str(int(time.time()) + deadline_in)} if deadline_in else {})},
        )
        commands = log.read_text() if log.exists() else ""
        final = (state / "us-west1").read_text().strip() if (state / "us-west1").exists() else ""
        return done, commands, final

    def test_a_pong_failure_while_the_control_plane_moves_holds_then_promotes(self) -> None:
        done, commands, final = self.roll(lanes_now=MOVING, pong="1 1 0", hold_max=30)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(commands.count("bash tools/wait-region-synthetic-up.sh us-west1"), 3)
        self.assertIn("--clear-drain-region us-west1", commands)
        self.assertNotIn("recover-gcp-region.sh", commands)
        self.assertEqual(final, "promoted")

    def test_a_pong_failure_that_outlasts_the_hold_fails_closed_and_recovers(self) -> None:
        done, commands, final = self.roll(lanes_now=MOVING, pong=" ".join(["1"] * 20))
        self.assertNotEqual(done.returncode, 0)
        self.assertIn("failing closed", done.stderr)
        self.assertNotIn("--clear-drain-region us-west1", commands)
        self.assertIn("bash tools/recover-gcp-region.sh us-west1", commands)
        self.assertEqual(final, "recovered")

    def test_a_pong_failure_with_a_still_control_plane_fails_at_once(self) -> None:
        done, commands, final = self.roll(lanes_now=STILL, pong="1 0")
        self.assertNotEqual(done.returncode, 0)
        self.assertEqual(commands.count("bash tools/wait-region-synthetic-up.sh us-west1"), 1)
        self.assertNotIn("--clear-drain-region us-west1", commands)
        self.assertEqual(final, "recovered")

    def test_a_blind_canary_pass_over_a_down_enclave_is_never_promoted(self) -> None:
        down = page(*[{**r, "status": "down"} if r["probe_type"] in gate_hold.GATEWAY_ONLY_PROBES else r
                      for r in healthy_page("us-west1", at=time.time() + 3600)["data"]["current"]["checks"]])
        done, commands, final = self.roll(lanes_now=MOVING, pong="0", status=down)
        self.assertNotEqual(done.returncode, 0)
        self.assertIn("attributed to the gateway", done.stderr)
        self.assertNotIn("--clear-drain-region us-west1", commands)
        self.assertEqual(final, "recovered")

    def test_a_first_deployment_pre_dns_failure_is_not_re_run(self) -> None:
        done, commands, _ = self.roll(lanes_now=MOVING, verify="65 0 0", previous="")
        self.assertNotEqual(done.returncode, 0)
        self.assertEqual(commands.count("bash tools/verify-region-before-dns.sh us-west1"), 1)
        self.assertNotIn("--clear-drain-region us-west1", commands)

    def test_an_existing_regions_pre_dns_failure_holds_while_moving(self) -> None:
        done, commands, final = self.roll(lanes_now=MOVING, verify="65 0", hold_max=30)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(commands.count("bash tools/verify-region-before-dns.sh us-west1"), 2)
        self.assertEqual(final, "promoted")

    def test_holding_extends_the_forward_deadline_by_exactly_the_hold(self) -> None:
        """Review of #772: hold time is the budget's, not the deadline's."""
        done, commands, final = self.roll(lanes_now=MOVING, pong="1 1 1 1 1 1 1 1 0", hold_max=60,
                                          deadline_in=12)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(final, "promoted")
        self.assertEqual(commands.count("bash tools/wait-region-synthetic-up.sh us-west1"), 9)

    def test_work_outside_a_hold_keeps_the_base_deadline(self) -> None:
        started = time.monotonic()
        done, commands, final = self.roll(lanes_now=STILL, deadline_in=3, slow_attest=30)
        self.assertEqual(done.returncode, 76, done.stderr)
        self.assertIn("rollout deadline passed before promotion", done.stderr)
        self.assertEqual(final, "recovered")
        self.assertLess(time.monotonic() - started, 25)

    def test_recovery_that_meets_a_bad_control_plane_says_so(self) -> None:
        done, commands, final = self.roll(lanes_now=STILL, pong="1", recover="65")
        self.assertNotEqual(done.returncode, 0)
        self.assertEqual(final, "recovery-failed")
        self.assertIn("re-run tools/recover-gcp-region.sh for us-west1", done.stderr)
        self.assertNotIn("--clear-drain-region us-west1", commands)


# The real pre-DNS gate, killed mid cold swap -------------------------------------

VERIFY_GCLOUD = r'''#!/bin/bash
echo "gcloud $*" >> "${COMMAND_LOG}"
state="$(cat "${DNS_STATE}")"
case "$*" in
  *"instance-groups managed describe"*) echo "https://example.invalid/instanceTemplates/tpl" ;;
  *"instance-templates describe"*)
    echo '{"properties":{"metadata":{"items":[{"key":"tee-env-QUILL_USAGE_HEARTBEAT","value":"off"}]}}}' ;;
  *"compute instances list"*) printf '10.0.0.1\n10.0.0.2\n' ;;
  *"record-sets list"*"--type=CNAME"*)
    if [ "${state}" = cname ]; then echo '[{"rrdatas":["api.quillrouter.com."],"ttl":0}]'; else echo '[]'; fi ;;
  *"record-sets list"*"--type=A"*)
    if [ "${state}" = a ]; then echo '[{"rrdatas":["10.0.0.1"],"ttl":60}]'; else echo '[]'; fi ;;
  *"record-sets transaction execute"*)
    if [ "${state}" = cname ]; then echo a > "${DNS_STATE}"; else echo cname > "${DNS_STATE}"; fi ;;
  *"record-sets transaction"*) ;;
  *) echo "unexpected gcloud: $*" >&2; exit 1 ;;
esac
'''

VERIFY_CURL = r'''#!/bin/bash
out=""
while [ "$#" -gt 0 ]; do
  [ "$1" = "--output" ] && out="$2"
  shift
done
[ -n "${out}" ] && echo '{"choices":[{"message":{"role":"assistant","content":"PONG"}}]}' > "${out}"
printf '200'
'''


class VerifyColdSwap(unittest.TestCase):
    """Review of #772: a kill after the cold-CNAME swap must restore it."""

    def test_term_mid_cold_swap_restores_the_cname_and_marks_no_rerun(self) -> None:
        temp = Path(tempfile.mkdtemp(prefix="verify-cold-"))
        self.addCleanup(shutil.rmtree, temp, ignore_errors=True)
        bin_dir = temp / "bin"
        bin_dir.mkdir()
        for name, body in (("gcloud", VERIFY_GCLOUD), ("curl", VERIFY_CURL),
                           ("uv", "#!/bin/bash\nexit 0\n")):
            (bin_dir / name).write_text(body)
            (bin_dir / name).chmod(0o755)
        (temp / "dns").write_text("cname\n")
        log, mark = temp / "commands.log", temp / "no-rerun"
        jq = shutil.which("jq")
        self.assertIsNotNone(jq)
        proc = subprocess.Popen(
            [TEST_BASH, str(ROOT / "tools/verify-region-before-dns.sh"), "us-west1",
             "quill-enclave-mig-uswest1-", "sha256:" + "a" * 64],
            cwd=ROOT, start_new_session=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            env={"PATH": f"{bin_dir}:{Path(jq).parent}:{Path(sys.executable).parent}:/usr/bin:/bin",
                 "TMPDIR": str(temp), "COMMAND_LOG": str(log), "DNS_STATE": str(temp / "dns"),
                 "STAGE_D_PROBE_API_KEY": "probe-key", "TRUSTEDROUTER_INTERNAL_TOKEN": "token",
                 "GATE_HOLD_NO_RERUN_MARK": str(mark)},
        )
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline and (temp / "dns").read_text().strip() != "a":
            time.sleep(0.2)
        self.assertEqual((temp / "dns").read_text().strip(), "a", "the cold swap never happened")
        time.sleep(1)  # inside the propagation wait
        os.killpg(proc.pid, signal.SIGTERM)  # what gate_hold does at a deadline
        out, err = proc.communicate(timeout=30)
        self.assertEqual(proc.returncode, 143, err)
        self.assertTrue(mark.exists(), "a cold swap must mark the attempt as never re-run")
        self.assertEqual((temp / "dns").read_text().strip(), "cname", err)
        self.assertIn("restored cold CNAME", err)
        executes = [line for line in log.read_text().splitlines() if "transaction execute" in line]
        self.assertEqual(len(executes), 2)


# The gateway side of the interleavings table ---------------------------------------

class Interleavings(unittest.TestCase):
    """quill-router docs/design/component-leases-v3.md, read from the gateway."""

    def test_control_plane_migrating_or_warming_changes_no_gateway_verdict(self) -> None:
        moving = lanes(held="control-plane")
        self.assertEqual(decide("pong", 0, after=moving), "pass")
        self.assertEqual(decide("canary", 0, after=moving), "pass")  # fresh evidence present
        self.assertTrue(decide("canary", 1, after=moving).startswith("gateway:"))

    def test_control_plane_canary_or_ramp_during_pong_gates_holds_the_gateway(self) -> None:
        moving = lanes(held="control-plane")
        self.assertTrue(decide("pong", 1, after=moving).startswith("inconclusive:"))
        self.assertTrue(decide("pre-dns", 65, after=moving).startswith("inconclusive:"))
        self.assertTrue(decide("discovery", 1, after=moving).startswith("inconclusive:"))

    def test_a_public_surface_change_is_inconclusive_if_it_ever_overlaps(self) -> None:
        # Admission keeps it exclusive with the gateway lane; this is defense in depth.
        self.assertTrue(decide("pong", 1, after=lanes(held="public-surface")).startswith("inconclusive:"))

    def test_after_the_control_plane_finishes_the_gate_is_as_strict_as_before(self) -> None:
        done = lanes(epochs={"control-plane": 4})
        self.assertTrue(decide("pong", 1, before=done, after=done).startswith("gateway:"))


if __name__ == "__main__":
    unittest.main()
