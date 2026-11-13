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
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

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
    return {"schema_version": version, "cloud": "gcp", "lanes": out}


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

    def test_a_canary_pass_with_an_unreadable_page_while_moving_is_inconclusive(self) -> None:
        verdict = decide("canary", 0, after=lanes(held="control-plane"), payload={"oops": 1})
        self.assertTrue(verdict.startswith("inconclusive:"), verdict)


class GatewayFailures(unittest.TestCase):
    def test_a_failed_canary_is_always_the_gateways(self) -> None:
        verdict = decide("canary", 1, after=lanes(held="control-plane"))
        self.assertTrue(verdict.startswith("gateway:"), verdict)

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
import os, sys
seq = os.environ["LANES_SEQ"]
lines = open(seq).read().splitlines()
with open(os.environ["LANES_LOG"], "a") as log:
    log.write(" ".join(sys.argv[1:]) + "\n")
if not lines:
    sys.exit(1)
print(lines[0])
if len(lines) > 1:
    open(seq, "w").write("\n".join(lines[1:]) + "\n")
'''

GATE_STUB = r'''#!/bin/bash
codes="$(cat "${GATE_CODES}")"
code="${codes%% *}"
rest="${codes#* }"
[ "${rest}" = "${codes}" ] || printf '%s' "${rest}" > "${GATE_CODES}"
echo "gate $* started_at=${WAIT_UP_STARTED_AT:-unset}" >> "${GATE_LOG}"
exit "${code}"
'''

CURL_STUB = r'''#!/bin/bash
[ -f "${STATUS_FILE}" ] || exit 7
cat "${STATUS_FILE}"
'''


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
        self.addCleanup(shutil.rmtree, self.temp, ignore_errors=True)

    def run_lib(self, script: str, *, codes: str = "0", lane_lines: list[object] | None = None,
                status: object | None = None, hold_max: int = 3, env: dict[str, str] | None = None,
                errexit: bool = False) -> tuple[subprocess.CompletedProcess[str], list[str]]:
        (self.temp / "codes").write_text(codes)
        (self.temp / "lanes").write_text("".join(json.dumps(x) + "\n" for x in (lane_lines or [STILL])))
        status_file = self.temp / "status.json"
        if status is not None:
            status_file.write_text(json.dumps(status))
        completed = subprocess.run(
            [TEST_BASH, "-c", f'set -{"e" if errexit else ""}uo pipefail\n'
                              f'source "{self.tools}/gate-hold-lib.sh"\n{script}'],
            env={"PATH": f"{self.bin}:/usr/bin:/bin", "TMPDIR": str(self.temp),
                 "GATE_CODES": str(self.temp / "codes"), "GATE_LOG": str(self.temp / "gate.log"),
                 "LANES_SEQ": str(self.temp / "lanes"), "LANES_LOG": str(self.temp / "lanes.log"),
                 "STATUS_FILE": str(status_file), "TR_CP_HOLD_STATE_DIR": str(self.temp / "hold"),
                 "TR_CP_HOLD_MAX_SECONDS": str(hold_max), "TR_CP_HOLD_SLEEP_SECONDS": "1",
                 **(env or {})},
            capture_output=True, text=True, timeout=60,
        )
        log = self.temp / "gate.log"
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
        moving = lanes(held="control-plane")
        done, log = self.run_lib('gate_hold pong us-central1 gate; echo "rc=$?"', codes="1 1 0",
                                 lane_lines=[moving], status=self.fresh_page(), hold_max=30)
        self.assertIn("rc=0", done.stdout)
        self.assertEqual(len(log), 3)
        self.assertEqual(done.stderr.count("::warning::us-central1: pong gate inconclusive"), 2)

    def test_a_failure_while_the_control_plane_keeps_moving_fails_closed_after_the_bound(self) -> None:
        moving = lanes(held="control-plane")
        started = time.monotonic()
        done, log = self.run_lib('gate_hold pong us-central1 gate; echo "rc=$?"', codes="9",
                                 lane_lines=[moving], status=self.fresh_page(), hold_max=2)
        self.assertIn("rc=9", done.stdout)
        self.assertIn("failing closed", done.stderr)
        self.assertGreaterEqual(len(log), 2)
        self.assertLessEqual(len(log), 5)
        self.assertLess(time.monotonic() - started, 20)

    def test_a_canary_that_passed_blind_while_moving_reruns_then_fails_closed(self) -> None:
        moving = lanes(held="control-plane")
        stale = healthy_page(at=time.time() - 3600)
        done, log = self.run_lib('gate_hold canary us-central1 gate; echo "rc=$?"', codes="0",
                                 lane_lines=[moving], status=stale, hold_max=2)
        self.assertIn("rc=1", done.stdout)
        self.assertGreaterEqual(len(log), 2)

    def test_the_hold_clock_is_shared_by_a_regions_gates(self) -> None:
        moving = lanes(held="control-plane")
        hold = self.temp / "hold"
        hold.mkdir()
        (hold / "cp-hold-started-us-central1").write_text(f"{int(time.time()) - 100}\n")
        done, log = self.run_lib('gate_hold pong us-central1 gate; echo "rc=$?"', codes="1",
                                 lane_lines=[moving], status=self.fresh_page(), hold_max=60)
        self.assertIn("rc=1", done.stdout)
        self.assertEqual(len(log), 1)  # the bound was already spent by an earlier gate

    def test_no_decision_leaves_the_gates_own_verdict(self) -> None:
        (self.tools / "gate_hold.py").write_text("import sys\nsys.exit(3)\n")
        for codes, expected in (("0", "rc=0"), ("4", "rc=4")):
            done, log = self.run_lib('gate_hold pong r gate; echo "rc=$?"', codes=codes,
                                     lane_lines=[lanes(held="control-plane")])
            self.assertIn(expected, done.stdout)
            self.assertEqual(len(log), 1)
            (self.temp / "gate.log").unlink()

    def test_holding_runs_the_between_hook_and_it_can_stop_the_hold(self) -> None:
        moving = lanes(held="control-plane")
        script = ('stop() { echo hook >&2; exit 75; }\nGATE_HOLD_BETWEEN=stop\n'
                  'gate_hold pong us-central1 gate; echo "rc=$?"')
        done, log = self.run_lib(script, codes="1", lane_lines=[moving], status=self.fresh_page(),
                                 hold_max=60)
        self.assertEqual(done.returncode, 75)
        self.assertIn("hook", done.stderr)
        self.assertEqual(len(log), 1)

    def test_lanes_are_read_before_and_after_every_attempt(self) -> None:
        self.run_lib("gate_hold pong r gate", codes="0")
        self.assertEqual((self.temp / "lanes.log").read_text().splitlines(),
                         ["lanes --cloud gcp", "lanes --cloud gcp"])

    def test_under_errexit_like_actions_the_loop_still_decides(self) -> None:
        # GitHub Actions runs `run:` blocks with bash -eo pipefail.
        moving = lanes(held="control-plane")
        done, log = self.run_lib("gate_hold pong r gate\necho after", codes="1 1 0",
                                 lane_lines=[moving], status=self.fresh_page(), hold_max=30, errexit=True)
        self.assertEqual((done.returncode, done.stdout.strip(), len(log)), (0, "after", 3))
        (self.temp / "gate.log").unlink()
        (self.temp / "hold" / "cp-hold-started-r").unlink()  # a fresh region clock
        done, log = self.run_lib("gate_hold pong r gate\necho after", codes="9",
                                 lane_lines=[moving], status=self.fresh_page(), hold_max=2, errexit=True)
        self.assertEqual((done.returncode, done.stdout.strip()), (9, ""))
        self.assertIn("failing closed", done.stderr)
        self.assertGreaterEqual(len(log), 2)
        (self.temp / "gate.log").unlink()
        done, log = self.run_lib("gate_hold pong r gate\necho after", codes="7",
                                 status=self.fresh_page(), errexit=True)
        self.assertEqual((done.returncode, len(log)), (7, 1))
        self.assertIn("attributed to the gateway", done.stderr)

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
        for call in ('rollout_step gate_hold pre-dns "${region}" bash tools/verify-region-before-dns.sh',
                     'rollout_step gate_hold pong "${region}" interruptible bash tools/wait-region-synthetic-up.sh',
                     'gate_hold canary "${region}" interruptible python3 tools/watchdog.py',
                     'presence="$(gate_status_presence "${region}" "${presence_mode}")"',
                     "GATE_HOLD_BETWEEN=check_not_aborted"):
            self.assertIn(call, SECONDARY)
        self.assertNotIn("curl -fsS --max-time 15 https://trustedrouter.com/status.json", SECONDARY)

    def test_timeouts_leave_room_for_the_hold_bound(self) -> None:
        bound_minutes = 1800 // 60
        for name, gate_minutes in (("Blocking per-instance streaming gate (us-central1)", 12),
                                   ("Wait for us-central1 synthetic up", 12),
                                   ("Roll US West GCP MIG", 55),
                                   ("Roll Europe and US East GCP MIGs in parallel", 100)):
            minutes = int(re.search(r"timeout-minutes: (\d+)", step(name)).group(1))
            self.assertGreaterEqual(minutes, gate_minutes + bound_minutes, name)
        worker = int(re.search(r'TR_SECONDARY_WORKER_TIMEOUT: "(\d+)"', WORKFLOW).group(1))
        self.assertGreaterEqual(worker, 3300 + 1800)
        wave = int(re.search(r"timeout-minutes: (\d+)",
                             step("Roll Europe and US East GCP MIGs in parallel")).group(1))
        # Recovery still has its 40 minutes after the forward deadline.
        self.assertGreaterEqual(wave * 60, worker + 40 * 60 - 600)

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

    def test_new_files_trigger_a_gateway_rollout_and_run_in_ci(self) -> None:
        for path in ("tools/gate-hold-lib.sh", "tools/gate_hold.py"):
            self.assertIn(f'      - "{path}"\n', WORKFLOW)
        ci = (ROOT / ".github/workflows/ci.yml").read_text()
        self.assertIn("python3 tools/test_gate_hold.py", ci)


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
