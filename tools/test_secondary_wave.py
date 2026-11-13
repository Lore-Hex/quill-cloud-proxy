#!/usr/bin/env python3
"""Execute tools/roll-secondary-wave.sh with every cloud call stubbed.

The real wave runner, the real tools/roll-secondary-region.sh workers and a
real advisory lock (fcntl, same semantics as util-linux flock) run; gcloud,
uv, curl and the per-step tools are stubs that log and can block, fail or
inject a peer failure at an exact point.
"""
from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EU = ["europe-west4", "quill-enclave-mig-eu", "quill-enclave-mig-eu-", "eu",
      "api.quillrouter.com,api-europe-west4.quillrouter.com", "quill-enclave-tpl-eu-100",
      "c3-standard-4", "TDX", "active", "none"]
USE = ["us-east4", "quill-enclave-mig-useast4", "quill-enclave-mig-useast4-", "useast4",
       "api.quillrouter.com,api-us-east4.quillrouter.com", "quill-enclave-tpl-useast4-100",
       "c3-standard-4", "TDX", "active", "none"]

# Wait (bounded) until a file exists; used to force a precise interleaving.
WAIT_FOR = '''wait_for() {
  for _ in $(seq 1 200); do [ -e "$1" ] && return 0; sleep 0.05; done
  echo "timed out waiting for $1" >&2; return 1
}
'''

BASH_STUB = '''#!/bin/bash
echo "bash $* heartbeat=${QUILL_USAGE_HEARTBEAT:-<unset>} terminate=${QUILL_TERMINATE_AT_CAP:-<unset>}" >> "${COMMAND_LOG}"
''' + WAIT_FOR + '''
case "$*" in
  "tools/deploy-gcp-mig.sh "*) touch "${MARKS}/deployed-$2" ;;
esac
if [ -n "${BLOCK_UNTIL_PEER_DEPLOYED:-}" ]; then
  case "$*" in
    "tools/wait-region-attested.sh quill-enclave-mig-eu- europe-west4") wait_for "${MARKS}/deployed-us-east4" || exit 9 ;;
    "tools/wait-region-attested.sh quill-enclave-mig-useast4- us-east4") wait_for "${MARKS}/deployed-europe-west4" || exit 9 ;;
  esac
fi
if [ -n "${BLOCK_STEP:-}" ] && [ "$*" = "${BLOCK_STEP}" ]; then
  wait_for "${MARKS}/${BLOCK_UNTIL_MARK}" || exit 9
fi
if [ -n "${FAIL_STEP:-}" ] && [ "$*" = "${FAIL_STEP}" ]; then
  echo "stub failing: $*" >&2
  exit 1
fi
if [ -n "${BLOCK_UNTIL_ABORT:-}" ] && [ "$*" = "${BLOCK_UNTIL_ABORT}" ]; then
  wait_for "${TR_SECONDARY_WAVE_DIR}/abort" || exit 9
fi
exit 0
'''

PYTHON_STUB = '''#!/bin/bash
echo "python3 $*" >> "${COMMAND_LOG}"
''' + WAIT_FOR + '''
case "$*" in
  "tools/watchdog.py --regions "*) touch "${MARKS}/watchdog-done-$3" ;;
esac
exit 0
'''


def flock_stub() -> str:
    # Lock the inherited descriptor and exit, exactly as flock(1) does: the
    # lock belongs to the open file description the calling subshell holds.
    # At the first lock a worker takes after its watchdog passed (its
    # promotion), optionally record a peer failure first.
    return f'''#!{sys.executable}
import fcntl, os, sys
fd = int(sys.argv[-1])
short = os.environ.get("REGION_SHORT", "")
inject = os.environ.get("INJECT_PEER_FAILURE_AT_PROMOTION_OF", "")
marks = os.environ.get("MARKS", "")
wave = os.environ.get("TR_SECONDARY_WAVE_DIR", "")
if inject and inject == short and os.path.exists(os.path.join(marks, "watchdog-done-" + {{"useast4": "us-east4", "eu": "europe-west4"}}.get(short, ""))):
    done = os.path.join(marks, "injected")
    if not os.path.exists(done):
        open(done, "w").close()
        with open(os.path.join(wave, "abort"), "w") as handle:
            handle.write("europe-west4\\n")
# Hold Europe, after it re-entered canonical DNS and before its next lock,
# until a peer has recorded a failure (without holding the lock meanwhile).
if os.environ.get("BLOCK_EU_AFTER_PROMOTION") and short == "eu" \\
        and os.path.exists(os.path.join(marks, "promoted-europe-west4")):
    import time
    for _ in range(200):
        if os.path.exists(os.path.join(wave, "abort")):
            break
        time.sleep(0.05)
fcntl.flock(fd, fcntl.LOCK_EX)
'''


class Harness:
    def __init__(self, temp: Path) -> None:
        self.temp = temp
        self.bin = temp / "bin"
        self.bin.mkdir()
        self.marks = temp / "marks"
        self.marks.mkdir()
        self.log = temp / "commands.log"
        stubs = {
            "bash": BASH_STUB,
            "python3": PYTHON_STUB,
            "uv": ('#!/bin/bash\necho "uv $*" >> "${COMMAND_LOG}"\n'
                   'for a in "$@"; do [ "$prev" = "--clear-drain-region" ] && touch "${MARKS}/promoted-$a"; prev="$a"; done\n'),
            "gcloud": '#!/bin/bash\necho "gcloud $*" >> "${COMMAND_LOG}"\n',
            "curl": ("#!/bin/bash\necho '{\"checks\": [{\"target_region\": \"europe-west4\"}, "
                     "{\"target_region\": \"us-east4\"}]}'\n"),
            "flock": flock_stub(),
        }
        for name, body in stubs.items():
            path = self.bin / name
            path.write_text(body)
            path.chmod(0o755)
        jq = shutil.which("jq")
        assert jq, "jq is required by the script under test"
        self.path = f"{self.bin}:{Path(jq).parent}:/usr/bin:/bin"

    def env(self, **extra: str) -> dict[str, str]:
        env = {
            "PATH": self.path, "TMPDIR": str(self.temp), "COMMAND_LOG": str(self.log),
            "MARKS": str(self.marks), "GITHUB_RUN_ID": "33807667585",
            "TR_DEPLOY_MUTEX_OPERATION": "a" * 32, "IMAGE_REF": "registry.example/enclave:new",
            "IMAGE_DIGEST": "sha256:" + "a" * 64,
            "EUROPE_WEST4_QUILL_USAGE_HEARTBEAT": "on", "EUROPE_WEST4_QUILL_TERMINATE_AT_CAP": "on",
            "US_EAST4_QUILL_USAGE_HEARTBEAT": "on", "US_EAST4_QUILL_TERMINATE_AT_CAP": "on",
        }
        env.update(extra)
        return env

    def wave(self, *regions: list[str], **extra: str) -> subprocess.CompletedProcess[str]:
        args: list[str] = []
        for region in regions:
            args += ["--", *region]
        return subprocess.run(["/bin/bash", str(ROOT / "tools/roll-secondary-wave.sh"), *args],
                              cwd=ROOT, env=self.env(**extra), capture_output=True, text=True, timeout=60)

    def commands(self) -> str:
        return self.log.read_text() if self.log.exists() else ""


class WaveTests(unittest.TestCase):
    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self.h = Harness(Path(self._dir.name))

    def tearDown(self) -> None:
        self._dir.cleanup()

    def test_regions_roll_concurrently_and_both_promote(self):
        # Each region blocks until the other has started deploying, which a
        # serial run can never satisfy.
        result = self.h.wave(EU, USE, BLOCK_UNTIL_PEER_DEPLOYED="1")
        log = self.h.commands()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr + log)
        for region in ("europe-west4", "us-east4"):
            self.assertIn(f"--clear-drain-region {region}", log)
            self.assertIn(f"  {region}: promoted", result.stdout)
            self.assertIn(f"[{region}] {region} rollout healthy", result.stdout)
        self.assertNotIn("recover-gcp-region.sh", log)

    def test_failure_rolls_back_only_its_region_and_stops_the_peer_promoting(self):
        result = self.h.wave(
            EU, USE,
            FAIL_STEP="tools/verify-region-before-dns.sh europe-west4 quill-enclave-mig-eu- sha256:" + "a" * 64,
            BLOCK_UNTIL_ABORT="tools/verify-region-before-dns.sh us-east4 quill-enclave-mig-useast4- sha256:" + "a" * 64,
        )
        log = self.h.commands()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr + log)
        # Neither region re-enters canonical DNS with the new image.
        self.assertNotIn("--clear-drain-region europe-west4", log)
        self.assertNotIn("--clear-drain-region us-east4", log)
        # The peer stopped at its next gate: no synthetic wait or watchdog ran.
        self.assertNotIn("wait-region-synthetic-up.sh us-east4", log)
        self.assertNotIn("watchdog.py --regions us-east4", log)
        # Each region restores itself; the failure is attributed to Europe.
        self.assertIn("recover-gcp-region.sh europe-west4 quill-enclave-mig-eu ", log)
        self.assertIn("recover-gcp-region.sh us-east4 quill-enclave-mig-useast4 ", log)
        self.assertIn("  europe-west4: FAILED (exit 1)", result.stdout)
        self.assertIn("  us-east4: not promoted: europe-west4 failed first", result.stdout)
        self.assertIn("[us-east4] us-east4: stopping before promotion because europe-west4 failed", result.stdout)
        self.assertIn("[europe-west4] europe-west4: rollout failed; restoring", result.stdout)
        self.assertIn("[us-east4] us-east4: not promoted; restoring", result.stdout)

    def test_peer_failure_recorded_at_the_promotion_lock_still_blocks_promotion(self):
        # The failure lands after the last between-step check, at the lock the
        # promotion takes: only the check made under that lock can see it.
        result = self.h.wave(USE, INJECT_PEER_FAILURE_AT_PROMOTION_OF="useast4")
        log = self.h.commands()
        self.assertTrue((self.h.marks / "injected").exists(), log)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr + log)
        self.assertIn("watchdog.py --regions us-east4", log)
        self.assertNotIn("--clear-drain-region us-east4", log)
        self.assertIn("recover-gcp-region.sh us-east4 quill-enclave-mig-useast4 ", log)
        self.assertIn("  us-east4: not promoted: europe-west4 failed first", result.stdout)

    def test_promoted_region_is_not_rolled_back_by_a_later_peer_failure(self):
        # Europe re-enters canonical DNS; only then does US East fail. Like a
        # later region in the serial run, Europe keeps the new image.
        step = "tools/wait-region-synthetic-up.sh us-east4 us-east4"
        result = self.h.wave(EU, USE, BLOCK_STEP=step, BLOCK_UNTIL_MARK="promoted-europe-west4", FAIL_STEP=step,
                             BLOCK_EU_AFTER_PROMOTION="1")
        log = self.h.commands()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr + log)
        self.assertIn("--clear-drain-region europe-west4", log)
        self.assertNotIn("recover-gcp-region.sh europe-west4", log)
        self.assertIn("recover-gcp-region.sh us-east4", log)
        self.assertIn("  europe-west4: promoted", result.stdout)
        self.assertIn("  us-east4: FAILED (exit 1)", result.stdout)

    def test_stage_d_flags_reach_only_their_own_region(self):
        result = self.h.wave(
            EU, USE,
            EUROPE_WEST4_QUILL_USAGE_HEARTBEAT="on", EUROPE_WEST4_QUILL_TERMINATE_AT_CAP="off",
            US_EAST4_QUILL_USAGE_HEARTBEAT="off", US_EAST4_QUILL_TERMINATE_AT_CAP="off",
        )
        log = self.h.commands()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr + log)
        self.assertIn("bash tools/deploy-gcp-mig.sh europe-west4 heartbeat=on terminate=off", log)
        self.assertIn("bash tools/deploy-gcp-mig.sh us-east4 heartbeat=off terminate=off", log)

    def test_wave_wide_or_missing_stage_d_flags_are_refused_before_any_change(self):
        for extra in ({"QUILL_USAGE_HEARTBEAT": "on"}, {"QUILL_TERMINATE_AT_CAP": "off"},
                      {"US_EAST4_QUILL_USAGE_HEARTBEAT": ""}, {"US_EAST4_QUILL_TERMINATE_AT_CAP": "yes"}):
            with self.subTest(extra=extra):
                result = self.h.wave(EU, USE, **extra)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(self.h.commands(), "")

    def test_duplicate_region_and_malformed_arguments_are_refused(self):
        self.assertEqual(self.h.wave(EU, EU).returncode, 2)
        bad = subprocess.run(["/bin/bash", str(ROOT / "tools/roll-secondary-wave.sh"), "--", *EU[:9]],
                             cwd=ROOT, env=self.h.env(), capture_output=True, text=True, timeout=10)
        self.assertEqual(bad.returncode, 2)
        self.assertEqual(self.h.commands(), "")


class WorkerTests(unittest.TestCase):
    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self.h = Harness(Path(self._dir.name))

    def tearDown(self) -> None:
        self._dir.cleanup()

    def run_worker(self, wave_dir: Path | None) -> subprocess.CompletedProcess[str]:
        extra = {"QUILL_USAGE_HEARTBEAT": "on", "QUILL_TERMINATE_AT_CAP": "on"}
        if wave_dir is not None:
            extra["TR_SECONDARY_WAVE_DIR"] = str(wave_dir)
        return subprocess.run(["/bin/bash", str(ROOT / "tools/roll-secondary-region.sh"), *USE],
                              cwd=ROOT, env=self.h.env(**extra), capture_output=True, text=True, timeout=30)

    def test_region_is_untouched_when_a_peer_already_failed(self):
        wave = self.h.temp / "wave"
        wave.mkdir()
        (wave / "dns-reconcile.lock").touch()
        (wave / "abort").write_text("europe-west4\n")
        result = self.run_worker(wave)
        log = self.h.commands()
        self.assertEqual(result.returncode, 75, result.stderr)
        self.assertNotIn("--set-drain-region us-east4", log)
        self.assertNotIn("recover-gcp-region.sh", log)
        self.assertTrue(wave.exists(), "a worker must not delete the shared wave directory")

    def test_own_failure_is_recorded_for_peers_before_recovery(self):
        wave = self.h.temp / "wave"
        wave.mkdir()
        (wave / "dns-reconcile.lock").touch()
        env_fail = "tools/wait-region-attested.sh quill-enclave-mig-useast4- us-east4"
        extra = {"QUILL_USAGE_HEARTBEAT": "on", "QUILL_TERMINATE_AT_CAP": "on",
                 "TR_SECONDARY_WAVE_DIR": str(wave), "FAIL_STEP": env_fail}
        result = subprocess.run(["/bin/bash", str(ROOT / "tools/roll-secondary-region.sh"), *USE],
                                cwd=ROOT, env=self.h.env(**extra), capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual((wave / "abort").read_text(), "us-east4\n")
        self.assertIn("recover-gcp-region.sh us-east4", self.h.commands())

    def test_standalone_worker_is_unchanged_and_cleans_its_private_lock(self):
        before = set(self.h.temp.iterdir())
        result = self.run_worker(None)
        self.assertEqual(result.returncode, 0, result.stderr + self.h.commands())
        self.assertIn("--clear-drain-region us-east4", self.h.commands())
        leftovers = {p for p in set(self.h.temp.iterdir()) - before if p.name.startswith("tr-secondary")}
        self.assertEqual(leftovers, set())


class RecoveryLockTests(unittest.TestCase):
    """Recoveries inside a wave serialize drain and DNS changes on the wave lock."""

    def test_wave_lock_serializes_concurrent_critical_sections(self):
        recovery = (ROOT / "tools/recover-gcp-region.sh").read_text()
        start = recovery.index("with_wave_dns_lock() {")
        end = recovery.index("\n}\n", start) + 3
        function = recovery[start:end]
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
            h = Harness(temp)
            wave = temp / "wave"
            wave.mkdir()
            log = temp / "sections.log"
            script = function + (
                'section() { echo "start $1" >> "$LOG"; sleep 0.3; echo "end $1" >> "$LOG"; }\n'
                'with_wave_dns_lock section "$1"\n')
            env = {"PATH": h.path, "TR_SECONDARY_WAVE_DIR": str(wave), "LOG": str(log)}
            procs = [subprocess.Popen(["/bin/bash", "-c", script, "x", name], env=env) for name in "ab"]
            for proc in procs:
                self.assertEqual(proc.wait(timeout=20), 0)
            events = log.read_text().splitlines()
            self.assertEqual(len(events), 4)
            # No interleaving: each start is immediately followed by its end.
            self.assertEqual(events[0].split()[1], events[1].split()[1])
            self.assertEqual(events[2].split()[1], events[3].split()[1])

    def test_every_recovery_dns_mutation_takes_the_wave_lock(self):
        recovery = (ROOT / "tools/recover-gcp-region.sh").read_text()
        self.assertIn("with_wave_dns_lock update_drain_unlocked", recovery)
        self.assertIn("with_wave_dns_lock reconcile_gcp_dns_unlocked", recovery)
        self.assertIn("with_wave_dns_lock python3 tools/sync-route53-api-aliases.py --apply", recovery)
        body = recovery[recovery.index("trap on_exit EXIT"):]
        for unlocked in ("update_drain_unlocked", "reconcile_gcp_dns_unlocked"):
            self.assertNotIn(unlocked, body)


if __name__ == "__main__":
    unittest.main()
