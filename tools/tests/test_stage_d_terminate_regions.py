#!/usr/bin/env python3
"""Exercise the production region gate with isolated secondary-rollout mutations."""

import re
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ".github/workflows/deploy-enclave-gcp.yml"
HEARTBEAT = "tools/stage-d-heartbeat-regions.txt"
TERMINATE = "tools/stage-d-terminate-regions.txt"


class TerminateRegionsTests(unittest.TestCase):
    def setUp(self):
        self.inputs = {
            name: (ROOT / name).read_text()
            for name in (WORKFLOW, "tools/gcp-enclave-migs.txt", HEARTBEAT, TERMINATE)
        }

    def run_gate(self):
        # Run the exact pinned shell block, including fail-closed exit handling.
        shell = (ROOT / "tools/tests/test-stage-d-gates.sh").read_text()
        start = shell.index("workflow=.github/workflows/deploy-enclave-gcp.yml\n")
        end = shell.index('\ngrep -Fq "/internal/gateway/', start)
        with tempfile.TemporaryDirectory() as directory:
            for name, contents in self.inputs.items():
                path = Path(directory) / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(contents)
            return subprocess.run(
                ["bash", "-euo", "pipefail", "-c",
                 shell[start:end] + '\nprintf "%s\\n" "${stage_d_counts}"'],
                cwd=directory, capture_output=True, text=True, timeout=5,
            )

    def set_flag_off(self, step, flag):
        workflow = self.inputs[WORKFLOW]
        start = workflow.index(f"      - name: {step}\n")
        end = workflow.index("\n      - name:", start + 1)
        block, count = re.subn(
            rf'({flag}: )"on"', r'\1"off"', workflow[start:end]
        )
        self.assertEqual(count, 1, "mutation must change exactly one on flag")
        self.inputs[WORKFLOW] = workflow[:start] + block + workflow[end:]

    def remove_region(self, name, region):
        self.assertEqual(self.inputs[name].splitlines().count(region), 1)
        self.inputs[name] = self.inputs[name].replace(region + "\n", "")

    def assert_rejected(self, message):
        result = self.run_gate()
        self.assertNotEqual(result.returncode, 0, "mutation unexpectedly passed")
        self.assertIn("Stage D region bijection: " + message, result.stderr)

    def test_three_region_termination_passes(self):
        self.assertEqual(
            self.inputs[TERMINATE].splitlines(),
            ["us-central1", "europe-west4", "us-east4"],
        )
        result = self.run_gate()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), [
            "QUILL_USAGE_HEARTBEAT 3 0 3", "QUILL_TERMINATE_AT_CAP 3 0 3",
        ])

    def test_m1_europe_on_requires_terminate_declaration(self):
        self.remove_region(TERMINATE, "europe-west4")
        self.assert_rejected(
            "QUILL_TERMINATE_AT_CAP: declared regions not on: []; "
            "undeclared regions on: ['europe-west4']"
        )

    def test_m2_declared_us_east_cannot_be_off(self):
        self.set_flag_off("Roll US East GCP MIG", "QUILL_TERMINATE_AT_CAP")
        self.assert_rejected(
            "QUILL_TERMINATE_AT_CAP: declared regions not on: ['us-east4']"
        )

    def test_declared_europe_cannot_be_off(self):
        self.set_flag_off("Roll Europe GCP MIG", "QUILL_TERMINATE_AT_CAP")
        self.assert_rejected(
            "QUILL_TERMINATE_AT_CAP: declared regions not on: ['europe-west4']"
        )

    def test_m3_us_east_termination_requires_heartbeat_declaration(self):
        self.remove_region(HEARTBEAT, "us-east4")
        self.assert_rejected(
            "termination requires heartbeat in declared regions: ['us-east4']"
        )

    def test_subset_rejected_even_when_heartbeat_bijection_matches(self):
        self.remove_region(HEARTBEAT, "us-east4")
        self.set_flag_off("Roll US East GCP MIG", "QUILL_USAGE_HEARTBEAT")
        self.assert_rejected(
            "termination requires heartbeat in declared regions: ['us-east4']"
        )


if __name__ == "__main__":
    unittest.main()
