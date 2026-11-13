#!/usr/bin/env python3
"""Exercise the production region gate with isolated secondary-rollout mutations."""

import re
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ".github/workflows/deploy-enclave-gcp.yml"
INVENTORY = "tools/gcp-enclave-migs.txt"
PENDING_INVENTORY = "tools/gcp-enclave-migs-pending.txt"
HEARTBEAT = "tools/stage-d-heartbeat-regions.txt"
TERMINATE = "tools/stage-d-terminate-regions.txt"
# Europe and US East roll in one step; their flags carry a region key.
WAVE = "Roll Europe and US East GCP MIGs in parallel"


class TerminateRegionsTests(unittest.TestCase):
    def setUp(self):
        self.inputs = {
            name: (ROOT / name).read_text()
            for name in (WORKFLOW, INVENTORY, PENDING_INVENTORY, HEARTBEAT, TERMINATE)
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

    def test_four_region_termination_passes(self):
        self.assertEqual(
            self.inputs[TERMINATE].splitlines(),
            ["us-central1", "europe-west4", "us-east4", "us-west1"],
        )
        result = self.run_gate()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), [
            "QUILL_USAGE_HEARTBEAT 4 0 4", "QUILL_TERMINATE_AT_CAP 4 0 4",
        ])

    # The three tests below move a region that will stay in the main inventory,
    # so they keep holding after us-west1 is promoted and the pending file is
    # empty again.
    def take_from_inventory(self, region):
        line = next(
            entry for entry in self.inputs[INVENTORY].splitlines()
            if entry.startswith(region + ":")
        )
        self.inputs[INVENTORY] = self.inputs[INVENTORY].replace(line + "\n", "")
        return line

    def test_pending_region_is_held_to_the_same_bijection(self):
        self.inputs[PENDING_INVENTORY] += self.take_from_inventory("us-east4") + "\n"
        result = self.run_gate()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), [
            "QUILL_USAGE_HEARTBEAT 4 0 4", "QUILL_TERMINATE_AT_CAP 4 0 4",
        ])
        # Pending is not a way around the declaration: its flag must match too.
        self.set_flag_off(WAVE, "US_EAST4_QUILL_TERMINATE_AT_CAP")
        self.assert_rejected(
            "QUILL_TERMINATE_AT_CAP: declared regions not on: ['us-east4']"
        )

    def test_region_in_neither_inventory_is_rejected(self):
        # Positive control for the test above: the pending file is what kept
        # us-east4 configured there.
        self.take_from_inventory("us-east4")
        self.assert_rejected(
            "QUILL_USAGE_HEARTBEAT: unconfigured regions: ['us-east4']"
        )

    def test_region_in_both_inventories_is_rejected(self):
        self.inputs[PENDING_INVENTORY] += "us-east4:quill-enclave-mig-useast4\n"
        self.assert_rejected("invalid MIG inventory")

    def test_m1_europe_on_requires_terminate_declaration(self):
        self.remove_region(TERMINATE, "europe-west4")
        self.assert_rejected(
            "QUILL_TERMINATE_AT_CAP: declared regions not on: []; "
            "undeclared regions on: ['europe-west4']"
        )

    def test_m2_declared_us_east_cannot_be_off(self):
        self.set_flag_off(WAVE, "US_EAST4_QUILL_TERMINATE_AT_CAP")
        self.assert_rejected(
            "QUILL_TERMINATE_AT_CAP: declared regions not on: ['us-east4']"
        )

    def test_declared_europe_cannot_be_off(self):
        self.set_flag_off(WAVE, "EUROPE_WEST4_QUILL_TERMINATE_AT_CAP")
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
        self.set_flag_off(WAVE, "US_EAST4_QUILL_USAGE_HEARTBEAT")
        self.assert_rejected(
            "termination requires heartbeat in declared regions: ['us-east4']"
        )


    def edit_step(self, step, old, new):
        workflow = self.inputs[WORKFLOW]
        start = workflow.index(f"      - name: {step}\n")
        end = workflow.index("\n      - name:", start + 1)
        self.assertEqual(workflow[start:end].count(old), 1, old)
        self.inputs[WORKFLOW] = workflow[:start] + workflow[start:end].replace(old, new) + workflow[end:]

    def test_wave_flag_needs_its_own_regions_template(self):
        self.edit_step(WAVE, "US_EAST4_PREV_TEMPLATE:", "US_EAST4_PREVIOUS_TEMPLATE:")
        self.assert_rejected(f"QUILL_USAGE_HEARTBEAT: {WAVE}: cannot determine a unique rollout region")

    def test_wave_flag_key_must_match_the_template_it_names(self):
        # A key whose template output is another region's cannot claim it.
        self.edit_step(
            WAVE,
            "US_EAST4_PREV_TEMPLATE: ${{ steps.prev.outputs.us_east4_template }}",
            "US_EAST4_PREV_TEMPLATE: ${{ steps.prev.outputs.us_west1_template }}",
        )
        self.assert_rejected(f"QUILL_USAGE_HEARTBEAT: {WAVE}: cannot determine a unique rollout region")

    def test_unkeyed_flag_in_a_wave_step_is_rejected(self):
        # One bare flag would apply to every region in the wave.
        self.edit_step(
            WAVE,
            '          US_EAST4_QUILL_USAGE_HEARTBEAT: "on"\n',
            '          US_EAST4_QUILL_USAGE_HEARTBEAT: "on"\n          QUILL_USAGE_HEARTBEAT: "on"\n',
        )
        self.assert_rejected(f"QUILL_USAGE_HEARTBEAT: {WAVE}: cannot determine a unique rollout region")

    def test_keyed_flag_outside_a_wave_step_is_rejected(self):
        self.edit_step(
            "Roll US West GCP MIG",
            'QUILL_USAGE_HEARTBEAT: "on"',
            'US_WEST1_QUILL_USAGE_HEARTBEAT: "on"',
        )
        self.assert_rejected("QUILL_USAGE_HEARTBEAT: line")

    def test_duplicate_keyed_flag_is_rejected(self):
        self.edit_step(
            WAVE,
            'EUROPE_WEST4_QUILL_USAGE_HEARTBEAT: "on"',
            'US_EAST4_QUILL_USAGE_HEARTBEAT: "on"',
        )
        self.assert_rejected("QUILL_USAGE_HEARTBEAT: us-east4: duplicate flag")


if __name__ == "__main__":
    unittest.main()
