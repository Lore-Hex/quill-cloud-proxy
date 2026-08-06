#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]


class RolloutSafetyTests(unittest.TestCase):
    def test_workflow_uses_persistent_drains_for_every_region(self) -> None:
        workflow = (
            ROOT / ".github" / "workflows" / "deploy-enclave-gcp.yml"
        ).read_text(encoding="utf-8")

        self.assertIn("--set-drain-region us-central1", workflow)
        self.assertIn("--clear-drain-region us-central1", workflow)
        self.assertIn('update_drain set "${region}"', workflow)
        self.assertIn('update_drain clear "${region}"', workflow)
        self.assertNotIn("QUILL_EXCLUDE_CANONICAL_REGIONS:", workflow)

    def test_rollout_does_not_force_a_second_replacement_wave(self) -> None:
        deploy = (ROOT / "tools" / "deploy-gcp-mig.sh").read_text(encoding="utf-8")
        workflow = (
            ROOT / ".github" / "workflows" / "deploy-enclave-gcp.yml"
        ).read_text(encoding="utf-8")
        command = re.compile(
            r"^\s*(?:gc|gcloud)\s+compute\s+instance-groups\s+managed"
            r"\s+rolling-action\s+replace\b",
            re.MULTILINE,
        )

        self.assertIsNone(command.search(deploy))
        self.assertIsNone(command.search(workflow))
        self.assertIn("--update-policy-type=proactive", deploy)
        self.assertIn("--update-policy-max-unavailable=\"$MAX_UNAVAILABLE\"", deploy)
        self.assertIn("--update-policy-max-surge=\"$MAX_SURGE\"", deploy)

    def test_default_capacity_keeps_each_region_warm_during_rollout(self) -> None:
        deploy = (ROOT / "tools" / "deploy-gcp-mig.sh").read_text(encoding="utf-8")

        self.assertIn('TARGET_SIZE="${TARGET_SIZE:-2}"', deploy)
        self.assertIn('MAX_SURGE="${MAX_SURGE:-3}"', deploy)
        self.assertIn('MAX_UNAVAILABLE="${MAX_UNAVAILABLE:-0}"', deploy)
        self.assertIn('--update-policy-max-unavailable="$MAX_UNAVAILABLE"', deploy)

    def test_rollout_holds_old_generation_until_replacements_can_attest(self) -> None:
        deploy = (ROOT / "tools" / "deploy-gcp-mig.sh").read_text(encoding="utf-8")
        workflow = (
            ROOT / ".github" / "workflows" / "deploy-enclave-gcp.yml"
        ).read_text(encoding="utf-8")

        self.assertIn('MIN_READY="${MIN_READY:-600s}"', deploy)
        self.assertEqual(
            deploy.count('--update-policy-min-ready="$MIN_READY"'),
            2,
            "existing and newly-created MIGs must share the readiness hold",
        )
        self.assertEqual(
            deploy.count("gc beta compute instance-groups managed"),
            2,
            "minReadySec must use the beta Compute API until it reaches GA",
        )
        self.assertIn("install_components: beta", workflow)

    def test_pre_roll_failure_only_clears_drain_when_template_is_unchanged(self) -> None:
        workflow = (
            ROOT / ".github" / "workflows" / "deploy-enclave-gcp.yml"
        ).read_text(encoding="utf-8")

        self.assertIn(
            "Clear a stale drain when the primary template never changed", workflow
        )
        self.assertIn('[ "${current}" != "${PREV_US}" ]', workflow)
        self.assertIn("--clear-drain-region us-central1", workflow)

    def test_public_allowlist_is_published_before_rollout_and_collapsed_after(self) -> None:
        workflow = (
            ROOT / ".github" / "workflows" / "deploy-enclave-gcp.yml"
        ).read_text(encoding="utf-8")

        transition = workflow.index("\n  publish-transition-trust-page:")
        rollout = workflow.index("\n  rollout:")
        finalize = workflow.index("\n  finalize-trust-artifacts:")
        publish_final = workflow.index("\n  publish-trust-page:", finalize)

        self.assertLess(transition, rollout)
        self.assertLess(rollout, finalize)
        self.assertLess(finalize, publish_final)
        self.assertIn(
            "needs: [build-and-release, grant-batch-image-access, publish-transition-trust-page]",
            workflow,
        )
        self.assertIn('--accepted-image-digests "${previous}"', workflow)
        self.assertIn(
            '--accepted-image-references "${previous_references}"', workflow
        )
        self.assertIn(
            "expected_references: ${{ needs.build-and-release.outputs.accepted_references }}",
            workflow,
        )
        self.assertIn(
            "needs: [build-and-release, finalize-trust-artifacts]",
            workflow,
        )


if __name__ == "__main__":
    unittest.main()
