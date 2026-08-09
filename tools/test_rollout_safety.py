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

    def test_sao_paulo_uses_supported_amd_sev_profile(self) -> None:
        deploy = (ROOT / "tools" / "deploy-gcp-mig.sh").read_text(encoding="utf-8")
        workflow = (
            ROOT / ".github" / "workflows" / "deploy-enclave-gcp.yml"
        ).read_text(encoding="utf-8")

        self.assertIn('if [ "${REGION}" = "southamerica-east1" ]', deploy)
        self.assertIn('CONF_COMPUTE_TYPE}" != "SEV"', deploy)
        self.assertIn('"${MACHINE_TYPE}" != n2d-*', deploy)
        self.assertIn("CONF_COMPUTE_TYPE=SEV_SNP is not supported", deploy)
        self.assertIn("southamerica-east1:quill-enclave-mig-sa", workflow)
        sa_start = workflow.index(
            "          roll_secondary_region \\\n"
            "            southamerica-east1"
        )
        sa_end = workflow.index(
            ' >"${logs_dir}/southamerica-east1.log"',
            sa_start,
        )
        sa_call = workflow[sa_start:sa_end]
        self.assertIn("quill-enclave-mig-sa", sa_call)
        self.assertIn("api-southamerica-east1.quillrouter.com", sa_call)
        self.assertIn("n2d-standard-4", sa_call)
        self.assertIn("SEV", sa_call)
        self.assertGreaterEqual(
            workflow.count("api-southamerica-east1.quillrouter.com"),
            4,
            "all earlier regional rolls must answer the new SNI for ACME bootstrap",
        )

    def test_new_region_is_canaried_before_dns_and_global_traffic(self) -> None:
        workflow = (
            ROOT / ".github" / "workflows" / "deploy-enclave-gcp.yml"
        ).read_text(encoding="utf-8")
        function_start = workflow.index("          roll_secondary_region() {")
        function_end = workflow.index("          logs_dir=", function_start)
        function = workflow[function_start:function_end]

        direct_canary = function.index("verify-region-before-dns.sh")
        regional_promotion = function.index(
            'QUILL_ALLOW_DRAINED_REGIONAL_PROMOTION_REGIONS="${region}"'
        )
        canonical_readd = function.index('update_drain clear "${region}"')
        self.assertLess(direct_canary, regional_promotion)
        self.assertLess(regional_promotion, canonical_readd)
        self.assertIn(
            "first deployment has no synthetic target yet; direct per-instance "
            "attestation + PONG is the bootstrap gate",
            function,
        )

        direct_gate = (ROOT / "tools" / "verify-region-before-dns.sh").read_text(
            encoding="utf-8"
        )
        canonical_gate = direct_gate.index(
            'verify_instance "${BOOTSTRAP_HOST}" "${ip}" 3 bootstrap'
        )
        dns_bootstrap = direct_gate.index(
            "if replace_cold_alias_with_bootstrap_ip; then"
        )
        regional_gate = direct_gate.index(
            'verify_instance "${REGIONAL_HOST}" "${ip}" "${regional_attempts}" regional'
        )
        self.assertLess(canonical_gate, dns_bootstrap)
        self.assertLess(dns_bootstrap, regional_gate)
        self.assertIn('idempotency-key: ${idempotency_key}', direct_gate)
        self.assertIn('--connect-ip "${ip}"', direct_gate)
        self.assertIn('--expect-digest "${IMAGE_DIGEST}"', direct_gate)
        self.assertIn("restore_cold_alias", direct_gate)
        self.assertIn('trap on_exit EXIT', direct_gate)
        self.assertIn('promoted_cold_alias=0', direct_gate)

    def test_sao_paulo_is_not_managed_as_a_cold_dns_alias(self) -> None:
        terraform = (ROOT / "tools" / "dns" / "main.tf").read_text(encoding="utf-8")
        repair = (ROOT / "tools" / "fix-quillrouter-dns.sh").read_text(encoding="utf-8")
        aliases = terraform[
            terraform.index("  quill_cold_region_aliases = [") : terraform.index(
                "  ]", terraform.index("  quill_cold_region_aliases = [")
            )
        ]
        self.assertNotIn("southamerica-east1", aliases)
        cold_loop = repair[
            repair.index("for region in us-central1") : repair.index(
                "done", repair.index("for region in us-central1")
            )
        ]
        self.assertNotIn("southamerica-east1", cold_loop)

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

    def test_transition_and_final_pages_artifacts_have_unique_names(self) -> None:
        deploy_workflow = (
            ROOT / ".github" / "workflows" / "deploy-enclave-gcp.yml"
        ).read_text(encoding="utf-8")
        publish_workflow = (
            ROOT / ".github" / "workflows" / "publish-trust-page.yml"
        ).read_text(encoding="utf-8")

        self.assertEqual(
            deploy_workflow.count("artifact_name: github-pages-transition"), 1
        )
        self.assertEqual(deploy_workflow.count("artifact_name: github-pages-final"), 1)
        self.assertEqual(
            publish_workflow.count("${{ inputs.artifact_name || 'github-pages' }}"),
            3,
            "upload, initial deploy, and retry must select the same artifact",
        )


if __name__ == "__main__":
    unittest.main()
