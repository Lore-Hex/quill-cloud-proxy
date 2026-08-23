#!/usr/bin/env python3
from __future__ import annotations

import os
import re
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class RolloutSafetyTests(unittest.TestCase):
    def test_workflow_uses_persistent_drains_for_every_region(self) -> None:
        workflow = (
            ROOT / ".github" / "workflows" / "deploy-enclave-gcp.yml"
        ).read_text(encoding="utf-8")
        secondary = (ROOT / "tools" / "roll-secondary-region.sh").read_text(
            encoding="utf-8"
        )

        self.assertIn("--set-drain-region us-central1", workflow)
        self.assertIn(
            "PREV_DRAIN_STATE: "
            "${{ steps.prev.outputs.us_central1_drain_state }}",
            workflow,
        )
        self.assertIn('"--${drain_operation}-drain-region" us-central1', workflow)
        capture_start = workflow.index("      - name: Capture pre-rollout templates")
        capture_end = workflow.index(
            "\n\n      # Staged regional rollout", capture_start
        )
        capture = workflow[capture_start:capture_end]
        self.assertIn("QUILL_API_HOST=api.trustedrouter.com", capture)
        self.assertIn("QUILL_DNS_ZONE=trustedrouter-com", capture)
        self.assertIn("--list-drain-regions", capture)
        self.assertIn('update_drain set "${region}"', secondary)
        self.assertIn('update_drain clear "${region}"', secondary)
        self.assertIn('prior_drain_state="$9"', secondary)
        self.assertIn(
            "PREV_DRAIN_STATE: "
            "${{ steps.prev.outputs.europe_west4_drain_state }}",
            workflow,
        )
        self.assertIn(
            "PREV_DRAIN_STATE: ${{ steps.prev.outputs.us_east4_drain_state }}",
            workflow,
        )
        self.assertIn(
            "PREV_DRAIN_STATE: "
            "${{ steps.prev.outputs.southamerica_east1_drain_state }}",
            workflow,
        )
        self.assertNotIn("QUILL_EXCLUDE_CANONICAL_REGIONS:", workflow)

    def test_secondary_rejects_unknown_drain_state_before_mutation(self) -> None:
        completed = subprocess.run(
            [
                "bash",
                str(ROOT / "tools" / "roll-secondary-region.sh"),
                "europe-west4",
                "quill-enclave-mig-eu",
                "quill-enclave-mig-eu-",
                "eu",
                "api.trustedrouter.com",
                "old-template",
                "c3-standard-4",
                "TDX",
                "",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=5,
        )

        self.assertEqual(completed.returncode, 2, completed.stderr)
        self.assertIn("invalid pre-rollout drain state", completed.stderr)

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

    def test_gcp_gateway_rejects_observer_only_control_plane_overrides(self) -> None:
        deploy = (ROOT / "tools" / "deploy-gcp-mig.sh").read_text(
            encoding="utf-8"
        )

        self.assertIn(
            'TR_CONTROL_PLANE_BASE_URL="${TR_CONTROL_PLANE_BASE_URL:-https://trustedrouter.com}"',
            deploy,
        )
        self.assertIn("validate-control-plane-endpoints.py", deploy)

    def test_aws_observer_hosts_follow_the_configured_regions(self) -> None:
        script_path = ROOT / "tools" / "aws-control-plane-failover.sh"
        script = script_path.read_text(encoding="utf-8")

        self.assertIn('PRIMARY_HOST="aws-${PRIMARY_SLUG}.trustedrouter.com"', script)
        self.assertIn('SECONDARY_HOST="aws-${SECONDARY_SLUG}.trustedrouter.com"', script)
        self.assertNotIn("aws-euw1.trustedrouter.com", script)
        self.assertNotIn("aws-euw3.trustedrouter.com", script)

        completed = subprocess.run(
            ["bash", str(script_path), "cert"],
            cwd=ROOT,
            env={**os.environ, "PRIMARY_REGION": "us-east-2"},
            capture_output=True,
            text=True,
            timeout=5,
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("unknown region us-east-2", completed.stderr)

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
            "          bash tools/roll-secondary-region.sh \\\n"
            "            southamerica-east1"
        )
        sa_end = workflow.index("\n\n      # No cross-region", sa_start)
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
        function = (ROOT / "tools" / "roll-secondary-region.sh").read_text(
            encoding="utf-8"
        )

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

    def test_secondary_rollout_explicitly_guards_fail_closed_steps(self) -> None:
        workflow = (
            ROOT / ".github" / "workflows" / "deploy-enclave-gcp.yml"
        ).read_text(encoding="utf-8")
        function = (ROOT / "tools" / "roll-secondary-region.sh").read_text(
            encoding="utf-8"
        )

        # Keep every safety-sensitive command behind the explicit wrapper so
        # failures terminate this region before the next workflow step starts.
        self.assertIn("rollout_step() {", function)
        self.assertIn('exit "${step_status}"', function)
        self.assertIn("trap on_exit EXIT", function)
        self.assertIn("bash tools/recover-gcp-region.sh", function)
        for command in (
            'rollout_step update_drain set "${region}"',
            "rollout_step reconcile_dns",
            'rollout_step bash tools/wait-canonical-drained.sh "${region}"',
            'rollout_step bash tools/deploy-gcp-mig.sh "${region}"',
            "rollout_step wait_region_stable_with_dns_refresh",
            "rollout_step bash tools/wait-region-attested.sh",
            "rollout_step bash tools/verify-region-before-dns.sh",
            "rollout_step bash tools/wait-region-synthetic-up.sh",
            'rollout_step update_drain clear "${region}"',
        ):
            self.assertIn(command, function)

        self.assertIn("set -euo pipefail", function)
        europe = workflow.index("      - name: Roll Europe GCP MIG")
        us_east = workflow.index("      - name: Roll US East GCP MIG")
        sao_paulo = workflow.index("      - name: Roll São Paulo GCP MIG")
        self.assertLess(europe, us_east)
        self.assertLess(us_east, sao_paulo)

    def test_each_secondary_rollout_refreshes_route53_credentials(self) -> None:
        workflow = (
            ROOT / ".github" / "workflows" / "deploy-enclave-gcp.yml"
        ).read_text(encoding="utf-8")

        pairs = (
            (
                "Refresh AWS credentials for Europe backup-domain DNS",
                "Roll Europe GCP MIG",
            ),
            (
                "Refresh AWS credentials for US East backup-domain DNS",
                "Roll US East GCP MIG",
            ),
            (
                "Refresh AWS credentials for São Paulo backup-domain DNS",
                "Roll São Paulo GCP MIG",
            ),
        )
        previous_roll = -1
        for refresh_name, roll_name in pairs:
            refresh = workflow.index(f"      - name: {refresh_name}")
            roll = workflow.index(f"      - name: {roll_name}")
            self.assertLess(previous_roll, refresh)
            self.assertLess(refresh, roll)
            segment = workflow[refresh:roll]
            self.assertIn("uses: aws-actions/configure-aws-credentials@v4", segment)
            self.assertIn("role-to-assume: ${{ secrets.AWS_DEPLOY_ROLE_ARN }}", segment)
            previous_roll = roll

        self.assertIn('"tools/roll-secondary-region.sh"', workflow)

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

    def test_secondary_stability_wait_budget_covers_two_readiness_holds(self) -> None:
        secondary = (ROOT / "tools" / "roll-secondary-region.sh").read_text(
            encoding="utf-8"
        )

        budget = re.search(r"local wait_rounds=(\d+)", secondary)
        self.assertIsNotNone(budget)
        assert budget is not None
        self.assertGreaterEqual(int(budget.group(1)), 120)
        self.assertIn('seq 1 "${wait_rounds}"', secondary)
        self.assertIn("(${i}/${wait_rounds})", secondary)

    def test_primary_and_secondary_failures_restore_verified_previous_template(self) -> None:
        workflow = (
            ROOT / ".github" / "workflows" / "deploy-enclave-gcp.yml"
        ).read_text(encoding="utf-8")
        secondary = (ROOT / "tools" / "roll-secondary-region.sh").read_text(
            encoding="utf-8"
        )
        recovery = (ROOT / "tools" / "recover-gcp-region.sh").read_text(
            encoding="utf-8"
        )

        self.assertIn(
            "Recover us-central1 after any failed rollout step", workflow
        )
        self.assertIn("always() && (failure() || steps.canary_us.outcome == 'failure')", workflow)
        self.assertIn("bash tools/recover-gcp-region.sh", workflow)
        self.assertIn("bash tools/recover-gcp-region.sh", secondary)
        self.assertIn("prior_drain_state", secondary)
        self.assertIn('"${previous_template}" "${prior_drain_state}"', secondary)
        self.assertIn("pre-rollout canonical drain state", secondary)
        self.assertIn("trap 'exit 130' INT", secondary)
        self.assertIn("trap 'exit 143' TERM", secondary)
        self.assertIn("trap 'exit 130' INT", recovery)
        self.assertIn("trap 'exit 143' TERM", recovery)
        self.assertIn('update_drain set', recovery)
        self.assertIn('set-instance-template "${mig}"', recovery)
        self.assertIn("resolve_template_digest", recovery)
        self.assertIn("wait-canonical-drained.sh", recovery)
        self.assertIn("verify-region-before-dns.sh", recovery)
        self.assertIn('update_drain clear', recovery)
        self.assertIn('final_drain_state="${6-active}"', recovery)
        self.assertIn('update_drain set', recovery)
        self.assertLess(
            recovery.index('update_drain set'),
            recovery.index('set-instance-template "${mig}"'),
        )
        self.assertLess(
            recovery.index("verify-region-before-dns.sh"),
            recovery.rindex('update_drain clear'),
        )

        self.assertIn("us_central1_drain_state", workflow)
        self.assertIn("Restore us-central1 canonical drain state", workflow)

    def test_deploy_preflights_runtime_access_to_every_referenced_secret(self) -> None:
        deploy = (ROOT / "tools" / "deploy-gcp-mig.sh").read_text(encoding="utf-8")

        preflight = deploy.index("verify-gcp-runtime-secret-access.py")
        template = deploy.index("gc compute instance-templates create")
        self.assertLess(preflight, template)
        self.assertIn("compgen -A variable", deploy)
        self.assertIn("QUILL_*_SECRET|ACME_FALLBACK_EAB_SECRET", deploy)
        self.assertIn('--service-account "${WORKLOAD_SA}"', deploy)

    def test_recovery_and_secret_preflight_changes_trigger_deployment(self) -> None:
        workflow = (
            ROOT / ".github" / "workflows" / "deploy-enclave-gcp.yml"
        ).read_text(encoding="utf-8")

        self.assertIn('- "tools/recover-gcp-region.sh"', workflow)
        self.assertIn('- "tools/verify-gcp-runtime-secret-access.py"', workflow)

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
