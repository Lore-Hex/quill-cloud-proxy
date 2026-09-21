#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]


class RolloutSafetyTests(unittest.TestCase):
    def test_canary_keys_are_fresh_per_invocation_and_stable_within_retries(self) -> None:
        source = (ROOT / "tools/verify-region-before-dns.sh").read_text()
        namespace = next(
            line for line in source.splitlines() if line.startswith("CANARY_RUN_ID=")
        )
        assignments = re.findall(r'^  idempotency_key=".+"$', source, re.MULTILINE)
        self.assertEqual(len(assignments), 2)
        script = "\n".join([
            "set -euo pipefail", "REGION=us-east4", "stage=regional", "ip=192.0.2.1",
            namespace,
            *[
                line + '\nprintf "%s\\n%s\\n" "$idempotency_key" "$idempotency_key"'
                for line in assignments
            ],
        ])
        env = {**os.environ, "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "2"}

        def keys() -> list[str]:
            return subprocess.run(
                ["bash", "-c", script], env=env, check=True,
                capture_output=True, text=True,
            ).stdout.splitlines()

        first, second = keys(), keys()
        self.assertEqual(first[0], first[1])
        self.assertEqual(first[2], first[3])
        self.assertNotEqual(first[0], first[2])
        self.assertTrue(set(first).isdisjoint(second))
        self.assertTrue(all(len(key) < 200 for key in first))

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
        self.assertIn("rollout_restore_drain_operation", workflow)
        self.assertIn("--drain-origin rollout", workflow)
        self.assertIn('--github-run-id "${GITHUB_RUN_ID}"', workflow)
        capture_start = workflow.index("      - name: Capture pre-rollout templates")
        capture_end = workflow.index(
            "\n\n      # Staged regional rollout", capture_start
        )
        capture = workflow[capture_start:capture_end]
        self.assertIn("QUILL_API_HOST=api.trustedrouter.com", capture)
        self.assertIn("QUILL_DNS_ZONE=trustedrouter-com", capture)
        self.assertIn("--list-drain-regions", capture)
        self.assertIn("drain_origins", capture)
        self.assertIn('update_drain set "${region}"', secondary)
        self.assertIn('update_drain clear "${region}"', secondary)
        self.assertIn('prior_drain_state="$9"', secondary)
        self.assertIn('prior_drain_origin="${10}"', secondary)
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
            "PREV_DRAIN_STATE: ${{ steps.prev.outputs.us_west1_drain_state }}",
            workflow,
        )
        for region_key in (
            "us_central1",
            "europe_west4",
            "us_east4",
            "us_west1",
        ):
            self.assertIn(f"steps.prev.outputs.{region_key}_drain_origin", workflow)
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
                "none",
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

    def test_gcp_deploy_envs_are_allowed_by_measured_image(self) -> None:
        deploy = (ROOT / "tools" / "deploy-gcp-mig.sh").read_text(encoding="utf-8")
        dockerfile = (
            ROOT / "enclave-go" / "Dockerfile.enclave.gcp.multi"
        ).read_text(encoding="utf-8")

        label_match = re.search(
            r'LABEL "tee\.launch_policy\.allow_env_override"="([^"]+)"',
            dockerfile,
        )
        self.assertIsNotNone(label_match, "GCP image env allowlist label is missing")
        allowed = set(label_match.group(1).split(","))

        explicit_envs = set(re.findall(r"tee-env-([A-Z][A-Z0-9_]+)=", deploy))
        optional_envs = set(
            re.findall(
                r"^configure_optional_provider_secret\s+([A-Z][A-Z0-9_]+)\s+",
                deploy,
                re.MULTILINE,
            )
        )
        deployed = explicit_envs | optional_envs
        self.assertTrue(deployed, "GCP deploy env discovery is vacuous")
        self.assertEqual(
            deployed - allowed,
            set(),
            "deploy metadata contains env overrides rejected by Confidential Space",
        )

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

    def test_gcp_rollout_inventory_matches_deployed_regions(self) -> None:
        deploy = (ROOT / "tools" / "deploy-gcp-mig.sh").read_text(encoding="utf-8")
        inventory_path = ROOT / "tools" / "gcp-enclave-migs.txt"
        inventory = inventory_path.read_text(encoding="utf-8").splitlines()
        workflow = (
            ROOT / ".github" / "workflows" / "deploy-enclave-gcp.yml"
        ).read_text(encoding="utf-8")

        # Retain the SEV guard for an intentional future AMD region, but do not
        # let a retired MIG block trust publication or reappear in a rollout.
        self.assertIn('if [ "${REGION}" = "southamerica-east1" ]', deploy)
        self.assertIn('CONF_COMPUTE_TYPE}" != "SEV"', deploy)
        self.assertIn('"${MACHINE_TYPE}" != n2d-*', deploy)
        self.assertIn("CONF_COMPUTE_TYPE=SEV_SNP is not supported", deploy)
        self.assertEqual(
            inventory,
            [
                "us-central1:quill-enclave-mig-us",
                "europe-west4:quill-enclave-mig-eu",
                "us-east4:quill-enclave-mig-useast4",
            ],
        )
        # A region being bootstrapped. Promotion moves this line into the list
        # above (docs/runbooks/README.md, "Adding a gateway region").
        self.assertEqual(
            (ROOT / "tools" / "gcp-enclave-migs-pending.txt")
            .read_text(encoding="utf-8")
            .splitlines(),
            ["us-west1:quill-enclave-mig-uswest1"],
        )
        self.assertNotIn("southamerica-east1", inventory_path.read_text())
        self.assertNotIn('GCP_ENCLAVE_MIGS: "', workflow)
        # Both rollout loops read the pending-aware tool's output. Reading the
        # main inventory directly would skip a first-time region's MIG.
        self.assertNotIn("< tools/gcp-enclave-migs.txt", workflow)
        self.assertEqual(
            workflow.count("while IFS=: read -r region mig inventory_state; do"), 2
        )
        self.assertEqual(
            workflow.count("python3 tools/gcp_enclave_inventory.py list-existing"), 1
        )
        self.assertEqual(
            workflow.count("python3 tools/gcp_enclave_inventory.py list-all"), 1
        )
        self.assertNotIn("quill-enclave-mig-sa", workflow)
        self.assertNotIn("api-southamerica-east1.quillrouter.com", workflow)
        self.assertNotIn("Roll São Paulo GCP MIG", workflow)

        inventory_check = workflow.index(
            "      - name: Verify GCP enclave MIG inventory"
        )
        image_build = workflow.index("      - name: Build enclave image via Cloud Build")
        self.assertLess(inventory_check, image_build)
        inventory_step = workflow[inventory_check:image_build]
        self.assertIn("gcloud compute instance-groups managed list", inventory_step)
        self.assertIn("--filter='name~^quill-enclave-mig-'", inventory_step)
        self.assertIn(
            'python3 tools/gcp_enclave_inventory.py check --actual-file "${actual_migs}"',
            inventory_step,
        )

    def _inventoried_migs(self) -> list[tuple[str, str]]:
        # Main and pending: both are rolled, so both need every per-region list.
        migs = []
        for name in ("gcp-enclave-migs.txt", "gcp-enclave-migs-pending.txt"):
            for line in (ROOT / "tools" / name).read_text().splitlines():
                region, _, mig = line.partition(":")
                migs.append((region, mig))
        self.assertGreaterEqual(len(migs), 4)
        return migs

    def _workflow_shell(self, step: str, first_line: str, stop_before: str) -> str:
        """Return lines of one step's `run: |` block, as the runner would see them."""
        workflow = (
            ROOT / ".github" / "workflows" / "deploy-enclave-gcp.yml"
        ).read_text(encoding="utf-8")
        start = workflow.index(first_line, workflow.index(f"      - name: {step}\n"))
        body = workflow[start : workflow.index(stop_before, start + 1)].splitlines()
        self.assertTrue(all(not line or line.startswith(" " * 10) for line in body))
        script = "\n".join(line[10:] for line in body) + "\n"
        self.assertNotIn("${{", script, "the shell must not need Actions interpolation")
        return script

    def _run_workflow_shell(
        self,
        script: str,
        production: list[dict[str, str]] | None,
        *,
        project: str,
        main: str,
        pending: str,
    ) -> tuple[subprocess.CompletedProcess[str], str, str]:
        """Run real workflow shell against a fake gcloud.

        Everything else is real: bash, jq, sort and the inventory tool, reading
        fixture inventories from an isolated checkout-shaped directory.
        """
        self.assertIsNotNone(
            shutil.which("jq"), "jq is required: the shell under test runs gcloud's JSON through it"
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            (temp / "tools").mkdir()
            shutil.copy(ROOT / "tools" / "gcp_enclave_inventory.py", temp / "tools")
            (temp / "tools" / "gcp-enclave-migs.txt").write_text(main)
            (temp / "tools" / "gcp-enclave-migs-pending.txt").write_text(pending)
            (temp / "step.sh").write_text(script)
            (temp / "bin").mkdir()
            gcloud = temp / "bin" / "gcloud"
            gcloud.write_text('''#!/bin/bash
set -eu
if [ "$*" != "compute instance-groups managed list --project=${EXPECTED_PROJECT} --filter=name~^quill-enclave-mig- --format=json" ]; then
  echo "unexpected gcloud call: $*" >&2
  exit 1
fi
if [ "${GCLOUD_FAILS}" = 1 ]; then
  echo "ERROR: (gcloud.compute.instance-groups.managed.list) simulated failure" >&2
  exit 1
fi
printf '%s\\n' "${GCLOUD_JSON}"
''')
            gcloud.chmod(0o755)
            env = {
                **os.environ,
                "PATH": f"{temp / 'bin'}:{os.environ['PATH']}",
                "PROJECT_ID": "fixture-project",
                "EXPECTED_PROJECT": project,
                "RUNNER_TEMP": str(temp),
                "GITHUB_ENV": str(temp / "github-env"),
                "GCLOUD_FAILS": "1" if production is None else "0",
                "GCLOUD_JSON": json.dumps(production or []),
            }
            # GitHub runs an unspecified-shell step as `bash -e {0}`.
            completed = subprocess.run(
                ["bash", "-e", str(temp / "step.sh")],
                cwd=temp, env=env, capture_output=True, text=True, timeout=30,
            )
            github_env = temp / "github-env"
            listing = temp / "gcp-enclave-migs-actual.txt"
            return (
                completed,
                github_env.read_text() if github_env.exists() else "",
                listing.read_text() if listing.exists() else "",
            )

    @staticmethod
    def _listed_mig(region: str, name: str) -> dict[str, str]:
        return {
            "name": name,
            "region": f"https://www.googleapis.com/compute/v1/projects/p/regions/{region}",
        }

    def _run_inventory_step(
        self, production: list[dict[str, str]] | None, *, main: str, pending: str
    ) -> tuple[subprocess.CompletedProcess[str], str, str]:
        # The whole step: from the first line of its `run: |` to the next step.
        script = self._workflow_shell(
            "Verify GCP enclave MIG inventory", "          set -euo pipefail\n", "\n      - "
        )
        self.assertIn("gcp_enclave_inventory.py check", script)
        return self._run_workflow_shell(
            script, production, project="fixture-project", main=main, pending=pending
        )

    def test_inventory_step_tolerates_only_an_absent_pending_mig(self) -> None:
        mig = self._listed_mig
        serving = [
            mig("us-east4", "quill-enclave-mig-useast4"),
            mig("us-central1", "quill-enclave-mig-us"),
            mig("europe-west4", "quill-enclave-mig-eu"),
        ]
        west = mig("us-west1", "quill-enclave-mig-uswest1")
        main = (
            "us-central1:quill-enclave-mig-us\n"
            "europe-west4:quill-enclave-mig-eu\n"
            "us-east4:quill-enclave-mig-useast4\n"
        )
        pending = "us-west1:quill-enclave-mig-uswest1\n"

        completed, github_env, listing = self._run_inventory_step(
            serving, main=main, pending=pending
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn(
            "pending and not created yet us-west1:quill-enclave-mig-uswest1",
            completed.stdout,
        )
        self.assertEqual(
            listing,
            "europe-west4:quill-enclave-mig-eu\n"
            "us-central1:quill-enclave-mig-us\n"
            "us-east4:quill-enclave-mig-useast4\n",
        )
        # The Stage D step reads this listing through the exported path.
        self.assertRegex(
            github_env, r"^GCP_ENCLAVE_MIGS_ACTUAL=.+/gcp-enclave-migs-actual\.txt\n$"
        )

        completed, _, _ = self._run_inventory_step(
            [*serving, west], main=main, pending=pending
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn(
            "pending and present us-west1:quill-enclave-mig-uswest1", completed.stdout
        )

        refusals = (
            # Positive control: the same production is refused when the absent
            # MIG is listed as serving, so it is the pending file that forgives.
            (serving, main + pending, "",
             "main inventory MIG us-west1:quill-enclave-mig-uswest1 does not exist"),
            ([*serving, mig("southamerica-east1", "quill-enclave-mig-sa")], main, pending,
             "production MIG southamerica-east1:quill-enclave-mig-sa is in neither inventory"),
            (serving[:2], main, pending,
             "main inventory MIG europe-west4:quill-enclave-mig-eu does not exist"),
            ([], main, pending,
             "main inventory MIG us-central1:quill-enclave-mig-us does not exist"),
        )
        for production, main_text, pending_text, message in refusals:
            with self.subTest(message=message):
                completed, github_env, _ = self._run_inventory_step(
                    production, main=main_text, pending=pending_text
                )
                self.assertEqual(completed.returncode, 1, completed.stdout)
                self.assertIn(message, completed.stderr)
                self.assertEqual(github_env, "")

        # A zonal group under the enclave prefix has no region: jq fails on it
        # and pipefail carries that to the step. A failed listing does the same.
        zonal = {"name": "quill-enclave-mig-zonal", "zone": "projects/p/zones/us-central1-a"}
        for production in ([*serving, zonal], None):
            with self.subTest(production=production):
                completed, github_env, _ = self._run_inventory_step(
                    production, main=main, pending=pending
                )
                self.assertNotEqual(completed.returncode, 0)
                self.assertNotIn("matches production", completed.stdout)
                self.assertEqual(github_env, "")

    def test_capture_step_lists_production_again_before_it_rolls(self) -> None:
        # The capture loop itself needs bash 4 (an associative array of drain
        # origins). Its listing does not, so run that for real and show what the
        # loop would iterate; the loop's pending branch is pinned in the next test.
        listing = self._workflow_shell(
            "Capture pre-rollout templates (for rollback)",
            "          # List production again",
            "          while IFS=: read -r region mig inventory_state; do\n",
        )
        script = (
            listing
            + "while IFS=: read -r region mig inventory_state; do\n"
            + '  echo "${region} ${mig} ${inventory_state}"\n'
            + 'done < "${mig_dir}/rollout.txt"\n'
        )
        mig = self._listed_mig
        serving = [
            mig("us-central1", "quill-enclave-mig-us"),
            mig("europe-west4", "quill-enclave-mig-eu"),
            mig("us-east4", "quill-enclave-mig-useast4"),
        ]
        main = (
            "us-central1:quill-enclave-mig-us\n"
            "europe-west4:quill-enclave-mig-eu\n"
            "us-east4:quill-enclave-mig-useast4\n"
        )
        pending = "us-west1:quill-enclave-mig-uswest1\n"

        def run(production: list[dict[str, str]] | None) -> subprocess.CompletedProcess[str]:
            return self._run_workflow_shell(
                script, production, project="quill-cloud-proxy", main=main, pending=pending
            )[0]

        first_deploy = run(serving)
        self.assertEqual(first_deploy.returncode, 0, first_deploy.stderr)
        self.assertEqual(
            first_deploy.stdout.splitlines(),
            [
                "us-central1 quill-enclave-mig-us main",
                "europe-west4 quill-enclave-mig-eu main",
                "us-east4 quill-enclave-mig-useast4 main",
                # Still iterated, so its (empty) template and its drain state
                # reach the US West step.
                "us-west1 quill-enclave-mig-uswest1 absent",
            ],
        )
        later_deploy = run([*serving, mig("us-west1", "quill-enclave-mig-uswest1")])
        self.assertEqual(later_deploy.returncode, 0, later_deploy.stderr)
        self.assertEqual(
            later_deploy.stdout.splitlines()[-1], "us-west1 quill-enclave-mig-uswest1 pending"
        )

        for production in (
            [*serving, mig("asia-east1", "quill-enclave-mig-asia")],
            serving[:2],
            [],
            None,
        ):
            with self.subTest(production=production):
                refused = run(production)
                self.assertEqual(refused.returncode, 1, refused.stdout)
                self.assertEqual(refused.stdout, "")
                self.assertIn(
                    "production's enclave MIGs do not match the inventories; refusing to roll",
                    refused.stderr,
                )

    def test_rollout_loops_take_a_pending_region_from_the_inventory_tool(self) -> None:
        workflow = (
            ROOT / ".github" / "workflows" / "deploy-enclave-gcp.yml"
        ).read_text(encoding="utf-8")

        stage_d = workflow[
            workflow.index("      - id: stage-d-transition") : workflow.index(
                "      - id: write-trust"
            )
        ]
        self.assertIn(
            "python3 tools/gcp_enclave_inventory.py list-existing \\\n"
            '            --actual-file "${GCP_ENCLAVE_MIGS_ACTUAL}" > "${rollout_migs}"',
            stage_d,
        )
        self.assertIn('done < "${rollout_migs}"', stage_d)
        # A process substitution would hide a failure of the tool and hand the
        # loop an empty list, which publishes an empty transition set.
        self.assertNotIn("<(python3 tools/gcp_enclave_inventory.py", workflow)
        # A failed listing must not read as "nothing running": for a pending
        # region that answer is accepted, so a failed read of a pending region
        # that IS running would drop its digest from the transition set. The
        # listing therefore runs as a plain command whose status is checked,
        # never inside a process substitution.
        listing = stage_d.index(
            'if ! gcloud compute instance-groups managed list-instances "${mig}" \\\n'
        )
        listing_refusal = stage_d.index("could not list ${mig}'s instances; refusing")
        self.assertNotIn(
            "< <(\n              gcloud compute instance-groups managed list-instances",
            stage_d,
        )
        self.assertIn('> "${running_listing}"; then', stage_d[listing:listing_refusal])
        self.assertIn("exit 1", stage_d[listing_refusal : listing_refusal + 200])

        no_templates = stage_d.index('if [ "${#running_templates[@]}" -eq 0 ]; then')
        pending_branch = stage_d.index('if [ "${inventory_state}" = "pending" ]; then')
        refusal = stage_d.index("no running MIG template found; refusing")
        self.assertLess(listing_refusal, no_templates)
        self.assertLess(no_templates, pending_branch)
        self.assertLess(pending_branch, refusal)
        self.assertIn("continue", stage_d[pending_branch:refusal])

        capture_start = workflow.index("      - name: Capture pre-rollout templates")
        capture = workflow[
            capture_start : workflow.index("\n\n      # Staged regional rollout", capture_start)
        ]
        self.assertIn("gcloud compute instance-groups managed list", capture)
        self.assertIn("--filter='name~^quill-enclave-mig-'", capture)
        self.assertIn("python3 tools/gcp_enclave_inventory.py list-all", capture)
        self.assertIn("do not match the inventories; refusing to roll", capture)
        self.assertIn('done < "${mig_dir}/rollout.txt"', capture)
        # No describe for a MIG that is not there: its empty previous template
        # is the first-deployment signal, and its drain state is still emitted.
        absent = capture.index('if [ "${inventory_state}" != "absent" ]; then')
        describe = capture.index("gcloud compute instance-groups managed describe")
        drain_state = capture.index('echo "${region//-/_}_drain_state=')
        self.assertLess(capture.index('tmpl=""'), absent)
        self.assertLess(absent, describe)
        self.assertLess(describe, drain_state)

    def test_pending_inventory_reaches_the_rollout_and_the_regional_reconciler(self) -> None:
        workflow = (ROOT / ".github/workflows/deploy-enclave-gcp.yml").read_text()
        push_paths = workflow.split("  push:\n", 1)[1].split("\njobs:", 1)[0]
        self.assertIn('      - "tools/gcp-enclave-migs-pending.txt"', push_paths)
        self.assertIn('      - "tools/gcp_enclave_inventory.py"', push_paths)
        self.assertIn(
            "python3 tools/test_gcp_enclave_inventory.py",
            (ROOT / ".github/workflows/ci.yml").read_text(),
        )

        # The reconciler knows a pending region from its first rollout: it holds
        # and promotes the cold CNAME and then keeps api-<region> on the attested
        # VMs. What that may and may not publish is tested in
        # test_reconcile_enclave_dns.py; here, that the file reaches both places
        # the reconciler runs. The scheduled one reads it from its image, so a
        # change to the file has to rebuild that image.
        reconciler = (ROOT / "tools/reconcile-enclave-dns.py").read_text()
        self.assertIn('"gcp-enclave-migs-pending.txt"', reconciler)
        # One filter decides the canonical answer, and it cannot be built
        # without the pending regions.
        self.assertEqual(reconciler.count("EXCLUDE_CANONICAL_REGIONS |"), 1)
        self.assertIn(
            "    return EXCLUDE_CANONICAL_REGIONS | GCP_ENCLAVE_PENDING_REGIONS\n", reconciler
        )
        self.assertIn(
            "    canonical_excludes = canonical_excluded_regions() | persistent_excludes\n",
            reconciler,
        )
        copied = [
            line.split()
            for line in (ROOT / "tools/Dockerfile.reconciler").read_text().splitlines()
            if line.startswith("COPY ") and "reconcile-enclave-dns.py" in line
        ]
        self.assertEqual(len(copied), 1)
        # Same directory as the script: it resolves both files next to itself.
        self.assertEqual(copied[0][-1], "/app/tools/")
        self.assertIn("gcp-enclave-migs.txt", copied[0])
        self.assertIn("gcp-enclave-migs-pending.txt", copied[0])
        reconciler_deploy = (
            ROOT / ".github/workflows/deploy-enclave-dns-reconciler.yml"
        ).read_text()
        reconciler_paths = reconciler_deploy.split("  push:\n", 1)[1].split(
            "\n  workflow_dispatch:", 1
        )[0]
        for inventory in ("gcp-enclave-migs.txt", "gcp-enclave-migs-pending.txt"):
            self.assertIn(f'      - "tools/{inventory}"', reconciler_paths)

        # The certificate-expiry check stays on the serving regions: a pending
        # region may legitimately have no VM, and so no certificate, yet.
        tls_check = (ROOT / "tools/check-public-tls.py").read_text()
        self.assertIn('with_name("gcp-enclave-migs.txt")', tls_check)
        self.assertNotIn("pending", tls_check)

    def test_every_inventoried_region_is_known_to_the_per_region_lists(self) -> None:
        cleanup = (ROOT / "tools/cleanup-enclave-rollout-drains.sh").read_text()
        start = cleanup.index("region_mig() {\n")
        function = cleanup[start : cleanup.index("\n}\n", start) + 3]
        stockout = (ROOT / ".github/workflows/relieve-mig-stockout.yml").read_text()
        region_input = stockout[stockout.index("      region:\n") : stockout.index("      zone:\n")]
        options = re.search(r"^        options: \[(.+)\]$", region_input, re.MULTILINE)
        self.assertIsNotNone(options)
        assert options is not None

        migs = self._inventoried_migs()
        self.assertEqual(
            sorted(options.group(1).split(", ")), sorted(region for region, _ in migs)
        )
        self.assertIn(
            'mig="$(python3 tools/gcp_enclave_inventory.py mig-for-region "${REGION}")"',
            stockout,
        )
        for region, mig in migs:
            with self.subTest(region=region):
                completed = subprocess.run(
                    ["bash", "-c", f'{function}\nregion_mig "{region}"'],
                    capture_output=True, text=True, timeout=5,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertEqual(completed.stdout, f"{mig}\t{mig}-\n")

    def test_us_west_rollout_mirrors_us_east_and_names_its_zones(self) -> None:
        workflow = (
            ROOT / ".github" / "workflows" / "deploy-enclave-gcp.yml"
        ).read_text(encoding="utf-8")

        def step(name: str) -> str:
            start = workflow.index(f"      - name: {name}\n")
            return workflow[start : workflow.index("\n\n", start)]

        zones = "          MIG_ZONES: us-west1-a,us-west1-b"
        west = step("Roll US West GCP MIG").splitlines()
        self.assertEqual(west.count(zones), 1)
        self.assertLess(west.index("        env:"), west.index(zones))
        self.assertLess(west.index(zones), west.index("        run: |"))
        # Apart from its zones (and the comments explaining them), the step is
        # the US East step with the region renamed.
        renamed = (
            step("Roll US East GCP MIG")
            .replace("US East", "US West")
            .replace("us-east4", "us-west1")
            .replace("us_east4", "us_west1")
            .replace("useast4", "uswest1")
        )
        self.assertEqual(
            [line for line in west if line != zones and not line.lstrip().startswith("#")],
            renamed.splitlines(),
        )
        for expected in (
            "timeout-minutes: 55",
            "            us-west1 \\",
            "            quill-enclave-mig-uswest1 \\",
            "            quill-enclave-mig-uswest1- \\",
            "            uswest1 \\",
            "            api.quillrouter.com,api-us-west1.quillrouter.com,api.trustedrouter.com,api.allyrouter.com,api.uptimerouter.com \\",
            "            c3-standard-4 \\",
            "            TDX \\",
        ):
            self.assertIn(expected, "\n".join(west))

    def _mig_zone_args(self, **env: str) -> subprocess.CompletedProcess[str]:
        deploy = (ROOT / "tools" / "deploy-gcp-mig.sh").read_text(encoding="utf-8")
        start = deploy.index("# Zones for a NEW regional MIG")
        block = deploy[start : deploy.index('\nIMAGE_REF="${IMAGE_REF:?', start)]
        default_surge = re.search(r'^MAX_SURGE="\$\{MAX_SURGE:-(\d+)\}"$', deploy, re.MULTILINE)
        self.assertIsNotNone(default_surge)
        assert default_surge is not None
        return subprocess.run(
            ["bash", "-euo", "pipefail", "-c",
             block + '\nprintf "%s\\n" "${#MIG_ZONE_ARGS[@]}" ${MIG_ZONE_ARGS[@]+"${MIG_ZONE_ARGS[@]}"}'],
            env={
                "PATH": os.environ["PATH"],
                "TMPDIR": tempfile.gettempdir(),
                "REGION": "us-west1",
                "MAX_SURGE": default_surge.group(1),
                **env,
            },
            capture_output=True, text=True, timeout=5,
        )

    def test_mig_zones_are_validated_before_anything_is_created(self) -> None:
        deploy = (ROOT / "tools" / "deploy-gcp-mig.sh").read_text(encoding="utf-8")
        self.assertLess(
            deploy.index("# Zones for a NEW regional MIG"),
            deploy.index("gc compute instance-templates create"),
        )

        unset = self._mig_zone_args()
        self.assertEqual((unset.returncode, unset.stdout), (0, "0\n"), unset.stderr)
        for value, expected in (
            ("us-west1-a,us-west1-b", "--zones=us-west1-a,us-west1-b"),
            ("us-west1-b", "--zones=us-west1-b"),
            ("us-west1-a,", "--zones=us-west1-a"),
        ):
            with self.subTest(value=value):
                completed = self._mig_zone_args(MIG_ZONES=value)
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertEqual(completed.stdout, f"1\n{expected}\n")

        for value, message in (
            # The zone that cannot host TDX belongs to another region's MIG.
            ("us-central1-f", "MIG_ZONES entry 'us-central1-f' is not a zone of us-west1"),
            ("us-west1-a,,us-west1-b", "MIG_ZONES entry '' is not a zone of us-west1"),
            ("us-west1-a, us-west1-b", "MIG_ZONES entry ' us-west1-b' is not a zone of us-west1"),
            ("us-west1", "MIG_ZONES entry 'us-west1' is not a zone of us-west1"),
            ("us-west1-a;rm", "is not a zone of us-west1"),
        ):
            with self.subTest(value=value):
                completed = self._mig_zone_args(MIG_ZONES=value)
                self.assertEqual(completed.returncode, 1, completed.stdout)
                self.assertEqual(completed.stdout, "")
                self.assertIn(message, completed.stderr)

        too_small = self._mig_zone_args(MIG_ZONES="us-west1-a,us-west1-b", MAX_SURGE="1")
        self.assertEqual(too_small.returncode, 1, too_small.stdout)
        self.assertIn("MAX_SURGE=1 is below the 2 zones in MIG_ZONES", too_small.stderr)
        no_surge = self._mig_zone_args(MIG_ZONES="us-west1-a,us-west1-b", MAX_SURGE="0")
        self.assertEqual(no_surge.returncode, 0, no_surge.stderr)

        # The zones the workflow names for us-west1 pass with the default surge.
        workflow = (ROOT / ".github/workflows/deploy-enclave-gcp.yml").read_text()
        named = re.findall(r"^          MIG_ZONES: (\S+)$", workflow, re.MULTILINE)
        self.assertEqual(named, ["us-west1-a,us-west1-b"])
        completed = self._mig_zone_args(MIG_ZONES=named[0])
        self.assertEqual(completed.stdout, f"1\n--zones={named[0]}\n", completed.stderr)

    def test_only_a_new_mig_gets_zones_and_the_capacity_tolerant_shape(self) -> None:
        deploy = (ROOT / "tools" / "deploy-gcp-mig.sh").read_text(encoding="utf-8")
        branch = deploy.index('if gc compute instance-groups managed describe "$MIG_NAME"')
        otherwise = deploy.index("\nelse\n", branch)
        update = deploy[branch:otherwise]
        create = deploy[otherwise : deploy.index("\nfi\n", otherwise)]
        self.assertIn("gc beta compute instance-groups managed update", update)
        self.assertIn("gc beta compute instance-groups managed create", create)

        for flag in (
            '    "${MIG_ZONE_ARGS[@]}" \\\n',
            "    --target-distribution-shape=balanced \\\n",
            "    --instance-redistribution-type=none \\\n",
        ):
            with self.subTest(flag=flag):
                self.assertIn(flag, create)
                # An existing MIG keeps its zones and shape: changing them is an
                # operator decision (tools/relieve-mig-stockout.py), not a deploy's.
                self.assertNotIn(flag.strip(" \\\n"), update)

    def _roll_us_west1(
        self, previous_template: str
    ) -> tuple[subprocess.CompletedProcess[str], str]:
        """Run the real secondary rollout for us-west1 with every child stubbed."""
        self.assertIsNotNone(shutil.which("jq"), "jq is required by the script under test")
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            bin_dir = temp / "bin"
            bin_dir.mkdir()
            command_log = temp / "commands.log"
            stubs = {
                # Children of the real script. What deploy-gcp-mig.sh would see
                # in its environment is the point of this test.
                "bash": '#!/bin/bash\necho "bash $* MIG_ZONES=${MIG_ZONES:-<unset>}" >> "${COMMAND_LOG}"\n',
                "uv": '#!/bin/bash\necho "uv $*" >> "${COMMAND_LOG}"\n',
                "python3": '#!/bin/bash\necho "python3 $*" >> "${COMMAND_LOG}"\n',
                "gcloud": '#!/bin/bash\necho "gcloud $*" >> "${COMMAND_LOG}"\n',
                # No synthetic target for the new region yet.
                "curl": "#!/bin/bash\necho '{\"regions\": [{\"target_region\": \"us-east4\"}]}'\n",
                "flock": "#!/bin/bash\nexit 0\n",
            }
            for name, body in stubs.items():
                path = bin_dir / name
                path.write_text(body, encoding="utf-8")
                path.chmod(0o755)

            completed = subprocess.run(
                [
                    "/bin/bash", str(ROOT / "tools" / "roll-secondary-region.sh"),
                    "us-west1", "quill-enclave-mig-uswest1", "quill-enclave-mig-uswest1-",
                    "uswest1", "api.quillrouter.com,api-us-west1.quillrouter.com",
                    previous_template, "c3-standard-4", "TDX", "active", "none",
                ],
                cwd=ROOT,
                env={
                    "PATH": f"{bin_dir}:/usr/bin:/bin",
                    "TMPDIR": tempfile.gettempdir(),
                    "COMMAND_LOG": str(command_log),
                    "GITHUB_RUN_ID": "33807667585",
                    "IMAGE_REF": "registry.example/enclave:new",
                    "IMAGE_DIGEST": "sha256:" + "a" * 64,
                    "MIG_ZONES": "us-west1-a,us-west1-b",
                },
                capture_output=True, text=True, timeout=30,
            )
            commands = command_log.read_text(encoding="utf-8") if command_log.exists() else ""
        return completed, commands

    def test_first_time_region_inherits_mig_zones_and_takes_the_bootstrap_path(self) -> None:
        # What the capture step hands over while the pending MIG does not exist.
        completed, commands = self._roll_us_west1(previous_template="")

        self.assertEqual(completed.returncode, 0, completed.stderr + commands)
        self.assertIn(
            "bash tools/deploy-gcp-mig.sh us-west1 MIG_ZONES=us-west1-a,us-west1-b\n",
            commands,
        )
        self.assertIn(
            "us-west1: first deployment has no synthetic target yet", completed.stdout
        )
        self.assertIn("us-west1 rollout healthy", completed.stdout)
        # An empty previous template must never reach recovery or a rollback.
        self.assertNotIn("recover-gcp-region.sh", commands)
        self.assertLess(
            commands.index("verify-region-before-dns.sh us-west1 quill-enclave-mig-uswest1-"),
            commands.index("--clear-drain-region us-west1"),
        )

    def test_pending_region_with_a_previous_template_still_needs_a_synthetic_target(self) -> None:
        # Once the pending MIG exists, the capture step reports its template and
        # the bootstrap exemption is gone: with no synthetic target the rollout
        # fails closed and recovers. docs/runbooks/README.md ("Adding a gateway
        # region") tells the operator what to do before retrying.
        completed, commands = self._roll_us_west1(previous_template="quill-enclave-tpl-uswest1-001")

        self.assertEqual(completed.returncode, 1, completed.stdout)
        self.assertIn(
            "us-west1: existing region is missing from synthetic status; failing closed",
            completed.stderr,
        )
        self.assertNotIn("first deployment has no synthetic target yet", completed.stdout)
        self.assertNotIn("--clear-drain-region us-west1", commands)
        self.assertIn(
            "bash tools/recover-gcp-region.sh us-west1 quill-enclave-mig-uswest1 "
            "quill-enclave-mig-uswest1- api.quillrouter.com,api-us-west1.quillrouter.com "
            "quill-enclave-tpl-uswest1-001 active none",
            commands,
        )

    def test_stage_d_region_gate_contract(self) -> None:
        stage_d_tests = (ROOT / "tools/tests/test-stage-d-gates.sh").read_text()
        # Pin membership, association, uniqueness, completeness, and execution;
        # changing rollout policy must not quietly disable any of these checks.
        required_guards = (
            'inventory=tools/gcp-enclave-migs.txt',
            'pending_inventory=tools/gcp-enclave-migs-pending.txt',
            'heartbeat_regions=tools/stage-d-heartbeat-regions.txt',
            'terminate_regions=tools/stage-d-terminate-regions.txt',
            'stage_d_counts="$(python3 - "${workflow}" "${inventory}" "${pending_inventory}" "${heartbeat_regions}" "${terminate_regions}"',
            'for source in (inventory, pending_inventory)',
            'require(configured and len(configured) == len(configured_list), "invalid MIG inventory")',
            'raise SystemExit(f"Stage D region bijection: {message}")',
            '("QUILL_USAGE_HEARTBEAT", heartbeat_file),',
            '("QUILL_TERMINATE_AT_CAP", terminate_file),',
            'for flag, declared_file in flag_files:',
            'declared_by_flag[flag] = declared',
            'heartbeat = declared_by_flag["QUILL_USAGE_HEARTBEAT"]',
            'terminate = declared_by_flag["QUILL_TERMINATE_AT_CAP"]',
            'require(terminate <= heartbeat,',
            'for flag, declared in declared_by_flag.items():',
            'require(not declared_text or declared_text.endswith("\\n"),',
            'require(all(re.fullmatch(r"[a-z]+(?:-[a-z]+)+[0-9]+", r) for r in declared_list),',
            'require(declared <= configured,',
            'require(len(declared) == len(declared_list),',
            'require(step is not None,',
            'require(value is not None,',
            'require(parent == " " * (indent + 2) + "env:",',
            'require(name.startswith("Roll ") and "GCP MIG" in name and len(regions) == 1,',
            'require(region in configured,',
            'require(region not in observed,',
            'require(on_regions == declared,',
            'require(off_regions == configured - declared,',
            'print(flag, len(on_regions), len(off_regions), len(configured))',
            'while read -r flag on_count off_count configured_region_count; do',
            '[ "$((on_count + off_count))" -eq "${configured_region_count}" ]',
            'done <<<"${stage_d_counts}"',
        )
        missing_guards = [guard for guard in required_guards if guard not in stage_d_tests]
        self.assertEqual(missing_guards, [], "Stage D regional shell gate was weakened")

    def test_stage_d_contract_assertion_rejects_weakened_gate(self) -> None:
        # Exercise the contract test itself: deleting its assertion must be red,
        # even though a Python test with no assertions would otherwise pass.
        stage_d_tests = (ROOT / "tools/tests/test-stage-d-gates.sh").read_text()
        for guard in (
            'require(on_regions == declared,',
            'require(off_regions == configured - declared,',
            'require(declared <= configured,',
            'require(region not in observed,',
            'require(name.startswith("Roll ") and "GCP MIG" in name and len(regions) == 1,',
        ):
            with self.subTest(guard=guard):
                self.assertIn(guard, stage_d_tests)
                with mock.patch.object(Path, "read_text", return_value=stage_d_tests.replace(guard, "", 1)):
                    with self.assertRaises(AssertionError):
                        self.test_stage_d_region_gate_contract()

    def _stage_d_inputs(self) -> dict[str, str]:
        return {
            path: (ROOT / path).read_text()
            for path in (
                ".github/workflows/deploy-enclave-gcp.yml",
                "tools/gcp-enclave-migs.txt",
                "tools/gcp-enclave-migs-pending.txt",
                "tools/stage-d-heartbeat-regions.txt",
                "tools/stage-d-terminate-regions.txt",
            )
        }

    def _run_stage_d_region_gate(self, inputs: dict[str, str]) -> subprocess.CompletedProcess:
        # Execute the actual shell block (including Python invocation and exit
        # propagation) against isolated files. Never mutate the working tree.
        shell = (ROOT / "tools/tests/test-stage-d-gates.sh").read_text()
        start = shell.index("workflow=.github/workflows/deploy-enclave-gcp.yml\n")
        end = shell.index('\ngrep -Fq "/internal/gateway/', start)
        with tempfile.TemporaryDirectory() as temp_dir:
            for name, text in inputs.items():
                path = Path(temp_dir) / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text)
            return subprocess.run(
                ["bash", "-euo", "pipefail", "-c", shell[start:end] + '\nprintf "%s\\n" "${stage_d_counts}"'],
                cwd=temp_dir, capture_output=True, text=True, timeout=5,
            )

    def _assert_stage_d_mutation_red(self, inputs: dict[str, str], message: str) -> None:
        baseline = self._run_stage_d_region_gate(self._stage_d_inputs())
        self.assertEqual(baseline.returncode, 0, baseline.stderr)
        mutated = self._run_stage_d_region_gate(inputs)
        self.assertNotEqual(mutated.returncode, 0, "mutated Stage D gate unexpectedly green")
        self.assertIn(message, mutated.stderr)

    def _set_stage_d_flag(self, inputs: dict[str, str], step: str, flag: str, value: str) -> None:
        path = ".github/workflows/deploy-enclave-gcp.yml"
        workflow = inputs[path]
        start = workflow.index(f"      - name: {step}\n")
        end = workflow.index("\n      - name:", start + 1)
        block, count = re.subn(
            rf'({flag}: ")(on|off)(")', rf'\g<1>{value}\3', workflow[start:end]
        )
        self.assertEqual(count, 1)
        inputs[path] = workflow[:start] + block + workflow[end:]

    def test_m1_declared_terminate_must_be_on(self) -> None:
        inputs = self._stage_d_inputs()
        self._set_stage_d_flag(inputs, "Roll the GCP MIG (us-central1)", "QUILL_TERMINATE_AT_CAP", "off")
        self._assert_stage_d_mutation_red(inputs, "QUILL_TERMINATE_AT_CAP: declared regions not on: ['us-central1']")

    def test_m2_undeclared_terminate_must_be_off(self) -> None:
        inputs = self._stage_d_inputs()
        path = "tools/stage-d-terminate-regions.txt"
        inputs[path] = inputs[path].replace("europe-west4\n", "")
        self._assert_stage_d_mutation_red(inputs, "undeclared regions on: ['europe-west4']")

    def test_m3_terminate_is_associated_with_its_rollout_region(self) -> None:
        inputs = self._stage_d_inputs()
        # Swap on/off: global counts stay identical, but ownership is wrong.
        path = "tools/stage-d-terminate-regions.txt"
        inputs[path] = inputs[path].replace("us-east4\n", "")
        self._set_stage_d_flag(inputs, "Roll the GCP MIG (us-central1)", "QUILL_TERMINATE_AT_CAP", "off")
        self._assert_stage_d_mutation_red(
            inputs, "declared regions not on: ['us-central1']; undeclared regions on: ['us-east4']"
        )

    def test_m4_terminate_requires_declared_heartbeat(self) -> None:
        inputs = self._stage_d_inputs()
        path = "tools/stage-d-heartbeat-regions.txt"
        inputs[path] = inputs[path].replace("us-central1\n", "")
        self._assert_stage_d_mutation_red(inputs, "termination requires heartbeat in declared regions: ['us-central1']")
        # Also isolate the invariant: fixing heartbeat's own bijection must
        # still refuse termination without heartbeat in that region.
        self._set_stage_d_flag(inputs, "Roll the GCP MIG (us-central1)", "QUILL_USAGE_HEARTBEAT", "off")
        self._assert_stage_d_mutation_red(inputs, "termination requires heartbeat in declared regions: ['us-central1']")

    def test_m5_declared_regions_must_be_configured(self) -> None:
        for stage in ("heartbeat", "terminate"):
            with self.subTest(stage=stage):
                inputs = self._stage_d_inputs()
                inputs[f"tools/stage-d-{stage}-regions.txt"] += "asia-east1\n"
                self._assert_stage_d_mutation_red(inputs, "unconfigured regions: ['asia-east1']")

    def test_m6_heartbeat_bijection_is_still_enforced(self) -> None:
        inputs = self._stage_d_inputs()
        self._set_stage_d_flag(inputs, "Roll the GCP MIG (us-central1)", "QUILL_USAGE_HEARTBEAT", "off")
        self._assert_stage_d_mutation_red(inputs, "QUILL_USAGE_HEARTBEAT: declared regions not on: ['us-central1']")

    def test_m7_contract_rejects_neutered_cross_flag_invariant(self) -> None:
        self.test_stage_d_region_gate_contract()
        shell = (ROOT / "tools/tests/test-stage-d-gates.sh").read_text()
        guard = "require(terminate <= heartbeat,"
        self.assertEqual(shell.count(guard), 1)
        mutated = shell.replace(guard, "require(True,", 1)
        with mock.patch.object(Path, "read_text", return_value=mutated):
            with self.assertRaisesRegex(AssertionError, "Stage D regional shell gate was weakened"):
                self.test_stage_d_region_gate_contract()

    def test_stage_d_empty_declarations_allow_all_flags_off(self) -> None:
        inputs = self._stage_d_inputs()
        for stage in ("heartbeat", "terminate"):
            inputs[f"tools/stage-d-{stage}-regions.txt"] = ""
        path = ".github/workflows/deploy-enclave-gcp.yml"
        inputs[path] = re.sub(r'(QUILL_(?:USAGE_HEARTBEAT|TERMINATE_AT_CAP): )"on"', r'\1"off"', inputs[path])
        completed = self._run_stage_d_region_gate(inputs)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout.splitlines(), ["QUILL_USAGE_HEARTBEAT 0 4 4", "QUILL_TERMINATE_AT_CAP 0 4 4"])

    def test_m8_pending_region_is_configured_by_the_pending_inventory(self) -> None:
        # Moves us-east4, which stays in the main inventory, so this keeps
        # holding once us-west1 is promoted and the pending file is empty again.
        main = "tools/gcp-enclave-migs.txt"
        pending = "tools/gcp-enclave-migs-pending.txt"
        line = "us-east4:quill-enclave-mig-useast4\n"

        moved = self._stage_d_inputs()
        self.assertEqual(moved[main].count(line), 1)
        moved[main] = moved[main].replace(line, "")
        moved[pending] += line
        completed = self._run_stage_d_region_gate(moved)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout.splitlines(), ["QUILL_USAGE_HEARTBEAT 4 0 4", "QUILL_TERMINATE_AT_CAP 4 0 4"])

        # A pending region's flags answer to the same declarations.
        self._set_stage_d_flag(moved, "Roll US East GCP MIG", "QUILL_USAGE_HEARTBEAT", "off")
        self._assert_stage_d_mutation_red(moved, "QUILL_USAGE_HEARTBEAT: declared regions not on: ['us-east4']")

        # Positive control: in neither file, the same region is unconfigured.
        dropped = self._stage_d_inputs()
        dropped[main] = dropped[main].replace(line, "")
        self._assert_stage_d_mutation_red(dropped, "unconfigured regions: ['us-east4']")

        # One region cannot be both "must exist" and "may be absent".
        doubled = self._stage_d_inputs()
        doubled[pending] += line
        self._assert_stage_d_mutation_red(doubled, "invalid MIG inventory")

    def test_stage_d_declared_files_trigger_deploy(self) -> None:
        workflow = (ROOT / ".github/workflows/deploy-enclave-gcp.yml").read_text()
        push_paths = workflow.split("  push:\n", 1)[1].split("\njobs:", 1)[0]
        for stage in ("heartbeat", "terminate"):
            self.assertIn(f'      - "tools/stage-d-{stage}-regions.txt"', push_paths)

    def test_stage_d_flags_are_forwarded_to_instance_metadata(self) -> None:
        deploy = (ROOT / "tools/deploy-gcp-mig.sh").read_text()
        start = deploy.index("# Stage D flags are opt-in.")
        end = deploy.index("# This value is a Secret Manager NAME", start)
        metadata = next(line for line in deploy.splitlines() if line.startswith('  --metadata="'))
        for flag in ("USAGE_HEARTBEAT", "TERMINATE_AT_CAP"):
            self.assertIn(f"${{{flag}_TEE_ENV}}", metadata)
            for value in ("on", "off"):
                with self.subTest(flag=flag, value=value):
                    completed = subprocess.run(
                        ["bash", "-euo", "pipefail", "-c", deploy[start:end] + f'\nprintf "%s" "${{{flag}_TEE_ENV}}"'],
                        env={**os.environ, "SPEND_LEASE_LOCAL_ADMISSION_TEE_ENV": "", f"QUILL_{flag}": value},
                        capture_output=True, text=True, timeout=5,
                    )
                    self.assertEqual(completed.returncode, 0, completed.stderr)
                    self.assertEqual(completed.stdout, f"|tee-env-QUILL_{flag}=on" if value == "on" else "")

    def test_recovery_heartbeat_uses_selected_template_not_workflow_env(self) -> None:
        verifier = (ROOT / "tools/verify-region-before-dns.sh").read_text()
        recovery = (ROOT / "tools/recover-gcp-region.sh").read_text()
        secondary = (ROOT / "tools/roll-secondary-region.sh").read_text()
        self.assertLess(
            recovery.index('set-instance-template "${mig}"'),
            recovery.index('bash tools/verify-region-before-dns.sh'),
        )
        self.assertIn('--template="${previous_template}"', recovery)
        self.assertIn('"${previous_template}" "${prior_drain_state}"', secondary)
        self.assertIn('bash tools/recover-gcp-region.sh', secondary)

        # Execute the real verifier through template selection and probe-key
        # gating. Later network probes have their own recorded-response tests.
        boundary = "# This is an existing gateway-to-router credential"
        self.assertIn(boundary, verifier)
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            script = temp / "verify-region-before-dns.sh"
            script.write_text(verifier.split(boundary, 1)[0])
            (temp / "stage-d-gate-lib.sh").write_text(
                (ROOT / "tools/stage-d-gate-lib.sh").read_text()
            )
            gcloud = temp / "gcloud"
            gcloud.write_text('''#!/bin/bash
set -eu
case "$*" in
  "compute instance-groups managed describe "*)
    echo "https://example.invalid/instanceTemplates/previous-template" ;;
  "compute instance-templates describe previous-template "*)
    printf '{"properties":{"metadata":{"items":[{"key":"tee-env-QUILL_USAGE_HEARTBEAT","value":"%s"}]}}}\n' "$TEMPLATE_HEARTBEAT" ;;
  "secrets versions access latest --secret=trustedrouter-synthetic-monitor-api-key "*)
    echo fallback-monitor-key ;;
  *) echo "unexpected gcloud call: $*" >&2; exit 1 ;;
esac
''')
            gcloud.chmod(0o755)
            for template_flag, workflow_flag in (("off", "on"), ("on", "off")):
                with self.subTest(template_flag=template_flag, workflow_flag=workflow_flag):
                    env = {
                        **os.environ,
                        "PATH": f"{temp}:{os.environ['PATH']}",
                        "TEMPLATE_HEARTBEAT": template_flag,
                        "QUILL_USAGE_HEARTBEAT": workflow_flag,
                        "HEARTBEAT_FLAG": workflow_flag,
                    }
                    env.pop("STAGE_D_PROBE_API_KEY", None)
                    completed = subprocess.run(
                        ["bash", str(script), "us-central1", "quill-enclave-mig-us-", "fixture-digest"],
                        env=env, capture_output=True, text=True, timeout=5,
                    )
                    self.assertIn(
                        f"selected template previous-template has QUILL_USAGE_HEARTBEAT={template_flag}",
                        completed.stdout,
                    )
                    if template_flag == "off":
                        self.assertEqual(completed.returncode, 0, completed.stderr)
                        self.assertIn("plain streaming health and settled authorization only", completed.stderr)
                    else:
                        self.assertNotEqual(completed.returncode, 0)
                        self.assertIn("QUILL_USAGE_HEARTBEAT=on; failing closed", completed.stderr)

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
        us_west = workflow.index("      - name: Roll US West GCP MIG")
        self.assertLess(europe, us_east)
        # The region that may still be bootstrapping rolls last, so its first
        # deploy cannot hold up the regions that already serve.
        self.assertLess(us_east, us_west)
        self.assertEqual(
            re.findall(r"^      - name: (Roll .*GCP MIG.*)$", workflow, re.MULTILINE),
            [
                "Roll the GCP MIG (us-central1)",
                "Roll Europe GCP MIG",
                "Roll US East GCP MIG",
                "Roll US West GCP MIG",
            ],
        )
        self.assertNotIn("Roll São Paulo GCP MIG", workflow)

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
                "Refresh AWS credentials for US West backup-domain DNS",
                "Roll US West GCP MIG",
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

    def test_primary_stability_wait_and_rollback_cover_two_readiness_holds(self) -> None:
        # One surge VM per zone: two VMs in ONE zone are replaced one after the
        # other, each held ready for MIN_READY (600 s). 2026-09-21: the primary
        # step's 15-minute cap failed a healthy rollout at the second hold.
        workflow = (
            ROOT / ".github" / "workflows" / "deploy-enclave-gcp.yml"
        ).read_text(encoding="utf-8")
        deploy = (ROOT / "tools" / "deploy-gcp-mig.sh").read_text(encoding="utf-8")
        recovery = (ROOT / "tools" / "recover-gcp-region.sh").read_text(
            encoding="utf-8"
        )
        min_ready = re.search(r'MIN_READY="?\$\{MIN_READY:-(\d+)s?\}"?', deploy)
        self.assertIsNotNone(min_ready, "MIN_READY default not found in deploy-gcp-mig.sh")
        assert min_ready is not None
        two_holds = 2 * int(min_ready.group(1))

        step = workflow.split("- name: Wait for us-central1 MIG to be stable", 1)[1]
        step = step.split("\n      - name:", 1)[0]
        cap = re.search(r"timeout-minutes: (\d+)", step)
        rounds = re.search(r"wait_rounds=(\d+)", step)
        self.assertIsNotNone(cap)
        self.assertIsNotNone(rounds)
        assert cap is not None and rounds is not None
        # Headroom for two boots and the DNS refresh in each round.
        self.assertGreaterEqual(int(cap.group(1)) * 60, two_holds + 900)
        # A round is at least 15 s (wait-until --timeout=10, then sleep 5).
        self.assertGreaterEqual(int(rounds.group(1)) * 15, two_holds + 300)
        self.assertIn('seq 1 "${wait_rounds}"', step)

        rollback = re.search(r"ROLLBACK_STABLE_TIMEOUT:-(\d+)", recovery)
        self.assertIsNotNone(rollback)
        assert rollback is not None
        self.assertGreaterEqual(int(rollback.group(1)), two_holds + 900)

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
        self.assertIn('"${prior_drain_origin}"', secondary)
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
        self.assertIn('final_drain_origin="${7-none}"', recovery)
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
        self.assertIn("Clear healthy rollout-created canonical drains", workflow)
        cleanup_start = workflow.index(
            "      - name: Clear healthy rollout-created canonical drains"
        )
        cleanup = workflow[cleanup_start:]
        self.assertIn("if: always()", cleanup)
        self.assertIn("cleanup-enclave-rollout-drains.sh", cleanup)

    def test_deploy_preflights_runtime_access_to_every_referenced_secret(self) -> None:
        deploy = (ROOT / "tools" / "deploy-gcp-mig.sh").read_text(encoding="utf-8")

        preflight = deploy.index("verify-gcp-runtime-secret-access.py")
        template = deploy.index("gc compute instance-templates create")
        self.assertLess(preflight, template)
        self.assertIn("compgen -A variable", deploy)
        self.assertIn("QUILL_*_SECRET|ACME_FALLBACK_EAB_SECRET", deploy)
        self.assertIn('--service-account "${WORKLOAD_SA}"', deploy)

    def test_optional_secrets_use_one_fail_closed_inventory_read(self) -> None:
        deploy = (ROOT / "tools" / "deploy-gcp-mig.sh").read_text(encoding="utf-8")

        self.assertEqual(deploy.count("gc secrets list --format='value(name)'"), 1)
        self.assertIn('SECRET_MANAGER_INVENTORY="$(gc secrets list', deploy)
        self.assertIn("secret_inventory_has()", deploy)
        self.assertIn('secret_inventory_has "$default_secret"', deploy)
        self.assertNotRegex(
            deploy,
            r"gc secrets describe (?:\"\$default_secret\"|trustedrouter-)",
        )

    def test_recovery_and_secret_preflight_changes_trigger_deployment(self) -> None:
        workflow = (
            ROOT / ".github" / "workflows" / "deploy-enclave-gcp.yml"
        ).read_text(encoding="utf-8")

        self.assertIn('- "tools/recover-gcp-region.sh"', workflow)
        self.assertIn('- "tools/verify-gcp-runtime-secret-access.py"', workflow)

    def test_rollout_scripts_match_the_built_image_source(self) -> None:
        workflow = (
            ROOT / ".github" / "workflows" / "deploy-enclave-gcp.yml"
        ).read_text(encoding="utf-8")
        rollout = workflow.split("\n  rollout:\n", 1)[1].split(
            "\n  finalize-trust-artifacts:\n", 1
        )[0]
        checkout = rollout.split("- uses: actions/checkout@v4", 1)[1].split(
            "\n      - ", 1
        )[0]
        # Moving main injected a new env into an older measured image, which
        # Confidential Space rejected before the workload could start.
        self.assertEqual(
            re.findall(r"^          ref: (.+)$", checkout, re.MULTILINE),
            ["${{ github.sha }}"],
        )
        self.assertIn("persist-credentials: false", checkout)
        self.assertNotIn("TRUST_PUSH_TOKEN", checkout)

    def test_public_allowlist_is_published_before_rollout_and_collapsed_after(self) -> None:
        workflow = (
            ROOT / ".github" / "workflows" / "deploy-enclave-gcp.yml"
        ).read_text(encoding="utf-8")

        transition = workflow.index("\n  verify-transition-trust-page:")
        rollout = workflow.index("\n  rollout:")
        finalize = workflow.index("\n  finalize-trust-artifacts:")
        verify_final = workflow.index("\n  verify-final-trust-page:", finalize)

        self.assertLess(transition, rollout)
        self.assertLess(rollout, finalize)
        self.assertLess(finalize, verify_final)
        self.assertIn(
            "needs: [build-and-release, grant-batch-image-access, verify-transition-trust-page]",
            workflow,
        )
        self.assertIn('--accepted-image-digests "${previous}"', workflow)
        self.assertIn(
            '--accepted-image-references "${previous_references}"', workflow
        )
        self.assertIn(
            'tools/wait-trust-page-set.sh "${EXPECTED_DIGESTS}" "${EXPECTED_REFERENCES}"',
            workflow,
        )
        self.assertIn(
            "needs: [build-and-release, finalize-trust-artifacts]",
            workflow,
        )
        self.assertIn(
            "EXPECTED_DIGESTS: ${{ needs.build-and-release.outputs.image_digest }}",
            workflow,
        )
        self.assertNotIn("\n  publish-transition-trust-page:", workflow)

    def test_trust_artifacts_are_regenerated_after_rebase(self) -> None:
        workflow = (
            ROOT / ".github" / "workflows" / "deploy-enclave-gcp.yml"
        ).read_text(encoding="utf-8")

        helper = workflow.index("regenerate_trust_artifacts_after_rebase()")
        rebase = workflow.index('git rebase -X theirs "$rebase_target"')
        regenerate = workflow.index(
            "regenerate_trust_artifacts_after_rebase", helper + 1
        )
        self.assertLess(helper, rebase)
        self.assertLess(rebase, regenerate)
        self.assertIn("python3 tools/write-trust-artifacts.py", workflow[helper:rebase])
        self.assertIn("git commit --amend --no-edit", workflow[helper:rebase])

    def test_public_trust_verifiers_are_independent_of_publish_job_identity(self) -> None:
        deploy_workflow = (
            ROOT / ".github" / "workflows" / "deploy-enclave-gcp.yml"
        ).read_text(encoding="utf-8")
        publish_workflow = (
            ROOT / ".github" / "workflows" / "publish-trust-page.yml"
        ).read_text(encoding="utf-8")

        self.assertEqual(deploy_workflow.count("tools/wait-trust-page-set.sh"), 2)
        self.assertNotIn("artifact_name: github-pages-transition", deploy_workflow)
        self.assertNotIn("artifact_name: github-pages-final", deploy_workflow)
        self.assertEqual(
            publish_workflow.count("${{ inputs.artifact_name || 'github-pages' }}"),
            3,
            "upload, initial deploy, and retry must select the same artifact",
        )


if __name__ == "__main__":
    unittest.main()
