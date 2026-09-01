#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "deploy-enclave-dns-reconciler.yml"


class DnsReconcilerSchedulerTests(unittest.TestCase):
    @staticmethod
    def _continued_command(workflow: str, prefix: str) -> str:
        lines = workflow.splitlines()
        start = next(i for i, line in enumerate(lines) if prefix in line)
        command: list[str] = []
        for line in lines[start:]:
            command.append(line)
            if not line.rstrip().endswith("\\"):
                break
        return "\n".join(command)

    def test_scheduler_is_declarative_and_retries_transient_control_plane_errors(
        self,
    ) -> None:
        workflow = WORKFLOW.read_text()

        self.assertIn("SCHEDULER_NAME: enclave-dns-reconciler-tick", workflow)
        self.assertIn("BUILD_REGION: us-central1", workflow)
        self.assertIn("LOCK_BUCKET_REGION: us-central1", workflow)
        self.assertIn("JOB_REGION: us-east4", workflow)
        self.assertIn("SCHEDULER_REGION: us-central1", workflow)
        self.assertIn(
            'run_uri="https://${JOB_REGION}-run.googleapis.com/',
            workflow,
        )
        self.assertNotIn("  REGION: us-central1", workflow)
        self.assertIn('SCHEDULER_SCHEDULE: "*/2 * * * *"', workflow)
        self.assertIn("--max-retry-attempts=3", workflow)
        self.assertIn("--min-backoff=5s", workflow)
        self.assertIn("--max-backoff=10s", workflow)
        self.assertIn("--max-doublings=1", workflow)
        self.assertIn("--attempt-deadline=15s", workflow)
        self.assertNotIn("--max-retry-duration", workflow)

        for verb in ("create", "update"):
            command = self._continued_command(
                workflow, f"gcloud scheduler jobs {verb} http"
            )
            self.assertIn('"${retry_flags[@]}"', command)

    def test_scheduler_distinguishes_not_found_from_control_plane_failure(self) -> None:
        workflow = WORKFLOW.read_text()

        self.assertIn('2>"${describe_error}"', workflow)
        self.assertIn("grep -Eqi 'NOT_FOUND|not found'", workflow)
        self.assertIn('exit "${describe_status}"', workflow)

    def test_scheduler_uses_dedicated_invoker_and_exercises_its_auth_path(self) -> None:
        workflow = WORKFLOW.read_text()

        self.assertIn(
            "SCHEDULER_SERVICE_ACCOUNT: enclave-dns-reconciler-invoker@",
            workflow,
        )
        self.assertIn("gcloud scheduler jobs run", workflow)
        self.assertIn("gcloud run jobs executions list", workflow)
        self.assertIn("gcloud run jobs executions describe", workflow)
        self.assertNotIn("gcloud run jobs execute", workflow)

    def test_reconciler_has_a_bucket_scoped_singleflight_lease(self) -> None:
        workflow = WORKFLOW.read_text()

        self.assertIn(
            "LOCK_BUCKET: quill-cloud-proxy-enclave-dns-reconciler-state",
            workflow,
        )
        self.assertIn("--role=roles/storage.objectUser", workflow)
        self.assertIn(
            "--member=\"serviceAccount:${RECONCILER_SERVICE_ACCOUNT}\"",
            workflow,
        )
        self.assertIn(
            "--update-env-vars=\"QUILL_RECONCILE_LOCK_BUCKET=${LOCK_BUCKET}\"",
            workflow,
        )


if __name__ == "__main__":
    unittest.main()
