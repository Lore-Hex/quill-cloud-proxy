#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "deploy-enclave-dns-reconciler.yml"


class DnsReconcilerSchedulerTests(unittest.TestCase):
    def test_scheduler_is_declarative_and_retries_transient_control_plane_errors(
        self,
    ) -> None:
        workflow = WORKFLOW.read_text()

        self.assertIn("SCHEDULER_NAME: enclave-dns-reconciler-tick", workflow)
        self.assertIn('SCHEDULER_SCHEDULE: "*/2 * * * *"', workflow)
        self.assertIn("gcloud scheduler jobs create http", workflow)
        self.assertIn("gcloud scheduler jobs update http", workflow)
        self.assertIn("--max-retry-attempts=5", workflow)
        self.assertIn("--min-backoff=10s", workflow)
        self.assertIn("--max-backoff=30s", workflow)
        self.assertIn("--max-doublings=2", workflow)
        self.assertIn("--max-retry-duration=110s", workflow)
        self.assertIn("--attempt-deadline=30s", workflow)


if __name__ == "__main__":
    unittest.main()
