#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import pathlib
import unittest


def load_module():
    path = pathlib.Path(__file__).with_name("synthetic_gate_status.py")
    spec = importlib.util.spec_from_file_location("synthetic_gate_status", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load synthetic_gate_status.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gate = load_module()


def sample(
    monitor: str,
    probe: str,
    *,
    status: str = "up",
    created_at: str = "2026-07-17T01:01:00Z",
) -> dict[str, object]:
    return {
        "target_region": "us-central1",
        "monitor_region": monitor,
        "probe_type": probe,
        "effective_status": status,
        "created_at": created_at,
    }


def complete_samples(monitor: str) -> list[dict[str, object]]:
    return [sample(monitor, probe) for probe in gate.REQUIRED_PROBES]


class SyntheticGateStatusTests(unittest.TestCase):
    def evaluate(self, checks: list[dict[str, object]]) -> str:
        started_at = gate._timestamp("2026-07-17T01:00:00Z")
        self.assertIsNotNone(started_at)
        return gate.evaluate_region(
            {"data": {"current": {"checks": checks}}},
            region="us-central1",
            started_at=started_at,
            monitor_regions=["us-central1", "europe-west4"],
        )

    def test_complete_fresh_probe_sets_are_up(self) -> None:
        checks = complete_samples("us-central1") + complete_samples("europe-west4")
        self.assertEqual(self.evaluate(checks), "up")

    def test_stale_peer_failure_does_not_replace_required_fresh_sample(self) -> None:
        checks = complete_samples("us-central1") + complete_samples("europe-west4")
        checks.append(
            sample(
                "europe-west4",
                "openai_sdk_pong",
                status="down",
                created_at="2026-07-16T23:00:00Z",
            )
        )
        self.assertEqual(self.evaluate(checks), "up")

    def test_missing_fresh_peer_probe_waits(self) -> None:
        checks = complete_samples("us-central1") + complete_samples("europe-west4")
        checks = [
            check
            for check in checks
            if not (
                check["monitor_region"] == "europe-west4"
                and check["probe_type"] == "responses_pong"
            )
        ]
        self.assertEqual(self.evaluate(checks), "waiting")

    def test_fresh_failure_is_down(self) -> None:
        checks = complete_samples("us-central1") + complete_samples("europe-west4")
        for check in checks:
            if (
                check["monitor_region"] == "us-central1"
                and check["probe_type"] == "openai_sdk_pong"
            ):
                check["effective_status"] = "down"
        self.assertEqual(self.evaluate(checks), "down")


if __name__ == "__main__":
    unittest.main()
