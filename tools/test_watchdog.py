#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import io
import pathlib
import unittest
from unittest import mock


def load_watchdog_module():
    path = pathlib.Path(__file__).with_name("watchdog.py")
    spec = importlib.util.spec_from_file_location("watchdog", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load watchdog.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


watchdog = load_watchdog_module()


class WatchdogStateTests(unittest.TestCase):
    def test_status_url_is_cache_busted_without_losing_existing_query(self) -> None:
        url = watchdog.cache_busted_status_url(
            "https://trustedrouter.com/status.json?format=json", nonce=123
        )
        self.assertEqual(
            url,
            "https://trustedrouter.com/status.json?format=json&_watchdog=123",
        )

    def test_fetch_requires_a_fresh_status_snapshot(self) -> None:
        payload = io.BytesIO(
            b'{"data":{"current":{"checks":[{"target_region":"us-central1",'
            b'"probe_type":"tls_health","effective_status":"up"}]}}}'
        )
        with mock.patch.object(
            watchdog.urllib.request, "urlopen", return_value=payload
        ) as urlopen:
            result = watchdog.fetch_per_region(
                "https://trustedrouter.com/status.json", ["us-central1"]
            )

        self.assertEqual(result, {"us-central1": "up"})
        request = urlopen.call_args.args[0]
        self.assertIn("_watchdog=", request.full_url)
        self.assertEqual(request.get_header("Cache-control"), "no-cache")
        self.assertEqual(request.get_header("Pragma"), "no-cache")

    def test_fetch_ignores_stale_failure_after_newer_success(self) -> None:
        payload = io.BytesIO(
            b'{"data":{"current":{"checks":['
            b'{"target_region":"us-central1","monitor_region":"europe-west4",'
            b'"probe_type":"tls_health","target":"us-central1",'
            b'"created_at":"2026-07-27T22:47:00Z","effective_status":"down"},'
            b'{"target_region":"us-central1","monitor_region":"europe-west4",'
            b'"probe_type":"tls_health","target":"us-central1",'
            b'"created_at":"2026-07-27T22:48:00Z","effective_status":"up"}'
            b"]}}}"
        )
        with mock.patch.object(
            watchdog.urllib.request, "urlopen", return_value=payload
        ):
            result = watchdog.fetch_per_region(
                "https://trustedrouter.com/status.json", ["us-central1"]
            )

        self.assertEqual(result, {"us-central1": "up"})

    def test_fetch_ignores_provider_failure_when_gateway_is_up(self) -> None:
        payload = io.BytesIO(
            b'{"data":{"current":{"checks":['
            b'{"target_region":"us-central1","monitor_region":"us-central1",'
            b'"probe_type":"tls_health","target":"us-central1",'
            b'"created_at":"2026-07-27T22:48:00Z","effective_status":"up"},'
            b'{"target_region":"us-central1","monitor_region":"us-central1",'
            b'"probe_type":"attestation_nonce","target":"us-central1",'
            b'"created_at":"2026-07-27T22:48:00Z","effective_status":"up"},'
            b'{"target_region":"us-central1","monitor_region":"us-central1",'
            b'"probe_type":"openai_sdk_pong","target":"us-central1",'
            b'"created_at":"2026-07-27T22:49:00Z","effective_status":"down"}'
            b"]}}}"
        )
        with mock.patch.object(
            watchdog.urllib.request, "urlopen", return_value=payload
        ):
            result = watchdog.fetch_per_region(
                "https://trustedrouter.com/status.json", ["us-central1"]
            )

        self.assertEqual(result, {"us-central1": "up"})

    def test_fetch_returns_unknown_when_only_provider_probes_exist(self) -> None:
        payload = io.BytesIO(
            b'{"data":{"current":{"checks":['
            b'{"target_region":"us-central1","monitor_region":"us-central1",'
            b'"probe_type":"openai_sdk_pong","target":"us-central1",'
            b'"created_at":"2026-07-27T22:49:00Z","effective_status":"up"}'
            b"]}}}"
        )
        with mock.patch.object(
            watchdog.urllib.request, "urlopen", return_value=payload
        ):
            result = watchdog.fetch_per_region(
                "https://trustedrouter.com/status.json", ["us-central1"]
            )

        self.assertEqual(result, {"us-central1": "unknown"})

    def test_fetch_keeps_newest_failure_and_worst_current_dimension(self) -> None:
        payload = io.BytesIO(
            b'{"data":{"current":{"checks":['
            b'{"target_region":"us-central1","monitor_region":"us-central1",'
            b'"probe_type":"tls_health","target":"us-central1",'
            b'"created_at":"2026-07-27T22:48:00Z","effective_status":"up"},'
            b'{"target_region":"us-central1","monitor_region":"europe-west4",'
            b'"probe_type":"attestation_nonce","target":"us-central1",'
            b'"created_at":"2026-07-27T22:47:00Z","effective_status":"up"},'
            b'{"target_region":"us-central1","monitor_region":"europe-west4",'
            b'"probe_type":"attestation_nonce","target":"us-central1",'
            b'"created_at":"2026-07-27T22:49:00Z","effective_status":"down"}'
            b"]}}}"
        )
        with mock.patch.object(
            watchdog.urllib.request, "urlopen", return_value=payload
        ):
            result = watchdog.fetch_per_region(
                "https://trustedrouter.com/status.json", ["us-central1"]
            )

        self.assertEqual(result, {"us-central1": "down"})

    def test_rolls_back_only_after_threshold(self) -> None:
        regions = ["europe-west4"]
        rollback_set: set[str] = set()
        consecutive_down = {"europe-west4": 0}

        first = watchdog.update_rollback_state(
            regions=regions,
            per_region={"europe-west4": "down"},
            baseline_down=set(),
            rollback_set=rollback_set,
            consecutive_down=consecutive_down,
            rollback_after=3,
        )
        second = watchdog.update_rollback_state(
            regions=regions,
            per_region={"europe-west4": "down"},
            baseline_down=set(),
            rollback_set=rollback_set,
            consecutive_down=consecutive_down,
            rollback_after=3,
        )
        third = watchdog.update_rollback_state(
            regions=regions,
            per_region={"europe-west4": "down"},
            baseline_down=set(),
            rollback_set=rollback_set,
            consecutive_down=consecutive_down,
            rollback_after=3,
        )

        self.assertEqual(first, [])
        self.assertEqual(second, [])
        self.assertEqual(third, ["europe-west4"])
        self.assertEqual(rollback_set, {"europe-west4"})
        self.assertEqual(consecutive_down["europe-west4"], 3)

    def test_recovery_or_unknown_resets_consecutive_down(self) -> None:
        regions = ["us-east4"]
        rollback_set: set[str] = set()
        consecutive_down = {"us-east4": 0}

        watchdog.update_rollback_state(
            regions=regions,
            per_region={"us-east4": "down"},
            baseline_down=set(),
            rollback_set=rollback_set,
            consecutive_down=consecutive_down,
            rollback_after=2,
        )
        watchdog.update_rollback_state(
            regions=regions,
            per_region={"us-east4": "unknown"},
            baseline_down=set(),
            rollback_set=rollback_set,
            consecutive_down=consecutive_down,
            rollback_after=2,
        )
        result = watchdog.update_rollback_state(
            regions=regions,
            per_region={"us-east4": "down"},
            baseline_down=set(),
            rollback_set=rollback_set,
            consecutive_down=consecutive_down,
            rollback_after=2,
        )

        self.assertEqual(result, [])
        self.assertEqual(rollback_set, set())
        self.assertEqual(consecutive_down["us-east4"], 1)

    def test_baseline_down_region_does_not_trigger_deploy_rollback(self) -> None:
        regions = ["europe-west4"]
        rollback_set: set[str] = set()
        consecutive_down = {"europe-west4": 0}

        for _ in range(5):
            result = watchdog.update_rollback_state(
                regions=regions,
                per_region={"europe-west4": "down"},
                baseline_down={"europe-west4"},
                rollback_set=rollback_set,
                consecutive_down=consecutive_down,
                rollback_after=2,
            )

        self.assertEqual(result, [])
        self.assertEqual(rollback_set, set())
        self.assertEqual(consecutive_down["europe-west4"], 0)


if __name__ == "__main__":
    unittest.main()
