#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import pathlib
import unittest


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
