#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest
from unittest import mock


SCRIPT = Path(__file__).with_name("reconcile-enclave-dns.py")
SPEC = importlib.util.spec_from_file_location("reconcile_enclave_dns", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
reconciler = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(reconciler)


class PersistentDrainTests(unittest.TestCase):
    def test_drain_payload_round_trips_deterministically(self) -> None:
        encoded = reconciler.encode_drain_rrdatas(
            {"us-east4", "europe-west4", "us-central1"}
        )

        self.assertEqual(
            encoded,
            ['"v1;europe-west4;us-central1;us-east4"'],
        )
        self.assertEqual(
            reconciler.parse_drain_rrdatas(encoded),
            {"us-east4", "europe-west4", "us-central1"},
        )

    def test_empty_versioned_payload_means_no_drains(self) -> None:
        self.assertEqual(reconciler.parse_drain_rrdatas(['"v1"']), set())

    def test_malformed_drain_payload_fails_closed(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "unsupported payload"):
            reconciler.parse_drain_rrdatas(['"us-central1"'])
        with self.assertRaisesRegex(RuntimeError, "invalid region"):
            reconciler.parse_drain_rrdatas(['"v1;US_CENTRAL1"'])
        with self.assertRaisesRegex(RuntimeError, "exactly one TXT"):
            reconciler.parse_drain_rrdatas(['"v1;us-central1"', '"v1;us-east4"'])

    def test_set_drain_preserves_other_regions(self) -> None:
        with (
            mock.patch.object(
                reconciler,
                "persistent_drain_regions",
                return_value={"europe-west4"},
            ),
            mock.patch.object(reconciler, "set_dns_txt") as set_dns_txt,
        ):
            regions = reconciler.update_persistent_drain(
                "us-central1",
                enabled=True,
            )

        self.assertEqual(regions, {"europe-west4", "us-central1"})
        set_dns_txt.assert_called_once_with(
            reconciler.DNS_ZONE,
            reconciler.DRAIN_RECORD,
            ['"v1;europe-west4;us-central1"'],
        )

    def test_clear_drain_keeps_marker_with_empty_version(self) -> None:
        with (
            mock.patch.object(
                reconciler,
                "persistent_drain_regions",
                return_value={"us-central1"},
            ),
            mock.patch.object(reconciler, "set_dns_txt") as set_dns_txt,
        ):
            regions = reconciler.update_persistent_drain(
                "us-central1",
                enabled=False,
            )

        self.assertEqual(regions, set())
        set_dns_txt.assert_called_once_with(
            reconciler.DNS_ZONE,
            reconciler.DRAIN_RECORD,
            ['"v1"'],
        )


if __name__ == "__main__":
    unittest.main()
