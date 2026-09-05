#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("check-public-tls.py")
SPEC = importlib.util.spec_from_file_location("check_public_tls", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
TLS_CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TLS_CHECK)


class PublicTLSCheckTests(unittest.TestCase):
    def test_gcp_probe_hosts_equal_rollout_inventory(self) -> None:
        inventory_regions = tuple(
            line.partition(":")[0]
            for line in (Path(__file__).with_name("gcp-enclave-migs.txt"))
            .read_text(encoding="utf-8")
            .splitlines()
        )
        expected_hosts = tuple(
            f"api-{region}.quillrouter.com" for region in inventory_regions
        )
        probed_gcp_hosts = tuple(
            host
            for host in TLS_CHECK.DEFAULT_HOSTS
            if host.startswith("api-") and host.endswith(".quillrouter.com")
        )

        self.assertEqual(TLS_CHECK.GCP_REGIONAL_HOSTS, expected_hosts)
        self.assertEqual(probed_gcp_hosts, expected_hosts)
        self.assertNotIn(
            "api-southamerica-east1.quillrouter.com",
            TLS_CHECK.DEFAULT_HOSTS,
        )

    def test_default_hosts_cover_operational_aliases(self) -> None:
        self.assertIn("api.trustedrouter.com", TLS_CHECK.DEFAULT_HOSTS)
        self.assertIn("api-aws.trustedrouter.com", TLS_CHECK.DEFAULT_HOSTS)
        self.assertNotIn("api-aws.trustedrouter.com", TLS_CHECK.ATTESTED_SELF_SIGNED_HOSTS)
        self.assertIn("allyrouter.com", TLS_CHECK.DEFAULT_HOSTS)
        self.assertIn("status.allyrouter.com", TLS_CHECK.DEFAULT_HOSTS)
        self.assertIn("trust.allyrouter.com", TLS_CHECK.DEFAULT_HOSTS)
        self.assertIn("api.allyrouter.com", TLS_CHECK.DEFAULT_HOSTS)
        self.assertIn("uptimerouter.com", TLS_CHECK.DEFAULT_HOSTS)
        self.assertIn("status.uptimerouter.com", TLS_CHECK.DEFAULT_HOSTS)
        self.assertIn("trust.uptimerouter.com", TLS_CHECK.DEFAULT_HOSTS)
        self.assertIn("api.uptimerouter.com", TLS_CHECK.DEFAULT_HOSTS)

    def test_parses_certificate_expiry_as_utc(self) -> None:
        expiry = TLS_CHECK.certificate_expiry(
            {"notAfter": "Sep 30 23:51:54 2026 GMT"}
        )
        self.assertEqual(expiry, datetime(2026, 9, 30, 23, 51, 54, tzinfo=UTC))

    def test_rejects_certificate_inside_warning_window(self) -> None:
        now = datetime(2026, 7, 31, tzinfo=UTC)
        self.assertFalse(
            TLS_CHECK.expiry_is_safe(
                now + timedelta(days=13, hours=23),
                now=now,
                minimum_remaining=timedelta(days=14),
            )
        )

    def test_accepts_certificate_at_warning_boundary(self) -> None:
        now = datetime(2026, 7, 31, tzinfo=UTC)
        self.assertTrue(
            TLS_CHECK.expiry_is_safe(
                now + timedelta(days=14),
                now=now,
                minimum_remaining=timedelta(days=14),
            )
        )

    def test_missing_not_after_fails_closed(self) -> None:
        with self.assertRaisesRegex(ValueError, "notAfter"):
            TLS_CHECK.certificate_expiry({})


if __name__ == "__main__":
    unittest.main()
