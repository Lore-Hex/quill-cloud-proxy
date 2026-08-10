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


class TrustDigestTests(unittest.TestCase):
    def test_reads_single_digest(self) -> None:
        response = mock.MagicMock()
        response.__enter__.return_value.read.return_value = b"sha256:" + b"1" * 64
        with mock.patch.object(reconciler.urllib.request, "urlopen", return_value=response):
            self.assertEqual(reconciler.trust_digests(), ["sha256:" + "1" * 64])

    def test_reads_deduplicated_rollout_digest_set(self) -> None:
        old = "sha256:" + "1" * 64
        new = "sha256:" + "2" * 64
        response = mock.MagicMock()
        response.__enter__.return_value.read.return_value = f"{old},{new},{old}\n".encode()
        with mock.patch.object(reconciler.urllib.request, "urlopen", return_value=response):
            self.assertEqual(reconciler.trust_digests(), [old, new])

    def test_rejects_malformed_rollout_digest_set(self) -> None:
        response = mock.MagicMock()
        response.__enter__.return_value.read.return_value = b"sha256:not-a-digest"
        with (
            mock.patch.object(reconciler.urllib.request, "urlopen", return_value=response),
            self.assertRaisesRegex(SystemExit, "trust digest set looks wrong"),
        ):
            reconciler.trust_digests()


class CanonicalMirrorTests(unittest.TestCase):
    def test_defaults_are_symmetric_for_both_public_api_names(self) -> None:
        self.assertEqual(
            reconciler.default_canonical_mirrors("api.trustedrouter.com"),
            "quillrouter-com:api.quillrouter.com.",
        )
        self.assertEqual(
            reconciler.default_canonical_mirrors("api.quillrouter.com"),
            "trustedrouter-com:api.trustedrouter.com.",
        )
        self.assertEqual(
            reconciler.default_canonical_mirrors("api-us-east4.quillrouter.com"),
            "",
        )

    def test_parses_canonical_mirrors(self) -> None:
        self.assertEqual(
            reconciler.parse_canonical_mirrors(
                "quillrouter-com:api.quillrouter.com,backup-zone:api.backup.test."
            ),
            [
                ("quillrouter-com", "api.quillrouter.com."),
                ("backup-zone", "api.backup.test."),
            ],
        )

    def test_rejects_malformed_canonical_mirror(self) -> None:
        with self.assertRaisesRegex(ValueError, "zone:record"):
            reconciler.parse_canonical_mirrors("api.quillrouter.com")

    def test_apply_reconciles_mirror_to_exact_canonical_set(self) -> None:
        healthy = ["203.0.113.10", "203.0.113.11"]
        with (
            mock.patch.object(
                reconciler,
                "current_dns_ips",
                return_value=["198.51.100.7"],
            ),
            mock.patch.object(reconciler, "set_dns_ips") as set_dns_ips,
        ):
            reconciler.reconcile_dns_record(
                "quillrouter-com",
                "api.quillrouter.com.",
                healthy,
                apply=True,
                label="compatibility mirror",
            )

        set_dns_ips.assert_called_once_with(
            "quillrouter-com",
            "api.quillrouter.com.",
            healthy,
        )

    def test_dry_run_never_mutates_mirror(self) -> None:
        with (
            mock.patch.object(
                reconciler,
                "current_dns_ips",
                return_value=["198.51.100.7"],
            ),
            mock.patch.object(reconciler, "set_dns_ips") as set_dns_ips,
        ):
            reconciler.reconcile_dns_record(
                "quillrouter-com",
                "api.quillrouter.com.",
                ["203.0.113.10"],
                apply=False,
                label="compatibility mirror",
            )

        set_dns_ips.assert_not_called()


class RegionalDnsPromotionTests(unittest.TestCase):
    def test_cname_to_a_uses_one_cloud_dns_transaction(self) -> None:
        completed = mock.Mock(returncode=0, stdout="", stderr="")
        cname = {
            "name": "api-southamerica-east1.quillrouter.com.",
            "type": "CNAME",
            "ttl": 300,
            "rrdatas": ["api.quillrouter.com."],
        }

        with mock.patch.object(
            reconciler.subprocess,
            "run",
            return_value=completed,
        ) as run:
            reconciler.replace_cname_with_ips(
                "quillrouter-com",
                "api-southamerica-east1.quillrouter.com.",
                cname,
                ["203.0.113.10", "203.0.113.11"],
            )

        commands = [call.args[0] for call in run.call_args_list]
        self.assertEqual(
            [command[4] for command in commands],
            ["start", "remove", "add", "execute"],
        )
        self.assertIn("CNAME", commands[1])
        self.assertIn("api.quillrouter.com.", commands[1])
        self.assertIn("A", commands[2])
        self.assertIn("203.0.113.10", commands[2])
        self.assertIn("203.0.113.11", commands[2])
        transaction_files = {
            command[command.index("--transaction-file") + 1]
            for command in commands
        }
        self.assertEqual(len(transaction_files), 1)

    def test_set_dns_ips_promotes_existing_cname_without_separate_delete(self) -> None:
        cname = {
            "type": "CNAME",
            "ttl": 300,
            "rrdatas": ["api.quillrouter.com."],
        }
        with (
            mock.patch.object(
                reconciler,
                "current_dns_record",
                return_value=cname,
            ),
            mock.patch.object(reconciler, "replace_cname_with_ips") as replace,
            mock.patch.object(reconciler, "current_dns_ips") as current_ips,
        ):
            reconciler.set_dns_ips(
                "quillrouter-com",
                "api-southamerica-east1.quillrouter.com.",
                ["203.0.113.10"],
            )

        replace.assert_called_once()
        current_ips.assert_not_called()

    def test_rollout_drain_holds_cold_cname_before_direct_canary(self) -> None:
        cname = {
            "type": "CNAME",
            "ttl": 300,
            "rrdatas": ["api.quillrouter.com."],
        }
        with (
            mock.patch.object(
                reconciler,
                "current_dns_record",
                return_value=cname,
            ),
            mock.patch.object(reconciler, "current_dns_ips") as current_ips,
            mock.patch.object(reconciler, "set_dns_ips") as set_ips,
        ):
            reconciler.reconcile_regional(
                {"southamerica-east1": ["203.0.113.10"]},
                True,
                drained_regions={"southamerica-east1"},
            )

        current_ips.assert_not_called()
        set_ips.assert_not_called()

    def test_direct_canary_override_allows_drained_cname_promotion(self) -> None:
        cname = {
            "type": "CNAME",
            "ttl": 300,
            "rrdatas": ["api.quillrouter.com."],
        }
        with (
            mock.patch.object(
                reconciler,
                "ALLOW_DRAINED_REGIONAL_PROMOTION_REGIONS",
                {"southamerica-east1"},
            ),
            mock.patch.object(
                reconciler,
                "current_dns_record",
                return_value=cname,
            ),
            mock.patch.object(reconciler, "current_dns_ips", return_value=[]),
            mock.patch.object(reconciler, "set_dns_ips") as set_ips,
        ):
            reconciler.reconcile_regional(
                {"southamerica-east1": ["203.0.113.10"]},
                True,
                drained_regions={"southamerica-east1"},
            )

        set_ips.assert_called_once_with(
            reconciler.REGIONAL_ZONE,
            "api-southamerica-east1.quillrouter.com.",
            ["203.0.113.10"],
        )


if __name__ == "__main__":
    unittest.main()
