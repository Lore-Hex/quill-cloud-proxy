#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import subprocess
import unittest
from pathlib import Path
from unittest import mock


MODULE_PATH = Path(__file__).with_name("sync-route53-api-aliases.py")
SPEC = importlib.util.spec_from_file_location("sync_route53_api_aliases", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
SYNC = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SYNC)


class Route53AliasSyncTests(unittest.TestCase):
    def test_aliases_are_independent_direct_records(self) -> None:
        names = {alias.name for alias in SYNC.ALIASES}
        self.assertEqual(
            names,
            {"api.allyrouter.com.", "api.uptimerouter.com."},
        )

    def test_normalizes_and_sorts_public_ipv4(self) -> None:
        self.assertEqual(
            SYNC.normalized_ipv4(
                ["34.11.89.24", "34.141.142.209", "34.11.89.24"]
            ),
            ["34.11.89.24", "34.141.142.209"],
        )

    def test_rejects_too_small_or_private_source_set(self) -> None:
        with self.assertRaisesRegex(ValueError, "only 1 healthy"):
            SYNC.normalized_ipv4(["34.11.89.24"])
        with self.assertRaisesRegex(ValueError, "public IPv4"):
            SYNC.normalized_ipv4(["10.0.0.1", "34.11.89.24"])

    def test_change_batch_is_an_a_record_upsert(self) -> None:
        alias = SYNC.AliasRecord("ZONE", "api.example.com.")
        batch = SYNC.change_batch(alias, ["34.11.59.111", "34.11.89.24"])
        change = batch["Changes"][0]
        self.assertEqual(change["Action"], "UPSERT")
        record = change["ResourceRecordSet"]
        self.assertEqual(record["Name"], "api.example.com.")
        self.assertEqual(record["Type"], "A")
        self.assertEqual(record["TTL"], 60)
        self.assertEqual(
            record["ResourceRecords"],
            [{"Value": "34.11.59.111"}, {"Value": "34.11.89.24"}],
        )

    def test_command_failure_reports_stderr(self) -> None:
        failure = subprocess.CalledProcessError(
            254,
            ["aws", "route53", "list-resource-record-sets"],
            stderr="The security token included in the request is expired",
        )
        with mock.patch.object(SYNC.subprocess, "run", side_effect=failure):
            with self.assertRaisesRegex(
                RuntimeError,
                "aws route53 list-resource-record-sets failed with exit 254: "
                "The security token included in the request is expired",
            ):
                SYNC.run_json(["aws", "route53", "list-resource-record-sets"])

    def test_invalid_command_json_has_operation_context(self) -> None:
        result = subprocess.CompletedProcess(
            ["gcloud", "dns", "record-sets"],
            0,
            stdout="not-json",
            stderr="",
        )
        with mock.patch.object(SYNC.subprocess, "run", return_value=result):
            with self.assertRaisesRegex(
                RuntimeError,
                "gcloud dns record-sets returned invalid JSON",
            ):
                SYNC.run_json(["gcloud", "dns", "record-sets"])


if __name__ == "__main__":
    unittest.main()
