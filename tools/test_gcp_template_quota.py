#!/usr/bin/env python3
"""Offline tests for the read-only GCP release quota gate."""

import json
from pathlib import Path
import subprocess
import unittest
from unittest import mock

import gcp_template_quota as quota


def project(limit=1000, usage=996):
    return {"quotas": [{"metric": "INSTANCE_TEMPLATES", "limit": limit, "usage": usage}]}


class QuotaTests(unittest.TestCase):
    def test_exact_room_for_every_region(self):
        self.assertEqual(quota.available_templates(project(), 4), 4)

    def test_full_and_insufficient_capacity_fail(self):
        for used in (997, 1000, 1001):
            with self.subTest(used=used), self.assertRaises(quota.QuotaError):
                quota.available_templates(project(usage=used), 4)

    def test_unknown_or_ambiguous_quota_fails_closed(self):
        for data in ({}, [], {"quotas": None}, {"quotas": []},
                     {"quotas": [{}]}, {"quotas": [None]},
                     {"quotas": project()["quotas"] * 2}):
            with self.subTest(data=data), self.assertRaises(quota.QuotaError):
                quota.available_templates(data, 4)

    def test_invalid_limits_or_usage_fail_closed(self):
        for field in ("limit", "usage"):
            for value in (None, True, "1000", -1, float("inf"), float("nan"), 0.5):
                data = project()
                data["quotas"][0][field] = value
                with self.subTest(field=field, value=value), self.assertRaises(quota.QuotaError):
                    quota.available_templates(data, 4)

    def test_invalid_requirement_fails(self):
        for required in (0, -1, True, 1.5):
            with self.subTest(required=required), self.assertRaises(quota.QuotaError):
                quota.available_templates(project(), required)

    def test_unrelated_quotas_are_not_capacity(self):
        data = project(usage=1000)
        data["quotas"].append({"metric": "CPUS", "limit": 1000000, "usage": 0})
        with self.assertRaises(quota.QuotaError):
            quota.available_templates(data, 4)

    @mock.patch("gcp_template_quota.subprocess.run")
    def test_command_is_read_only_and_bounded(self, run):
        run.return_value.stdout = json.dumps(project())
        self.assertEqual(quota.read_project("test-project"), project())
        run.assert_called_once_with(
            ["gcloud", "compute", "project-info", "describe", "--project=test-project", "--format=json"],
            check=True, capture_output=True, text=True, timeout=60,
        )

    @mock.patch("gcp_template_quota.subprocess.run")
    def test_no_retry_or_mutation_on_read_failure(self, run):
        run.side_effect = subprocess.TimeoutExpired("gcloud", 60)
        with self.assertRaises(quota.QuotaError):
            quota.read_project("test-project")
        self.assertEqual(run.call_count, 1)

    @mock.patch("gcp_template_quota.subprocess.run")
    def test_bad_json_fails_closed(self, run):
        run.return_value.stdout = "not json"
        with self.assertRaises(quota.QuotaError):
            quota.read_project("test-project")

    def test_release_checks_quota_before_build(self):
        root = Path(__file__).resolve().parents[1]
        workflow = (root / ".github/workflows/deploy-enclave-gcp.yml").read_text()
        check = workflow.index("python3 tools/gcp_template_quota.py")
        build = workflow.index("- name: Build enclave image via Cloud Build")
        self.assertLess(check, build)
        ci = (root / ".github/workflows/ci.yml").read_text()
        self.assertIn("python3 tools/test_gcp_template_quota.py", ci)


if __name__ == "__main__":
    unittest.main()
