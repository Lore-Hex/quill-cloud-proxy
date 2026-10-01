#!/usr/bin/env python3
"""Offline tests for the pinned cross-repository coordinator and gateway binding."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import yaml

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("cloud_rollout_bootstrap", ROOT / "tools/cloud-rollout.py")
bootstrap = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bootstrap)


class BootstrapTests(unittest.TestCase):
    def test_verifies_exact_source_before_execution(self):
        code = b"print('test coordinator')\n"
        pin = {"commit": "a" * 40, "sha256": hashlib.sha256(code).hexdigest()}
        calls = []

        def run(args, **kwargs):
            calls.append(args)
            if args[0] == "gh":
                self.assertTrue(args[-1].endswith("?ref=" + "a" * 40))
                return subprocess.CompletedProcess(args, 0, code)
            self.assertEqual(Path(args[1]).read_bytes(), code)
            self.assertEqual(kwargs["env"]["TR_DEPLOY_COMPONENT"], "gateway")
            return subprocess.CompletedProcess(args, 0)

        with mock.patch.object(bootstrap.Path, "read_text", return_value=json.dumps(pin)), \
             mock.patch.object(bootstrap.subprocess, "run", side_effect=run), \
             mock.patch.object(sys, "argv", ["cloud-rollout.py", "assert", "--cloud", "azure"]):
            self.assertEqual(bootstrap.main(), 0)
        self.assertEqual(len(calls), 2)
        self.assertFalse(Path(calls[1][1]).exists())

    def test_wrong_digest_never_executes_source(self):
        pin = {"commit": "a" * 40, "sha256": "b" * 64}
        with mock.patch.object(bootstrap.Path, "read_text", return_value=json.dumps(pin)), \
             mock.patch.object(bootstrap.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, b"wrong")) as run:
            with self.assertRaisesRegex(RuntimeError, "reviewed pin"):
                bootstrap.main()
            self.assertEqual(run.call_count, 1)

    def test_unreadable_source_never_executes(self):
        with mock.patch.object(bootstrap.subprocess, "run", side_effect=subprocess.CalledProcessError(1, "gh")) as run:
            with self.assertRaises(subprocess.CalledProcessError):
                bootstrap.main()
            self.assertEqual(run.call_count, 1)

    def test_missing_outer_reservation_fails_before_cloud_access(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "called"
            python = Path(directory) / "python3"
            python.write_text(f'#!/bin/sh\ntouch "{marker}"\n')
            python.chmod(0o755)
            env = {k: v for k, v in os.environ.items() if not k.startswith("TR_DEPLOY_")}
            env["PATH"] = directory + os.pathsep + env["PATH"]
            result = subprocess.run(["bash", "-c", 'source "$1"; require_cloud_rollout azure',
                                     "test", str(ROOT / "tools/cloud-rollout-guard.sh")],
                                    env=env, text=True, capture_output=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Missing azure reservation", result.stderr)
            self.assertFalse(marker.exists())

    def test_cloud_argument_is_pinned_by_mutator(self):
        for script, cloud in [("deploy-gcp-mig.sh", "gcp"), ("roll-secondary-region.sh", "gcp"),
                              ("deploy-azure-aci.sh", "azure"), ("deploy-aws-nitro.sh", "aws"),
                              ("aws-trim-to-800.sh", "aws")]:
            with self.subTest(script=script):
                text = (ROOT / "tools" / script).read_text()
                self.assertIn("cloud-rollout-guard.sh", text)
                self.assertIn("require_cloud_rollout " + cloud, text)

    def test_workflow_holds_reservation_until_signed_final_trust_verification(self):
        jobs = yaml.safe_load((ROOT / ".github/workflows/deploy-enclave-gcp.yml").read_text())["jobs"]
        self.assertIn("admit-cloud", jobs["rollout"]["needs"])
        self.assertIn("needs.admit-cloud.outputs.operation", jobs["rollout"]["env"]["TR_DEPLOY_MUTEX_OPERATION"])
        final = jobs["finalize-cloud"]
        self.assertIn("always()", final["if"])
        self.assertIn("verify-final-trust-page", final["needs"])
        self.assertIn("TR_DEPLOY_OUTCOME=failure", final["steps"][-1]["run"])
        self.assertIn("cloud-rollout.py release", final["steps"][-1]["run"])


if __name__ == "__main__":
    unittest.main()
