"""Exercise candidate template generation with fake AWS and no cloud access."""

from __future__ import annotations

import base64
import gzip
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class ComputeTests(unittest.TestCase):
    def run_candidate(self, *, bad_signature=False, missing=False, follows_latest=False, wrong_checksum=False, unadmitted=False, bootstrap_mode="legacy"):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            calls = root / "calls.jsonl"
            fake = root / "aws"
            fake.write_text("""#!/usr/bin/env python3
import base64, json, os, sys
a=sys.argv[1:]
with open(os.environ['CALLS'], 'a') as f: f.write(json.dumps(a)+'\\n')
command=a[:2]
if command == ['s3api','head-object']:
    digest=('f'*64 if os.environ['BAD_CHECKSUM']=='1' else os.environ['DIGEST'])
    print(json.dumps({'ContentLength':4,'ChecksumSHA256':base64.b64encode(bytes.fromhex(digest)).decode()}))
elif command == ['ec2','describe-security-groups']:
    print('vpc-test' if 'VpcId' in a[a.index('--query')+1] else 'sg-test')
elif command == ['ec2','describe-subnets']: print('subnet-a\\tsubnet-b')
elif command == ['iam','get-instance-profile']: print('{}')
elif command == ['ec2','describe-launch-templates']: print('lt-test')
elif command == ['autoscaling','describe-auto-scaling-groups']:
    print(json.dumps({'AutoScalingGroups':[{'LaunchTemplate':{'LaunchTemplateId':'lt-test','Version':'$Latest' if os.environ['LATEST']=='1' else '55'}}]}))
elif command == ['ec2','create-launch-template-version']: print('56')
else: sys.exit('Unexpected AWS operation: '+repr(a))
""")
            fake.chmod(0o700)
            # The real admission gate is covered by test_aws_eif_admission.
            # Isolate template tests from public HTTPS and production pin reads.
            python = root / "python3"
            python.write_text(
                "#!" + sys.executable + "\nimport os,sys\n"
                "if sys.argv[1:3] == ['-m','tools.aws_eif_admission']:\n"
                "    sys.exit(int(os.environ['UNADMITTED']))\n"
                "os.execv(" + repr(sys.executable) + ", ["
                + repr(sys.executable) + "] + sys.argv[1:])\n"
            )
            python.chmod(0o700)
            cosign = root / "cosign"
            cosign.write_text("#!/bin/sh\nexit " + ("1\n" if bad_signature else "0\n"))
            cosign.chmod(0o700)
            digest = hashlib.sha256(b"test").hexdigest()
            record = {
                "schema": "trustedrouter.aws-eif.v1", "source_commit": "a" * 40,
                "builder_image": "330422590279.dkr.ecr.eu-west-1.amazonaws.com/quill-enclave-eif-builder@sha256:" + "b" * 64,
                "enclave_image_id": "sha256:" + "c" * 64, "nitro_cli_version": "1.5.3",
                "eif_sha256": digest, "eif_size_bytes": 4,
                "measurements": {"PCR0": "1" * 96, "PCR1": "2" * 96, "PCR2": "3" * 96},
            }
            (root / "manifest.json").write_text(json.dumps(record))
            (root / "signature.json").write_text("{}")
            source = (ROOT / "tools/deploy-aws-nitro.sh").read_text()
            phase = "phase_compute() {" + source.split("phase_compute() {", 1)[1].split("phase_quotas() {", 1)[0]
            script = 'set -euo pipefail\nlog() { printf "%s\\n" "$*" >&2; }\nlatest_ecr_tag() { echo test; }\n' + phase + "\nphase_compute\n"
            env = {**os.environ, "PATH": str(root) + os.pathsep + os.environ["PATH"],
                   "AWS_CONFIG_FILE": "/dev/null", "AWS_SHARED_CREDENTIALS_FILE": "/dev/null", "AWS_EC2_METADATA_DISABLED": "true",
                   "AWS_ACCOUNT": "330422590279", "AWS_REGION": "eu-west-1", "PROJECT_TAG": "quill-enclave",
                   "PARENT_ECR_REPO_NAME": "quill-parent", "PARENT_PUMP_ECR_REPO_NAME": "quill-parent-pump",
                   "SCRIPT_DIR": str(ROOT / "tools"), "AWS_EIF_MANIFEST": "" if missing else str(root / "manifest.json"),
                   "AWS_EIF_SIGNATURE": str(root / "signature.json"), "AWS_EIF_SOURCE_COMMIT": "a" * 40,
                   "CANDIDATE_TEMPLATE_ONLY": "1", "DRY_RUN": "0", "INSTANCE_TYPE": "m5.xlarge",
                   "AWS_BOOTSTRAP_MODE": bootstrap_mode,
                   "TR_CONTROL_PLANE_BASE_URL": "https://trustedrouter.com", "CALLS": str(calls), "DIGEST": digest,
                   "LATEST": str(int(follows_latest)), "BAD_CHECKSUM": str(int(wrong_checksum)),
                   "UNADMITTED": str(int(unadmitted))}
            result = subprocess.run(["bash", "-c", script], env=env, text=True, capture_output=True, timeout=15, check=False)
            return result, [json.loads(line) for line in calls.read_text().splitlines()] if calls.exists() else []

    def test_candidate_is_pinned_and_does_not_change_serving_resources(self):
        result, calls = self.run_candidate()
        self.assertEqual(result.returncode, 0, result.stderr)
        writes = [call for call in calls if call[1].startswith(("create-", "modify-", "update-"))]
        self.assertEqual([call[:2] for call in writes], [["ec2", "create-launch-template-version"]])
        data = json.loads(writes[0][writes[0].index("--launch-template-data") + 1])
        self.assertEqual(data["ImageId"], "ami-00fcaf85b81e85b1d")
        raw = base64.b64decode(data["UserData"])
        user_data = (gzip.decompress(raw) if raw[:2] == b"\x1f\x8b" else raw).decode()
        self.assertIn("aws-nitro-enclaves-cli-1.5.0-0.amzn2023", user_data)
        self.assertIn("QUILL_BOOTSTRAP_MODE=legacy", user_data)
        self.assertIn("sha256sum --check --strict", user_data)
        self.assertIn("stat -c %s /opt/quill/enclave.eif.tmp", user_data)
        self.assertIn("quill-enclave-eif-eu-west-1-330422590279", user_data)
        self.assertNotIn("build-enclave", user_data)
        self.assertNotIn("aws-nitro-enclaves-cli-devel", user_data)
        self.assertLess(user_data.index("sha256sum"), user_data.index("run-enclave --eif-path"))

    def test_missing_or_unverified_manifest_prevents_all_cloud_operations(self):
        for options in ({"missing": True}, {"bad_signature": True}):
            with self.subTest(options=options):
                result, calls = self.run_candidate(**options)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(calls, [])

    def test_wrong_stored_checksum_prevents_mutations(self):
        result, calls = self.run_candidate(wrong_checksum=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual([call[:2] for call in calls], [["s3api", "head-object"]])

    def test_unadmitted_candidate_prevents_all_cloud_operations(self):
        result, calls = self.run_candidate(unadmitted=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(calls, [])

    def test_asg_following_latest_blocks_candidate_version_creation(self):
        result, calls = self.run_candidate(follows_latest=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("candidate isolation refused", result.stderr)
        self.assertFalse(any(call[1].startswith(("create-", "modify-", "update-")) for call in calls))

    def test_attested_parent_requires_configured_keys_before_cloud(self):
        for mode in ("dual", "v2-only", "invalid"):
            result, calls = self.run_candidate(bootstrap_mode=mode)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
