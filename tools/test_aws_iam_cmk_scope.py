"""Execute the IAM phase with a refusing fake AWS CLI; never contact AWS."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
KEYS = {
    "eu-west-1": "d2535b04-c182-4262-adaa-c9489ce0d196",
    "eu-west-3": "0646cbd6-2687-4561-a7d9-f55aed89d16c",
}


class IAMScopeTests(unittest.TestCase):
    def test_parser_fuzz_gate_has_fixed_work_and_a_hard_watchdog(self):
        jobs = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())["jobs"]
        step = next(item for item in jobs["enclave-go"]["steps"] if item.get("name") == "Fuzz AWS sealed-bootstrap parsers")
        self.assertEqual(step["if"], "matrix.tags == 'cloud_aws,llm_multi'")
        self.assertFalse(step.get("continue-on-error", False))
        self.assertEqual(step["env"]["GOMAXPROCS"], "2")
        commands = [line.strip() for line in step["run"].splitlines() if line.strip() and not line.lstrip().startswith("#")]
        self.assertEqual(commands, [
            f"go test ./internal/bootstrap/awssealed -fuzz={target} -fuzztime=1000000x -parallel=2 -timeout=2m"
            for target in ("FuzzBundleParser", "FuzzCMSParser")
        ])

    def test_mock_policy_checks_are_enforced_by_required_ci(self):
        jobs = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())["jobs"]
        required = jobs["trust-page-validation"]
        self.assertEqual(required["permissions"], {"contents": "read"})
        self.assertNotIn("if", required)
        self.assertFalse(required.get("continue-on-error", False))
        policy = required["steps"][1]  # Immediately after the full checkout.
        self.assertEqual(required["steps"][0]["with"]["fetch-depth"], 0)
        self.assertEqual(policy["working-directory"], "tools/aws-secrets")
        self.assertEqual(policy["timeout-minutes"], 10)
        self.assertNotIn("if", policy)
        self.assertFalse(policy.get("continue-on-error", False))
        self.assertEqual(policy["env"]["AWS_CONFIG_FILE"], "/dev/null")
        self.assertEqual(policy["env"]["AWS_SHARED_CREDENTIALS_FILE"], "/dev/null")
        self.assertEqual(policy["env"]["AWS_EC2_METADATA_DISABLED"], "true")
        commands = policy["run"]
        self.assertIn("sha256sum --check --strict", commands)
        self.assertIn("terraform init -backend=false -input=false -lockfile=readonly", commands)
        self.assertIn("terraform test -no-color", commands)
        self.assertNotIn("terraform apply", commands)
        self.assertIn("terraform fmt -check -recursive", commands)
        self.assertIn("terraform validate -no-color", commands)

    def run_phase(self, failure: str = "success", regions: str = "eu-west-1 eu-west-3"):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            calls = directory / "calls.jsonl"
            fake = directory / "aws"
            fake.write_text("""#!/usr/bin/env python3
import json, os, sys
args = sys.argv[1:]
with open(os.environ['CALLS'], 'a') as stream:
    stream.write(json.dumps(args) + '\\n')
if args[:2] == ['kms', 'list-aliases']:
    region = args[args.index('--region') + 1]
    failure = os.environ['FAILURE']
    if region == 'eu-west-3' and failure != 'success':
        if failure == 'api-error':
            print('AccessDeniedException', file=sys.stderr)
            sys.exit(42)
        print(failure)
    else:
        print(json.loads(os.environ['KEYS'])[region])
elif args[:2] not in [
    ['iam', 'get-role'], ['iam', 'get-instance-profile'],
    ['iam', 'put-role-policy'], ['iam', 'attach-role-policy'],
]:
    sys.exit('unexpected AWS command: ' + repr(args))
""")
            fake.chmod(0o700)
            scripts = directory / "tools"
            config = scripts / "aws-secrets"
            config.mkdir(parents=True)
            shutil.copyfile(ROOT / "tools/aws_kms_admission.py", scripts / "aws_kms_admission.py")
            (config / "attested-release.json").write_text(json.dumps({
                "schema_version": 1, "required": False, "key_arns": {},
            }))
            source = (ROOT / "tools/deploy-aws-nitro.sh").read_text()
            phase = "phase_iam() {" + source.split("phase_iam() {", 1)[1].split("phase_oidc() {", 1)[0]
            script = "set -euo pipefail\nlog() { printf '%s\\n' \"$*\" >&2; }\n" + phase + "phase_iam\n"
            env = {
                **os.environ,
                "PATH": str(directory) + os.pathsep + os.environ["PATH"],
                "AWS_SHARED_CREDENTIALS_FILE": "/dev/null",
                "AWS_CONFIG_FILE": "/dev/null",
                "AWS_EC2_METADATA_DISABLED": "true",
                "PROJECT_TAG": "quill-enclave", "AWS_ACCOUNT": "330422590279",
                "AWS_REGION": "eu-west-3", "DRY_RUN": "0",
                "SCRIPT_DIR": str(scripts),
                "ENCLAVE_REGIONS": regions, "FAILURE": failure,
                "KEYS": json.dumps(KEYS), "CALLS": str(calls),
            }
            result = subprocess.run(["bash", "-c", script], env=env, text=True,
                                    capture_output=True, timeout=10, check=False)
            self.assertTrue(calls.exists(), result.stderr)
            recorded = [json.loads(line) for line in calls.read_text().splitlines()]
            return result, recorded

    def test_only_exact_regional_keys_are_granted(self):
        result, calls = self.run_phase()
        self.assertEqual(result.returncode, 0, result.stderr)
        writes = [args for args in calls if args[:2] == ["iam", "put-role-policy"]]
        self.assertEqual(len(writes), 1)
        policy = json.loads(writes[0][writes[0].index("--policy-document") + 1])
        direct = next(s for s in policy["Statement"] if s["Sid"] == "DecryptCrossCloudSAKeyDirect")
        self.assertEqual(direct["Resource"], [
            f"arn:aws:kms:{region}:330422590279:key/{key}" for region, key in KEYS.items()
        ])
        self.assertNotIn("*", "".join(direct["Resource"]))

    def test_lookup_failure_or_bad_key_never_mutates_iam(self):
        for failure in ("api-error", "", "None", "null", "*", "bad-key",
                        "key/123", "\"injected\"", "a\nb"):
            with self.subTest(failure=failure):
                result, calls = self.run_phase(failure)
                self.assertNotEqual(result.returncode, 0)
                self.assertTrue(all(args[:2] == ["kms", "list-aliases"] for args in calls))

    def test_no_match_fails_before_iam_writes(self):
        result, calls = self.run_phase("None")
        self.assertIn("No wildcard decrypt grant is permitted", result.stderr)
        self.assertEqual(len(calls), 2)

    def test_retired_cross_cloud_rotation_stops_before_any_cloud_call(self):
        source = (ROOT / "tools/deploy-aws-nitro.sh").read_text()
        phase = "phase_cross_cloud_key() {" + source.split("phase_cross_cloud_key() {", 1)[1].split('\ncase "$PHASE" in', 1)[0]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "aws-secrets"
            config.mkdir()
            shutil.copyfile(ROOT / "tools/aws_kms_admission.py", root / "aws_kms_admission.py")
            (config / "attested-release.json").write_text(json.dumps({
                "schema_version": 1, "required": True,
                "key_arns": {region: f"arn:aws:kms:{region}:330422590279:key/{key}"
                             for region, key in KEYS.items()},
            }))
            script = ("set -euo pipefail\nlog() { :; }\n"
                      "aws() { echo unexpected-cloud-call >&2; return 97; }\n"
                      "gcloud() { echo unexpected-cloud-call >&2; return 97; }\n"
                      + phase + "\nphase_cross_cloud_key\n")
            result = subprocess.run(["bash", "-c", script], capture_output=True, text=True,
                timeout=10, env={**os.environ, "SCRIPT_DIR": str(root), "PHASE": "cross-cloud-key"})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("legacy IAM provisioner is retired", result.stderr)
        self.assertNotIn("unexpected-cloud-call", result.stderr)


if __name__ == "__main__":
    unittest.main()
