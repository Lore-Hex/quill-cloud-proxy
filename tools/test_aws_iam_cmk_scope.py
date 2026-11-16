"""Execute the IAM phase with a refusing fake AWS CLI; never contact AWS."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
KEYS = {
    "eu-west-1": "d2535b04-c182-4262-adaa-c9489ce0d196",
    "eu-west-3": "0646cbd6-2687-4561-a7d9-f55aed89d16c",
}


class IAMScopeTests(unittest.TestCase):
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
                "ENCLAVE_REGIONS": regions, "FAILURE": failure,
                "KEYS": json.dumps(KEYS), "CALLS": str(calls),
            }
            result = subprocess.run(["bash", "-c", script], env=env, text=True,
                                    capture_output=True, timeout=10)
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


if __name__ == "__main__":
    unittest.main()
