from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class BundleReplicationTests(unittest.TestCase):
    def test_legacy_sync_refuses_active_attested_keys_before_cloud_access(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("sync-secrets-to-aws.sh", "aws_kms_admission.py"):
                shutil.copyfile(ROOT / "tools" / name, root / name)
            config = root / "aws-secrets"
            config.mkdir()
            (config / "attested-release.json").write_text(json.dumps({
                "schema_version": 1, "required": True, "key_arns": {
                    region: f"arn:aws:kms:{region}:330422590279:key/11111111-1111-1111-1111-111111111111"
                    for region in ("eu-west-1", "eu-west-3")
                },
            }))
            calls = root / "calls"
            for name in ("aws", "gcloud", "curl", "uv"):
                stub = root / name
                stub.write_text('#!/bin/sh\nprintf "%s\\n" "$0" >> "$CALLS"\nexit 99\n')
                stub.chmod(0o700)
            env = {"PATH": str(root) + os.pathsep + os.environ["PATH"], "CALLS": str(calls),
                   "AWS_CONFIG_FILE": "/dev/null", "AWS_SHARED_CREDENTIALS_FILE": "/dev/null",
                   "AWS_EC2_METADATA_DISABLED": "true"}
            result = subprocess.run(["bash", str(root / "sync-secrets-to-aws.sh"), "--apply"],
                                    env=env, text=True, capture_output=True, check=False, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("legacy IAM provisioner is retired", result.stderr)
            self.assertFalse(calls.exists(), "retired publisher reached a cloud/tool command")

    def test_regional_bundle_is_never_replicated_even_with_empty_skip_override(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            calls = root / "calls.jsonl"
            aws = root / "aws"
            aws.write_text("""#!/usr/bin/env python3
import json,os,sys
a=sys.argv[1:]
with open(os.environ['CALLS'],'a') as f: f.write(json.dumps(a)+'\\n')
if a[:2] == ['secretsmanager','list-secrets']:
    query=a[a.index('--query')+1]
    if query == 'SecretList[].Name': print('quill/attested-bootstrap-v2\\tquill/ordinary')
    elif query == 'length(SecretList)': print('2')
    else: print('')
elif a[:2] == ['secretsmanager','replicate-secret-to-regions']: print('InSync')
else: sys.exit('unexpected AWS operation')
""")
            aws.chmod(0o700)
            sleep = root / "sleep"
            sleep.write_text("#!/bin/sh\nexit 0\n")
            sleep.chmod(0o700)
            env = {**os.environ, "PATH": str(root) + os.pathsep + os.environ["PATH"],
                   "AWS_CONFIG_FILE": "/dev/null", "AWS_SHARED_CREDENTIALS_FILE": "/dev/null",
                   "AWS_EC2_METADATA_DISABLED": "true", "SKIP": "", "CALLS": str(calls)}
            result = subprocess.run(["bash", str(ROOT / "tools/replicate-secrets-to-region.sh"), "--apply"],
                                    env=env, text=True, capture_output=True, check=False, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            written = [json.loads(line) for line in calls.read_text().splitlines()
                       if "replicate-secret-to-regions" in line]
            self.assertEqual(len(written), 1)
            self.assertEqual(written[0][written[0].index("--secret-id") + 1], "quill/ordinary")
            self.assertIn("independently sealed per region", result.stdout)


if __name__ == "__main__":
    unittest.main()
