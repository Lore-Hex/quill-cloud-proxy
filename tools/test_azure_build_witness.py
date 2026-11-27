import base64
import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools import azure_build_witness as witness
from tools.gateway_trust_pr import allowed


class BuildWitnessTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.work = Path(tmp.name)
        self.sha = "a" * 40
        digest = "sha256:" + "b" * 64
        policy = b"synthetic policy"
        self.region = dict(source_commit=self.sha, image_build_commit=self.sha, image_digest=digest,
                           hostdata=hashlib.sha256(policy).hexdigest(),
                           origin_hostname="test.uaenorth.azurecontainer.io")
        props = {"ipAddress": {"dnsNameLabel": "test"},
                 "confidentialComputeProperties": {"ccePolicy": base64.b64encode(policy).decode()},
                 "containers": [{"name": "quill-enclave", "properties": {"image": "test@" + digest,
                                 "environmentVariables": [{"name": "PRIVATE", "value": "not for publication"}]}}]}
        template = {"resources": [{"type": "Microsoft.ContainerInstance/containerGroups",
                                   "location": "uaenorth", "properties": props}]}
        for name, value in [("template.json", json.dumps(template)), ("image-digest.txt", digest),
                            ("build-commit.txt", self.sha), ("template-build-commit.txt", self.sha)]:
            (self.work / name).write_text(value)

    def test_only_public_identifiers_are_signed(self):
        value = witness.create(self.work, self.region, self.sha)
        self.assertEqual(set(value), set(witness.FIELDS))
        self.assertNotIn("PRIVATE", json.dumps(value))
        path = witness.path_for(self.work, value)
        path.parent.mkdir()
        path.write_text(json.dumps(value))
        with patch.object(subprocess, "run", autospec=True) as run:
            witness.verify(self.work, self.region)
            argv = run.call_args.args[0]
            self.assertIn(witness.IDENTITY, argv)
            self.assertIn(witness.ISSUER, argv)
            self.assertTrue(run.call_args.kwargs["check"])
            run.side_effect = subprocess.CalledProcessError(1, argv)
            with self.assertRaises(subprocess.CalledProcessError):
                witness.verify(self.work, self.region)

    def test_reject_mismatched_build(self):
        for name, bad in (("source_commit", "c"*40), ("image_build_commit", "c"*40),
                          ("origin_hostname", "other.uaenorth.azurecontainer.io"),
                          ("image_digest", "sha256:"+"c"*64), ("hostdata", "c"*64)):
            with self.subTest(name=name), self.assertRaises(ValueError):
                witness.create(self.work, dict(self.region, **{name: bad}), self.sha)

    def test_legacy_exception_is_exact(self):
        for row in witness.LEGACY:
            legacy = dict(zip(witness.FIELDS, row), image_build_commit=row[1])
            self.assertIn("operator assertion", witness.verify(self.work, legacy))
            with self.assertRaises(FileNotFoundError):
                witness.verify(self.work, dict(legacy, hostdata="0"*64))

    def test_bot_path_scope(self):
        path = "trust-page/trust/azure-builds/" + "a"*64 + ".json"
        self.assertTrue(allowed("azure", path + ".bundle"))
        self.assertFalse(allowed("azure", path + ".sh"))
        self.assertFalse(allowed("aws", path))
