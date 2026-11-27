import unittest
from pathlib import Path
from unittest.mock import patch

from tools import check_gcp_tls_admission as gate


class TLSAdmissionTests(unittest.TestCase):
    digest = "sha256:" + "a" * 64

    def setUp(self):
        self.member = gate.PRINCIPAL + self.digest
        self.bucket = {"bindings": [{"role": "roles/storage.objectUser", "members": [self.member],
                                     "condition": {"expression": gate.OBJECTS}}]}
        self.key = {"bindings": [{"role": "roles/cloudkms.cryptoKeyEncrypterDecrypter",
                                  "members": [self.member]}]}

    def check(self):
        with patch.object(gate, "policy", side_effect=[self.bucket, self.key]):
            gate.check(self.digest)

    def test_exact_pair(self):
        self.check()

    def test_missing_either(self):
        for resource in (self.bucket, self.key):
            with self.subTest(resource=resource), patch.dict(resource, bindings=[]):
                with self.assertRaisesRegex(ValueError, "missing reviewed TLS binding"):
                    self.check()

    def test_no_other_image_or_pool_or_wider_role(self):
        for member in (gate.PRINCIPAL + "sha256:" + "b" * 64, gate.PRINCIPAL + "*"):
            with patch.dict(self.key["bindings"][0], members=[member]):
                with self.assertRaisesRegex(ValueError, gate.KEY):
                    self.check()
        with patch.dict(self.bucket["bindings"][0], role="roles/storage.admin"):
            with self.assertRaisesRegex(ValueError, gate.BUCKET):
                self.check()

    def test_require_reviewed_resource_scope(self):
        for expression in ("true", gate.OBJECTS + " || true", ""):
            with patch.dict(self.bucket["bindings"][0], condition={"expression": expression}):
                with self.assertRaisesRegex(ValueError, gate.BUCKET):
                    self.check()
        with patch.dict(self.key["bindings"][0], condition={"expression": "false"}):
            with self.assertRaisesRegex(ValueError, gate.KEY):
                self.check()

    def test_tag_rejected_without_cloud_call(self):
        with patch.object(gate, "policy") as read, self.assertRaises(ValueError):
            gate.check("latest")
        read.assert_not_called()

    def test_before_lease_not_after_drain(self):
        root = Path(__file__).resolve().parents[1]
        workflow = (root / ".github/workflows/deploy-enclave-gcp.yml").read_text()
        admit = workflow.split("\n  admit-cloud:\n", 1)[1].split("\n  rollout:\n", 1)[0]
        self.assertLess(admit.index("tools/check_gcp_tls_admission.py"), admit.index("cloud-rollout.py acquire"))
