from __future__ import annotations

import base64
import copy
import json
import unittest
from unittest.mock import MagicMock, patch

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from tools import verify_aws_denial_probe as probe


class DenialEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.der = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key().public_bytes(
            Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

    def setUp(self):
        self.instance = "i-0123456789abcdef0"
        self.nonce = bytes(range(32))
        self.measurements = {f"PCR{i}": str(i + 1) * 96 for i in range(3)}
        self.record = {
            "attestation_document": base64.b64encode(b"test-document").decode(),
            "public_key": base64.b64encode(self.der).decode(),
            "nonce": base64.b64encode(self.nonce).decode(),
            "protocol": probe.PROTOCOL.decode(),
        }
        self.payload = {
            "module_id": self.instance + "-enc012abc", "nonce": self.nonce,
            "public_key": self.der, "user_data": probe.PROTOCOL, "timestamp": 1_000_000,
            "pcrs": {i: bytes.fromhex(self.measurements[f"PCR{i}"]) for i in range(3)},
        }
        self.verifier = MagicMock()
        self.verifier.parse_cose_payload.return_value = (self.payload, b"payload")
        self.args = dict(instance=self.instance, nonce=self.nonce, measurements=self.measurements,
                         accepted=["9" * 96], debug=False, now=1000)

    def test_authenticated_unpublished_and_debug_evidence(self):
        for debug in (False, True):
            if debug:
                self.payload["pcrs"] = {i: bytes(48) for i in range(3)}
            with patch.object(probe.aws_bootstrap_probe, "verifier", return_value=self.verifier):
                result = probe.verify(json.dumps(self.record).encode(), **{**self.args, "debug": debug})
            self.assertEqual(result["mode"], "debug" if debug else "unpublished")
            self.assertIn("not a KMS denial result", result["scope"])
            self.assertNotIn("attestation_document", result)
        self.assertEqual(self.verifier.verify_cose_signature.call_count, 2)

    def test_signature_failure_cannot_be_reported_as_evidence(self):
        self.verifier.verify_cose_signature.side_effect = ValueError("signature")
        with patch.object(probe.aws_bootstrap_probe, "verifier", return_value=self.verifier), self.assertRaises(ValueError):
            probe.verify(json.dumps(self.record).encode(), **self.args)
        self.verifier.parse_cose_payload.assert_not_called()

    def test_signed_binding_failures(self):
        for field, wrong in (
            ("module_id", "i-ffffffff-enc123"), ("nonce", bytes(32)), ("public_key", b"other"),
            ("user_data", b"production"), ("timestamp", True), ("timestamp", 800_000),
            ("timestamp", 1_100_000), ("pcrs", {0: bytes(48)}),
        ):
            changed = copy.deepcopy(self.payload)
            changed[field] = wrong
            self.verifier.parse_cose_payload.return_value = (changed, b"payload")
            with self.subTest(field=field), patch.object(probe.aws_bootstrap_probe, "verifier", return_value=self.verifier), self.assertRaises(ValueError):
                probe.verify(json.dumps(self.record).encode(), **self.args)

    def test_invalid_or_serving_expectations_fail_before_verification(self):
        for overrides in (
            {"instance": ""}, {"nonce": b"short"}, {"accepted": []}, {"accepted": ["0" * 96]},
            {"accepted": [self.measurements["PCR0"]]}, {"measurements": {}},
        ):
            with self.subTest(overrides=overrides), patch.object(probe.aws_bootstrap_probe, "verifier") as verify, self.assertRaises(ValueError):
                probe.verify(json.dumps(self.record).encode(), **{**self.args, **overrides})
            verify.assert_not_called()

    def test_bad_frames_and_challenges_fail_before_verification(self):
        for body in (b"", b"x" * ((32 << 10) + 1), b"{}", b'{"nonce":"a","nonce":"b"}',
                     json.dumps({**self.record, "nonce": base64.b64encode(bytes(32)).decode()}).encode(),
                     json.dumps({**self.record, "attestation_document": "!"}).encode()):
            with patch.object(probe.aws_bootstrap_probe, "verifier") as verify, self.assertRaises(ValueError):
                probe.verify(body, **self.args)
            verify.assert_not_called()


if __name__ == "__main__":
    unittest.main()
