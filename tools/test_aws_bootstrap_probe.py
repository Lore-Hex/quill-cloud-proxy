from __future__ import annotations

import json
import unittest
from unittest.mock import MagicMock, patch

from tools import aws_bootstrap_probe as probe

PCR = "1" * 96
INSTANCE = "i-0123456789abcdef0"
EVIDENCE = {"policy": "transition", "mode": "attested", "bundle_version": 1}


class BootstrapProbeTests(unittest.TestCase):
    def test_health_rejects_missing_forged_legacy_and_wrong_versions(self):
        valid = {"status": "ok", "aws_bootstrap": EVIDENCE}
        self.assertEqual(probe.validate_health(json.dumps(valid).encode(), "transition", 1), EVIDENCE)
        for value in (
            {}, {"status": "ok"}, {**valid, "status": "down"},
            {**valid, "aws_bootstrap": {**EVIDENCE, "mode": "legacy"}},
            {**valid, "aws_bootstrap": {**EVIDENCE, "policy": "strict"}},
            {**valid, "aws_bootstrap": {**EVIDENCE, "bundle_version": 2}},
            {**valid, "aws_bootstrap": {**EVIDENCE, "bundle_version": True}},
            {**valid, "aws_bootstrap": {**EVIDENCE, "unexpected": "value"}},
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                probe.validate_health(json.dumps(value).encode(), "transition", 1)
        for raw in (b"x" * (16384 + 1), b'{"status":"down","status":"ok"}', b"null"):
            with self.assertRaises(ValueError):
                probe.validate_health(raw, "transition", 1)

    def fake_verifier(self):
        verify = MagicMock()
        verify.attach_mock(MagicMock(), "assert_tls13")
        verify.attach_mock(MagicMock(), "assert_cert_matches_hostname")
        verify.parse_cose_payload.return_value = ({"module_id": INSTANCE + "-enc01abc"}, b"cose")
        verify._read_http_response.side_effect = [
            ("HTTP/1.1 200 OK", {}, b"signed-attestation"),
            ("HTTP/1.1 200 OK", {}, json.dumps({"status": "ok", "aws_bootstrap": EVIDENCE}).encode()),
        ]
        return verify

    def run_probe(self):
        return probe.probe(pcr0=PCR, instance=INSTANCE, port=18444, policy="transition", version=1)

    def test_health_follows_full_verification_on_same_socket(self):
        verify = self.fake_verifier()
        with patch.object(probe, "verifier", return_value=verify), patch.object(probe.socket, "create_connection") as connect:
            result = self.run_probe()
        self.assertEqual(result["bootstrap"], EVIDENCE)
        connect.assert_called_once_with(("127.0.0.1", 18444), timeout=10)
        verify.SSL.Connection.assert_called_once()
        verify.assert_tls13.assert_called_once()
        verify._require_attestation_body_binds_exporter.assert_called_once()
        verify.verify_aws_cbor.assert_called_once()
        self.assertEqual(verify.verify_aws_cbor.call_args.kwargs["expected_pcr0"], PCR)
        names = [call[0] for call in verify.mock_calls]
        verified = names.index("verify_aws_cbor")
        sends = [i for i, name in enumerate(names) if name == "_ssl_send_all"]
        self.assertEqual(len(sends), 2)
        self.assertLess(sends[0], verified)
        self.assertLess(verified, sends[1])
        first, second = verify._ssl_send_all.call_args_list
        self.assertIs(first.args[1], second.args[1])
        self.assertTrue(second.args[2].startswith(b"GET /health HTTP/1.1\r\n"))
        verify.SSL.Connection.return_value.close.assert_called_once()

    def test_bad_attestation_nonce_or_wrong_instance_prevents_health_read(self):
        for failure in ("nonce", "signature", "instance"):
            with self.subTest(failure=failure):
                verify = self.fake_verifier()
                if failure == "nonce":
                    verify._require_attestation_body_binds_exporter.side_effect = SystemExit("nonce")
                elif failure == "signature":
                    verify.verify_aws_cbor.side_effect = SystemExit("signature")
                else:
                    verify.parse_cose_payload.return_value = ({"module_id": "i-ffffffff-enc01abc"}, b"cose")
                with patch.object(probe, "verifier", return_value=verify), patch.object(probe.socket, "create_connection"), self.assertRaises((ValueError, SystemExit)):
                    self.run_probe()
                self.assertEqual(verify._ssl_send_all.call_count, 1)
                verify.SSL.Connection.return_value.close.assert_called_once()

    def test_invalid_expectations_make_no_connection(self):
        valid = dict(pcr0=PCR, instance=INSTANCE, port=18444, policy="transition", version=1)
        with patch.object(probe.socket, "create_connection") as connect:
            for override in ({"pcr0": "0" * 96}, {"pcr0": "bad"}, {"instance": ""}, {"port": 0}, {"policy": "legacy"}, {"version": 0}, {"version": True}):
                with self.assertRaises(ValueError):
                    probe.probe(**{**valid, **override})
            connect.assert_not_called()


if __name__ == "__main__":
    unittest.main()
