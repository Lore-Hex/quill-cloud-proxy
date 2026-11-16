from __future__ import annotations

import json
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from tools import aws_bootstrap_probe as probe

PCR = "1" * 96
INSTANCE = "i-0123456789abcdef0"
EVIDENCE = {"policy": "transition", "mode": "attested", "bundle_version": 1}
LEGACY_EVIDENCE = {"policy": "transition", "mode": "legacy", "bundle_version": 0}


class BootstrapProbeTests(unittest.TestCase):
    def test_shared_go_health_wire_contract(self):
        path = Path(__file__).resolve().parents[1] / "enclave-go/internal/types/testdata/aws_bootstrap_health.json"
        bodies = json.loads(path.read_text())
        self.assertEqual(len(bodies), 3)
        for body in bodies:
            evidence = body["aws_bootstrap"]
            version = evidence.get("bundle_version", 0)
            expected = {**evidence, "bundle_version": version}
            self.assertEqual(
                probe.validate_health(json.dumps(body).encode(), evidence["policy"], version, mode=evidence["mode"]),
                expected,
            )

    def test_omitted_version_is_only_valid_for_explicit_transitional_legacy(self):
        valid = {"status": "ok", "aws_bootstrap": {"policy": "transition", "mode": "legacy"}}
        self.assertEqual(probe.validate_health(json.dumps(valid).encode(), "transition", 0, mode="legacy"), LEGACY_EVIDENCE)
        for evidence in (
            {"policy": "transition", "mode": "attested"},
            {"policy": "strict", "mode": "attested"},
            {"policy": "strict", "mode": "legacy"},
            {"policy": "transition", "mode": "legacy", "extra": 0},
            {"policy": "transition", "mode": "legacy", "bundle_version": None},
            {"policy": "transition", "mode": "legacy", "bundle_version": False},
            {"policy": "transition", "mode": "legacy", "bundle_version": 1},
        ):
            body = json.dumps({"status": "ok", "aws_bootstrap": evidence}).encode()
            for policy, mode, version in (("transition", "legacy", 0), ("transition", "attested", 1), ("strict", "attested", 1)):
                with self.subTest(evidence=evidence, policy=policy, mode=mode), self.assertRaises(ValueError):
                    probe.validate_health(body, policy, version, mode=mode)

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

    def test_legacy_expectation_is_explicit_and_never_strict(self):
        body = json.dumps({"status": "ok", "aws_bootstrap": LEGACY_EVIDENCE}).encode()
        self.assertEqual(probe.validate_health(body, "transition", 0, mode="legacy"), LEGACY_EVIDENCE)
        for policy, version, mode in (
            ("transition", 1, "attested"), ("transition", 0, "attested"),
            ("strict", 0, "legacy"), ("transition", 1, "legacy"),
            ("transition", False, "legacy"),
        ):
            with self.subTest(policy=policy, version=version, mode=mode), self.assertRaises(ValueError):
                probe.validate_health(body, policy, version, mode=mode)
        attested = json.dumps({"status": "ok", "aws_bootstrap": EVIDENCE}).encode()
        with self.assertRaises(ValueError):
            probe.validate_health(attested, "transition", 0, mode="legacy")

    def fake_verifier(self, evidence=EVIDENCE):
        verify = MagicMock()
        verify.attach_mock(MagicMock(), "assert_tls13")
        verify.attach_mock(MagicMock(), "assert_cert_matches_hostname")
        verify.parse_cose_payload.return_value = ({"module_id": INSTANCE + "-enc01abc"}, b"cose")
        verify._read_http_response.side_effect = [
            ("HTTP/1.1 200 OK", {}, b"signed-attestation"),
            ("HTTP/1.1 200 OK", {}, json.dumps({"status": "ok", "aws_bootstrap": evidence}).encode()),
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

    def test_legacy_check_still_requires_full_instance_and_tls_verification(self):
        for failure in (None, "nonce", "signature", "instance"):
            with self.subTest(failure=failure):
                verify = self.fake_verifier(LEGACY_EVIDENCE)
                if failure == "nonce":
                    verify._require_attestation_body_binds_exporter.side_effect = SystemExit("nonce")
                elif failure == "signature":
                    verify.verify_aws_cbor.side_effect = SystemExit("signature")
                elif failure == "instance":
                    verify.parse_cose_payload.return_value = ({"module_id": "i-ffffffff-enc01abc"}, b"cose")
                with patch.object(probe, "verifier", return_value=verify), patch.object(probe.socket, "create_connection"):
                    if failure:
                        with self.assertRaises((ValueError, SystemExit)):
                            probe.probe(pcr0=PCR, instance=INSTANCE, port=18444, policy="transition", version=0, mode="legacy")
                        self.assertEqual(verify._ssl_send_all.call_count, 1)
                    else:
                        result = probe.probe(pcr0=PCR, instance=INSTANCE, port=18444, policy="transition", version=0, mode="legacy")
                        self.assertEqual(result["bootstrap"], LEGACY_EVIDENCE)
                        verify.verify_aws_cbor.assert_called_once()
                        first, second = verify._ssl_send_all.call_args_list
                        self.assertIs(first.args[1], second.args[1])
                        names = [call[0] for call in verify.mock_calls]
                        sends = [i for i, name in enumerate(names) if name == "_ssl_send_all"]
                        self.assertLess(names.index("verify_aws_cbor"), sends[1])

    def test_invalid_expectations_make_no_connection(self):
        valid = dict(pcr0=PCR, instance=INSTANCE, port=18444, policy="transition", version=1)
        with patch.object(probe.socket, "create_connection") as connect:
            for override in (
                {"pcr0": "0" * 96}, {"pcr0": "bad"}, {"instance": ""}, {"port": 0},
                {"policy": "legacy"}, {"version": 0}, {"version": True}, {"mode": "unknown"},
                {"mode": "legacy"}, {"mode": "legacy", "version": 0, "policy": "strict"},
            ):
                with self.assertRaises(ValueError):
                    probe.probe(**{**valid, **override})
            connect.assert_not_called()


if __name__ == "__main__":
    unittest.main()
