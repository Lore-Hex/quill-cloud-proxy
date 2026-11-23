import io
import json
import types
import unittest
from unittest.mock import Mock, patch

from tools import check_nito_ehbp as audit


class NitoEHBPTest(unittest.TestCase):
    model = "openai/gpt-oss-120b:encrypted"

    def test_proof_stops_before_opening_socket_on_unknown_identity(self):
        for protocol, fmt, native in [
            ("chat-fields-v1", "tinfoil-verification-document-v1", "gpt-oss-120b"),
            ("ehbp-v1", "unknown", "gpt-oss-120b"),
            ("ehbp-v1", "tinfoil-verification-document-v1", "other"),
        ]:
            binding = {"proof_format": fmt, "provider_model_id": native}
            with patch.object(audit, "fetch", return_value=(b"{}", None)), \
                 patch.object(audit, "open_binding", return_value=(protocol, binding)), \
                 patch.object(audit.subprocess, "run") as verify, \
                 patch.object(audit.socket, "create_connection") as dial:
                with self.assertRaises(audit.CheckFailed):
                    audit.prove(self.model, "test", "verifier", "digest")
                verify.assert_not_called()
                dial.assert_not_called()

    def test_failed_verifier_never_contacts_claimed_enclave(self):
        e = json.dumps({"evidence": {"verification": {"enclave_host": "unverified.invalid"}}})
        binding = {"provider_model_id": "gpt-oss-120b", "proof_format": "tinfoil-verification-document-v1"}
        with patch.object(audit, "fetch", return_value=(e, None)), \
             patch.object(audit, "open_binding", return_value=("ehbp-v1", binding)), \
             patch.object(audit.subprocess, "run", return_value=types.SimpleNamespace(returncode=1)), \
             patch.object(audit.socket, "create_connection") as dial:
            with self.assertRaises(audit.CheckFailed):
                audit.prove(self.model, "test", "verifier", "digest")
            dial.assert_not_called()

    def test_failed_proof_never_sends_inference(self):
        argv = ["check", self.model, "--verifier", "v", "--release-digest", "d", "--canary"]
        with patch("sys.argv", argv), patch.dict("os.environ", {"NITO_API_KEY": "test"}), \
             patch.object(audit, "prove", side_effect=audit.CheckFailed("invalid evidence")), \
             patch.object(audit, "canary") as inference:
            with self.assertRaises(SystemExit):
                audit.main()
            inference.assert_not_called()

    def test_denial_is_redacted_and_not_retried(self):
        conn = Mock()
        resp = conn.getresponse.return_value
        resp.status = 403
        resp.read = io.BytesIO(b'{"error":{"code":"forbidden","message":"private response body"}}').read
        resp.getheader.return_value = "synthetic_trace"
        with patch.object(audit.http.client, "HTTPSConnection", return_value=conn):
            with self.assertRaises(audit.CheckFailed) as ctx:
                audit.fetch("POST", "/example", "test", {}, b"synthetic")
        self.assertEqual(str(ctx.exception), "upstream HTTP 403, code=forbidden, request_id=synthetic_trace")
        conn.request.assert_called_once()
        conn.close.assert_called_once()

    def test_reply_requires_authenticated_body_model_challenge_and_usage(self):
        token, headers = Mock(), Mock()
        for values in (None, ["aa", "bb"]):
            headers.get_all.return_value = values
            with self.assertRaises(audit.CheckFailed):
                audit.check_reply(token, b"{}", headers, "native", "answer")
        token.decrypt_response_body.assert_not_called()
        headers.get_all.return_value = ["a0" * 32]
        good = {"model": "native", "choices": [{"message": {"content": "answer"}}],
                "usage": {"prompt_tokens": 1, "completion_tokens": 2, "total_tokens": 3}}
        for bad in ({"model": "wrong"}, {"choices": [{"message": {"content": "stale"}}]},
                    {"usage": {"prompt_tokens": 1, "completion_tokens": True, "total_tokens": 2}}):
            token.decrypt_response_body.return_value = json.dumps({**good, **bad})
            with self.assertRaises(audit.CheckFailed):
                audit.check_reply(token, b"ciphertext", headers, "native", "answer")
        token.decrypt_response_body.return_value = json.dumps(good)
        audit.check_reply(token, b"ciphertext", headers, "native", "answer")
        token.decrypt_response_body.side_effect = ValueError("unauthenticated")
        with self.assertRaises(ValueError):
            audit.check_reply(token, json.dumps(good).encode(), headers, "native", "answer")
