from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools" / "verify-stage-d-stream.py"
DATA = ROOT / "tools" / "testdata"
SPEC = importlib.util.spec_from_file_location("verify_stage_d_stream", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
stream = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(stream)


class StageDStreamTests(unittest.TestCase):
    def test_accepts_done_terminal(self) -> None:
        stream.validate_stream((DATA / "stage-d-stream-done.sse").read_bytes())

    def test_accepts_finish_reason_terminal(self) -> None:
        stream.validate_stream(
            (DATA / "stage-d-stream-finish-reason.sse").read_bytes()
        )

    def test_rejects_missing_sse_first_byte_and_missing_terminal(self) -> None:
        with self.assertRaisesRegex(ValueError, "begin with an SSE"):
            stream.validate_stream((DATA / "stage-d-stream-not-sse.txt").read_bytes())
        with self.assertRaisesRegex(ValueError, "no .* terminal"):
            stream.validate_stream(
                (DATA / "stage-d-stream-no-terminal.sse").read_bytes()
            )

    def evidence(self, name: str) -> object:
        return json.loads((DATA / name).read_text(encoding="utf-8"))

    def test_literal_evidence_fixture_bytes(self) -> None:
        import hashlib

        digest = hashlib.sha256(
            (DATA / "stage-d-evidence-lookup.json").read_bytes()
        ).hexdigest()
        self.assertEqual(
            digest,
            "e44d18cd36d390da041d51b427cbac4e98d28a0316059529948516bd568e4eb0",
        )

    def test_literal_evidence_fixture_on_requires_matching_boot_and_heartbeat(self) -> None:
        evidence = self.evidence("stage-d-evidence-lookup.json")
        stream.validate_evidence(
            evidence,
            expected_gateway_request_id="rlog_00112233445566778899aabbccddeeff",
            expected_boot_kid="gcp-b1c0f84d-0001",
            require_stage_d=True,
            probe_key_in_use=True,
        )
        with self.assertRaisesRegex(ValueError, "boot kid"):
            stream.validate_evidence(
                evidence,
                expected_gateway_request_id="rlog_00112233445566778899aabbccddeeff",
                expected_boot_kid="another-boot",
                require_stage_d=True,
                probe_key_in_use=True,
            )
        no_heartbeat = copy.deepcopy(evidence)
        no_heartbeat["data"]["heartbeat_seq"] = 0
        with self.assertRaisesRegex(ValueError, "heartbeat"):
            stream.validate_evidence(
                no_heartbeat,
                expected_gateway_request_id="rlog_00112233445566778899aabbccddeeff",
                expected_boot_kid="gcp-b1c0f84d-0001",
                require_stage_d=True,
                probe_key_in_use=True,
            )

    def test_evidence_off_requires_settled_and_key_appropriate_kind(self) -> None:
        evidence = self.evidence("stage-d-evidence-lookup.json")
        evidence["data"]["stage_d_boot_kid"] = None
        evidence["data"]["heartbeat_seq"] = None
        stream.validate_evidence(
            evidence,
            expected_gateway_request_id="rlog_00112233445566778899aabbccddeeff",
            expected_boot_kid="",
            require_stage_d=False,
            probe_key_in_use=True,
        )
        stream.validate_evidence(
            evidence,
            expected_gateway_request_id="rlog_00112233445566778899aabbccddeeff",
            expected_boot_kid="",
            require_stage_d=False,
            probe_key_in_use=False,
        )
        evidence["data"]["settled"] = False
        with self.assertRaisesRegex(ValueError, "not settled"):
            stream.validate_evidence(
                evidence,
                expected_gateway_request_id="rlog_00112233445566778899aabbccddeeff",
                expected_boot_kid="",
                require_stage_d=False,
                probe_key_in_use=True,
            )
        evidence["data"]["settled"] = True
        regional = self.evidence("stage-d-evidence-regional-quota.json")
        stream.validate_evidence(
            regional,
            expected_gateway_request_id="rlog_00112233445566778899aabbccddeeff",
            expected_boot_kid="",
            require_stage_d=False,
            probe_key_in_use=False,
        )
        with self.assertRaisesRegex(ValueError, "local-typed"):
            stream.validate_evidence(
                regional,
                expected_gateway_request_id="rlog_00112233445566778899aabbccddeeff",
                expected_boot_kid="",
                require_stage_d=False,
                probe_key_in_use=True,
            )
        regional["data"]["authorization_kind"] = "legacy"
        with self.assertRaisesRegex(ValueError, "regional-lease"):
            stream.validate_evidence(
                regional,
                expected_gateway_request_id="rlog_00112233445566778899aabbccddeeff",
                expected_boot_kid="",
                require_stage_d=False,
                probe_key_in_use=False,
            )

    def test_evidence_rejects_aliases_and_nonliteral_keys(self) -> None:
        evidence = self.evidence("stage-d-evidence-lookup.json")
        evidence["data"]["kind"] = evidence["data"].pop("authorization_kind")
        with self.assertRaisesRegex(ValueError, "literal contract"):
            stream.validate_evidence(
                evidence,
                expected_gateway_request_id="rlog_00112233445566778899aabbccddeeff",
                expected_boot_kid="gcp-b1c0f84d-0001",
                require_stage_d=True,
                probe_key_in_use=True,
            )

    def test_evidence_rejects_bare_hex_authorization_id(self) -> None:
        evidence = self.evidence("stage-d-evidence-lookup.json")
        evidence["data"]["authorization_id"] = "0123456789abcdef0123456789abcdef"
        with self.assertRaisesRegex(ValueError, "invalid authorization_id"):
            stream.validate_evidence(
                evidence,
                expected_gateway_request_id="rlog_00112233445566778899aabbccddeeff",
                expected_boot_kid="gcp-b1c0f84d-0001",
                require_stage_d=True,
                probe_key_in_use=True,
            )


if __name__ == "__main__":
    unittest.main()
