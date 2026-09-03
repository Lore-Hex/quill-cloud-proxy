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
            "2bc7b029a6047752f6760a06d8bdab551dc52db2943087f864aad6acdf882b41",
        )

    def test_literal_evidence_fixture_on_requires_matching_boot_and_heartbeat(self) -> None:
        evidence = self.evidence("stage-d-evidence-lookup.json")
        stream.validate_evidence(
            evidence,
            expected_gateway_request_id="rlog_00112233445566778899aabbccddeeff",
            expected_boot_kid="gcp-b1c0f84d-0001",
            require_stage_d=True,
        )
        with self.assertRaisesRegex(ValueError, "boot kid"):
            stream.validate_evidence(
                evidence,
                expected_gateway_request_id="rlog_00112233445566778899aabbccddeeff",
                expected_boot_kid="another-boot",
                require_stage_d=True,
            )
        no_heartbeat = copy.deepcopy(evidence)
        no_heartbeat["data"]["heartbeat_seq"] = 0
        with self.assertRaisesRegex(ValueError, "heartbeat"):
            stream.validate_evidence(
                no_heartbeat,
                expected_gateway_request_id="rlog_00112233445566778899aabbccddeeff",
                expected_boot_kid="gcp-b1c0f84d-0001",
                require_stage_d=True,
            )

    def test_evidence_off_requires_settled_and_exact_local_typed_kind_only(self) -> None:
        evidence = self.evidence("stage-d-evidence-lookup.json")
        evidence["data"]["stage_d_boot_kid"] = None
        evidence["data"]["heartbeat_seq"] = None
        stream.validate_evidence(
            evidence,
            expected_gateway_request_id="rlog_00112233445566778899aabbccddeeff",
            expected_boot_kid="",
            require_stage_d=False,
        )
        evidence["data"]["settled"] = False
        with self.assertRaisesRegex(ValueError, "not settled"):
            stream.validate_evidence(
                evidence,
                expected_gateway_request_id="rlog_00112233445566778899aabbccddeeff",
                expected_boot_kid="",
                require_stage_d=False,
            )
        evidence["data"]["settled"] = True
        for wrong_kind in ("regional_lease", "legacy"):
            with self.subTest(wrong_kind=wrong_kind):
                evidence["data"]["authorization_kind"] = wrong_kind
                with self.assertRaisesRegex(ValueError, "local-typed"):
                    stream.validate_evidence(
                        evidence,
                        expected_gateway_request_id="rlog_00112233445566778899aabbccddeeff",
                        expected_boot_kid="",
                        require_stage_d=False,
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
            )


if __name__ == "__main__":
    unittest.main()
