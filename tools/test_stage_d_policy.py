#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools" / "write-stage-d-policy.py"
FIXTURE = ROOT / "tools" / "testdata" / "stage-d-accepted.json"
SPEC = importlib.util.spec_from_file_location("write_stage_d_policy", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
policy = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(policy)

DIGEST_A = "sha256:8ce7f0f3" + "0" * 54 + "aa"
DIGEST_B = "sha256:b1c0f84d" + "0" * 54 + "bb"
DIGEST_C = "sha256:" + "c" * 64


class StageDPolicyTests(unittest.TestCase):
    def test_transitional_union_is_sorted_and_unique(self) -> None:
        previous = {
            "schema": policy.SCHEMA,
            "plane": policy.PLANE,
            "sequence": 1199,
            "kind": "final",
            "issued_at": "2026-09-03T20:00:00Z",
            "image_digests": [DIGEST_B],
        }
        result = policy.build_policy(
            github_run_number=600,
            kind="transitional",
            issued_at="2026-09-03T21:30:00Z",
            incoming_digest=DIGEST_A,
            accepted_policies=[previous],
            running_digests=[DIGEST_C, DIGEST_B, f"{DIGEST_A},{DIGEST_C}"],
        )

        self.assertEqual(result["image_digests"], sorted([DIGEST_A, DIGEST_B, DIGEST_C]))

    def test_sequence_arithmetic(self) -> None:
        self.assertEqual(policy.release_sequence(600, "transitional"), 1200)
        self.assertEqual(policy.release_sequence(600, "final"), 1201)

    def test_fixed_input_is_byte_equal_to_cross_repo_fixture(self) -> None:
        previous = {
            "schema": policy.SCHEMA,
            "plane": policy.PLANE,
            "sequence": 1199,
            "kind": "final",
            "issued_at": "2026-09-03T20:00:00Z",
            "image_digests": [DIGEST_B],
        }
        result = policy.build_policy(
            github_run_number=600,
            kind="transitional",
            issued_at="2026-09-03T21:30:00Z",
            incoming_digest=DIGEST_A,
            accepted_policies=[previous],
        )

        self.assertEqual(policy.encoded_policy(result), FIXTURE.read_bytes())

    def test_final_contains_exactly_the_incoming_digest(self) -> None:
        result = policy.build_policy(
            github_run_number=600,
            kind="final",
            issued_at="2026-09-03T21:31:00Z",
            incoming_digest=DIGEST_C,
            accepted_policies=[json.loads(FIXTURE.read_text(encoding="utf-8"))],
            running_digests=[DIGEST_A, DIGEST_B],
        )
        self.assertEqual(result["sequence"], 1201)
        self.assertEqual(result["image_digests"], [DIGEST_C])

    def test_schema_rejects_unknown_keys_and_unsorted_digests(self) -> None:
        payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
        payload["extra"] = True
        with self.assertRaisesRegex(ValueError, "unknown"):
            policy.validate_policy(payload)
        payload.pop("extra")
        payload["image_digests"].reverse()
        with self.assertRaisesRegex(ValueError, "sorted and unique"):
            policy.validate_policy(payload)

    def test_cli_writes_parent_directory(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            output = Path(raw) / "gcp" / "policy.json"
            payload = policy.build_policy(
                github_run_number=1,
                kind="final",
                issued_at="2026-09-03T21:31:00Z",
                incoming_digest=DIGEST_C,
            )
            output.parent.mkdir(parents=True)
            output.write_bytes(policy.encoded_policy(payload))
            self.assertEqual(policy.read_policy(output), payload)


if __name__ == "__main__":
    unittest.main()
