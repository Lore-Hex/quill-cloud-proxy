#!/usr/bin/env python3

from __future__ import annotations

import base64
import gzip
import importlib.util
import os
from pathlib import Path
import re
import subprocess
import sys
import unittest

SCRIPT = Path(__file__).with_name("encode_ec2_user_data.py")
DEPLOY_SCRIPT = SCRIPT.with_name("deploy-aws-nitro.sh")
SPEC = importlib.util.spec_from_file_location("encode_ec2_user_data", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
encoder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(encoder)


class EncodeEC2UserDataTests(unittest.TestCase):
    def test_large_bootstrap_round_trips_below_ec2_limit(self) -> None:
        payload = (b"#!/bin/bash\nwrite_vsock_unit 8001 example.com\n" * 1_000)

        encoded = encoder.encode_user_data(payload)
        compressed = base64.b64decode(encoded)

        self.assertLessEqual(len(compressed), encoder.MAX_USER_DATA_BYTES)
        self.assertEqual(gzip.decompress(compressed), payload)

    def test_encoding_is_deterministic(self) -> None:
        payload = b"#!/bin/bash\necho ready\n"
        self.assertEqual(
            encoder.encode_user_data(payload),
            encoder.encode_user_data(payload),
        )

    def test_incompressible_payload_over_limit_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "maximum is 16384"):
            encoder.encode_user_data(os.urandom(20_000))

    def test_empty_payload_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "must not be empty"):
            encoder.encode_user_data(b"")

    def test_current_nitro_bootstrap_template_has_four_kib_headroom(self) -> None:
        script = DEPLOY_SCRIPT.read_text()
        template = script.split("  user_data=$(cat <<EOS\n", 1)[1].split("\nEOS\n)", 1)[0]

        compressed = encoder.compress_user_data(template.encode())

        self.assertLessEqual(len(compressed), encoder.MAX_USER_DATA_BYTES - 4096)

    def test_nitro_gateway_uses_canonical_billing_authority(self) -> None:
        script = DEPLOY_SCRIPT.read_text()
        assignments = re.findall(
            r"-e QUILL_TR_CONTROL_PLANE_BASE_URL=([^ \\\n]+)", script
        )
        self.assertEqual(assignments, ["${TR_CONTROL_PLANE_BASE_URL}"])
        self.assertIn(
            'TR_CONTROL_PLANE_BASE_URL="${TR_CONTROL_PLANE_BASE_URL:-https://trustedrouter.com}"',
            script,
        )
        self.assertIn(
            'python3 "$CONTROL_PLANE_VALIDATOR" "$TR_CONTROL_PLANE_BASE_URL"',
            script,
        )
        self.assertNotIn("write_vsock_unit 8048", script)

    def test_cli_emits_one_base64_value_and_round_trips(self) -> None:
        payload = b"#!/bin/bash\necho ready\n" * 1_000
        result = subprocess.run(
            [sys.executable, str(SCRIPT)],
            input=payload,
            capture_output=True,
            check=True,
        )

        self.assertNotIn(b"\n", result.stdout)
        self.assertEqual(gzip.decompress(base64.b64decode(result.stdout)), payload)

    def test_cli_fails_closed_when_compressed_payload_is_too_large(self) -> None:
        result = subprocess.run(
            [sys.executable, str(SCRIPT)],
            input=os.urandom(20_000),
            capture_output=True,
            check=False,
        )

        self.assertEqual(result.returncode, 1)
        self.assertIn(b"maximum is 16384", result.stderr)


if __name__ == "__main__":
    unittest.main()
