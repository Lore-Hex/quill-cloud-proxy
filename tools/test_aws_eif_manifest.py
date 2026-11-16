from __future__ import annotations

import copy
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools import aws_eif_manifest as manifest


class EIFManifestTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.eif = self.root / "enclave.eif"
        self.eif.write_bytes(b"test-only fake EIF bytes")
        self.measurements = self.root / "measurements.json"
        self.measurements.write_text(json.dumps({"Measurements": {
            "HashAlgorithm": "Sha384", "PCR0": "1" * 96,
            "PCR1": "2" * 96, "PCR2": "3" * 96,
        }}))
        self.record = manifest.create(
            self.eif, self.measurements, "a" * 40,
            "330422590279.dkr.ecr.eu-west-1.amazonaws.com/quill-enclave-eif-builder@sha256:" + "b" * 64,
            "sha256:" + "c" * 64, "1.5.3",
        )
        self.path = self.root / "manifest.json"
        self.path.write_text(json.dumps(self.record))
        self.signature = self.root / "manifest.json.bundle"
        self.signature.write_text("{}")

    def test_signed_roundtrip_checks_exact_workflow_identity(self):
        def verify_snapshot(args, **kwargs):
            self.assertNotEqual(Path(args[-1]), self.path)
            self.assertEqual(Path(args[-1]).read_bytes(), self.path.read_bytes())
            self.assertEqual(Path(args[3]).read_bytes(), self.signature.read_bytes())

        with patch.object(manifest.subprocess, "run", side_effect=verify_snapshot) as call:
            actual = manifest.verify(self.path, self.signature, self.eif, "a" * 40)
        self.assertEqual(actual, self.record)
        args = call.call_args.args[0]
        self.assertEqual(args[:3], ["cosign", "verify-blob", "--bundle"])
        self.assertEqual(args[4:-1], [
            "--certificate-identity", manifest.IDENTITY,
            "--certificate-oidc-issuer", manifest.ISSUER,
        ])
        self.assertFalse(Path(args[-1]).exists())
        self.assertTrue(call.call_args.kwargs["check"])
        self.assertEqual(call.call_args.kwargs["timeout"], 60)
        self.assertEqual(manifest.artifact_prefix(actual),
                         "releases/" + "a" * 40 + "/" + self.record["eif_sha256"])

    def test_input_replacement_cannot_change_authenticated_record(self):
        def replace_original(args, **kwargs):
            self.path.write_text(json.dumps({**self.record, "source_commit": "f" * 40}))
            self.signature.write_text('{"replacement": true}')
            self.assertEqual(json.loads(Path(args[-1]).read_bytes()), self.record)
            self.assertEqual(Path(args[3]).read_text(), "{}")

        with patch.object(manifest.subprocess, "run", side_effect=replace_original):
            self.assertEqual(manifest.verify(self.path, self.signature), self.record)

    def test_bad_signature_or_unavailable_verifier_fails_closed(self):
        for error in (FileNotFoundError(), subprocess.CalledProcessError(1, "cosign"),
                      subprocess.TimeoutExpired("cosign", 60)):
            with self.subTest(error=error), patch.object(manifest.subprocess, "run", side_effect=error):
                with self.assertRaises(type(error)):
                    manifest.verify(self.path, self.signature, self.eif)

    def test_mismatched_bytes_or_source_are_rejected(self):
        with patch.object(manifest.subprocess, "run"):
            with self.assertRaisesRegex(ValueError, "source commit"):
                manifest.verify(self.path, self.signature, self.eif, "f" * 40)
            self.eif.write_bytes(b"substituted bytes")
            with self.assertRaisesRegex(ValueError, "EIF bytes"):
                manifest.verify(self.path, self.signature, self.eif)

    def test_invalid_fields_fail_before_signature_verifier(self):
        for field, value in (
            ("schema", "untrusted"), ("source_commit", "main"),
            ("builder_image", "quill-builder:latest"), ("enclave_image_id", "image:latest"),
            ("nitro_cli_version", "latest"), ("eif_sha256", "x" * 64),
            ("eif_size_bytes", True), ("eif_size_bytes", 0),
            ("eif_size_bytes", manifest.MAX_EIF_BYTES + 1),
            ("measurements", {"PCR0": "1" * 96}),
            ("measurements", {"PCR0": "0" * 96, "PCR1": "2" * 96, "PCR2": "3" * 96}),
        ):
            record = copy.deepcopy(self.record)
            record[field] = value
            self.path.write_text(json.dumps(record))
            with self.subTest(field=field, value=value), patch.object(manifest.subprocess, "run") as call:
                with self.assertRaises(ValueError):
                    manifest.verify(self.path, self.signature)
                call.assert_not_called()

    def test_duplicate_unknown_missing_or_oversized_json_rejected(self):
        records = [
            json.dumps(self.record)[:-1] + ', "source_commit": "' + "a" * 40 + '"}',
            json.dumps({**self.record, "unexpected": True}),
            json.dumps({k: v for k, v in self.record.items() if k != "eif_sha256"}),
            " " * (manifest.MAX_MANIFEST_BYTES + 1),
        ]
        for content in records:
            self.path.write_text(content)
            with self.subTest(content=content[:40]), self.assertRaises(ValueError):
                manifest.verify(self.path, self.signature)

    def test_symlink_and_oversized_signature_rejected(self):
        link = self.root / "symlink.eif"
        link.symlink_to(self.eif)
        with self.assertRaises(ValueError):
            manifest.hash_eif(link)
        self.signature.write_bytes(b" " * (manifest.MAX_BUNDLE_BYTES + 1))
        with patch.object(manifest.subprocess, "run") as call:
            with self.assertRaises(ValueError):
                manifest.verify(self.path, self.signature)
            call.assert_not_called()


if __name__ == "__main__":
    unittest.main()
