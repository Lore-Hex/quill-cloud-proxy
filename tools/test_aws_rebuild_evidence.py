import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from tools.aws_rebuild_evidence import compare


class TestRebuildEvidence(unittest.TestCase):
    def test_every_output_must_match_independently(self):
        content = b"test image file"
        pcrs = {f"PCR{i}": str(i + 1) * 96 for i in range(3)}
        signed = {"enclave_image_id": "sha256:" + "a" * 64,
                  "eif_sha256": hashlib.sha256(content).hexdigest(),
                  "eif_size_bytes": len(content), "source_commit": "b" * 40,
                  "measurements": pcrs}
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "enclave.eif").write_bytes(content)
            (root / "image-id.txt").write_text(signed["enclave_image_id"])
            (root / "describe.json").write_text(json.dumps({"Measurements": pcrs}))
            for field in (None, "enclave_image_id", "eif_sha256", "eif_size_bytes", *pcrs):
                with self.subTest(field=field):
                    doc = {**signed, "measurements": pcrs.copy()}
                    if field in pcrs:
                        doc["measurements"][field] = "e" * 96
                    elif field is not None:
                        doc[field] = "different"
                    (root / "signed-manifest.json").write_text(json.dumps(doc))
                    result = compare(root)
                    self.assertEqual(len(result["matches"]), 6)
                    self.assertEqual([k for k, v in result["matches"].items() if not v],
                                     [] if field is None else [field])
