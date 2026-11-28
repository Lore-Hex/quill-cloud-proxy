from pathlib import Path
import tempfile
import unittest

from tools.azure_qualified_image import prepare, receipt_digest


class QualifiedAzureImage(unittest.TestCase):
    def test_signed_content_must_match_plane_and_source(self):
        sha = "a" * 40
        digest = "sha256:" + "b" * 64
        record = {"source": sha, "plane": "azure", "digest": digest}
        self.assertEqual(receipt_digest(record, sha), digest)
        for change in ({"source": "c" * 40}, {"plane": "gcp"}, {"digest": "latest"},
                       {"registry_image": "other.example/workload"}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                receipt_digest(record | change, sha)

    def test_never_reuses_or_overwrites_prior_work(self):
        with tempfile.TemporaryDirectory() as temp:
            work = Path(temp) / "region"
            sha = "a" * 40
            digest = "sha256:" + "b" * 64
            prepare(work, sha, digest)
            with self.assertRaises(FileExistsError):
                prepare(work, "d" * 40, "sha256:" + "e" * 64)
            self.assertEqual((work / "build-commit.txt").read_text(), sha)
            self.assertEqual((work / "image-digest.txt").read_text(), digest)
