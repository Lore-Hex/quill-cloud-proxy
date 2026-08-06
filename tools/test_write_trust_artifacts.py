#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("write-trust-artifacts.py")
SPEC = importlib.util.spec_from_file_location("write_trust_artifacts", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
trust = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(trust)

OLD = "sha256:" + "1" * 64
NEW = "sha256:" + "2" * 64


class TrustArtifactTests(unittest.TestCase):
    def test_current_release_accepts_only_target_digest(self) -> None:
        release = trust.release_payload("abc123", "example/image:tag", NEW)

        self.assertEqual(release["image_digest"], NEW)
        self.assertEqual(release["accepted_image_digests"], [NEW])
        self.assertEqual(release["release_state"], "current")

    def test_rolling_release_preserves_old_and_new_digests(self) -> None:
        release = trust.release_payload(
            "abc123",
            "example/image:tag",
            NEW,
            [f"{OLD},{NEW}", OLD],
        )

        self.assertEqual(release["image_digest"], NEW)
        self.assertEqual(release["accepted_image_digests"], [OLD, NEW])
        self.assertEqual(release["release_state"], "rolling")

    def test_rejects_malformed_digest(self) -> None:
        with self.assertRaisesRegex(ValueError, "invalid OCI image digest"):
            trust.release_payload("abc123", "example/image:tag", "sha256:not-a-digest")

    def test_artifacts_publish_machine_readable_accepted_set(self) -> None:
        release = trust.release_payload(
            "abc123",
            "example/image:tag",
            NEW,
            [OLD],
        )
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            trust.write_artifacts(out, release)

            self.assertEqual(
                (out / "image-digest-gcp.txt").read_text(encoding="utf-8"),
                f"{OLD},{NEW}\n",
            )
            stored = json.loads((out / "gcp-release.json").read_text(encoding="utf-8"))
            self.assertEqual(stored["accepted_image_digests"], [OLD, NEW])
            self.assertEqual(stored["release_state"], "rolling")
            page = (out / "index.html").read_text(encoding="utf-8")
            self.assertIn("Accepted measured digests", page)
            self.assertIn("During a rolling release", page)


if __name__ == "__main__":
    unittest.main()
