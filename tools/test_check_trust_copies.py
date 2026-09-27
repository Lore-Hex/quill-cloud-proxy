#!/usr/bin/env python3
"""tools/check-trust-copies.py on matching, differing and incomplete trees.

tools/test_check_trust_signatures.py runs tools/publish-trust-s3.sh, which
runs this check, on a signed tree.

Run: python3 tools/test_check_trust_copies.py
"""

from __future__ import annotations

import importlib.util
import shutil
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).with_name("check-trust-copies.py")
SPEC = importlib.util.spec_from_file_location("check_trust_copies", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
check = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(check)

REPO_TRUST_PAGE = SCRIPT.parent.parent / "trust-page"
# Written out here rather than read from check.REQUIRED, so a document dropped
# from the checker fails the missing-document test instead of vanishing from it.
DOCUMENTS = (
    "gcp-release.json",
    "image-digest-gcp.txt",
    "image-reference-gcp.txt",
    "accepted-image-digests-gcp.txt",
    "accepted-image-references-gcp.txt",
    "gcp/stage-d-accepted.json",
    "aws-release.json",
    "pcr0-aws.txt",
    "accepted-pcr0s-aws.txt",
    "azure-release.json",
    "hostdata-azure.txt",
    "accepted-hostdata-azure.txt",
)


class CheckTrustCopies(unittest.TestCase):
    def setUp(self) -> None:
        self.site = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.site)
        for name in DOCUMENTS:
            for path in (self.site / name, self.site / "trust" / name):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(f"{name}\n")
                path.with_name(f"{path.name}.bundle").write_text(f"{name} bundle\n")
        # Published at one path only: not a pair, so nothing to compare.
        (self.site / "index.html").write_text("<html></html>\n")
        (self.site / "pcr0.txt").write_text("pcr0\n")
        (self.site / "trust" / "retractions").mkdir()
        (self.site / "trust" / "retractions" / "old.json").write_text("{}\n")

    def test_matching_copies_pass(self) -> None:
        self.assertEqual(check.problems(self.site), [])
        self.assertEqual(check.main(["check", str(self.site)]), 0)

    def test_the_published_trust_page_passes(self) -> None:
        self.assertEqual(check.problems(REPO_TRUST_PAGE), [])

    def test_a_document_that_differs_between_its_paths_fails(self) -> None:
        (self.site / "pcr0-aws.txt").write_text("a newer measurement\n")

        self.assertEqual(
            check.problems(self.site),
            [f"{self.site / 'pcr0-aws.txt'} and {self.site / 'trust' / 'pcr0-aws.txt'} differ"],
        )
        self.assertEqual(check.main(["check", str(self.site)]), 1)

    def test_a_bundle_that_differs_between_its_paths_fails(self) -> None:
        (self.site / "trust" / "gcp" / "stage-d-accepted.json.bundle").write_text("resigned\n")

        self.assertEqual(len(check.problems(self.site)), 1)

    def test_a_bundle_at_one_path_only_passes(self) -> None:
        (self.site / "azure-release.json.bundle").unlink()

        self.assertEqual(check.problems(self.site), [])

    def test_a_symbolic_link_in_the_tree_is_refused(self) -> None:
        # The publishers follow links; the check would not walk into one.
        elsewhere = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, elsewhere)
        inside = self.site / "trust" / "retractions"
        inside.rename(elsewhere / "retractions")
        inside.symlink_to(elsewhere / "retractions", target_is_directory=True)

        self.assertEqual(check.problems(self.site), [f"{inside} is a symbolic link"])

    def test_each_required_document_must_exist_at_both_paths(self) -> None:
        for name in DOCUMENTS:
            for path in (self.site / name, self.site / "trust" / name):
                with self.subTest(path=str(path.relative_to(self.site))):
                    saved = path.read_bytes()
                    path.unlink()
                    try:
                        self.assertEqual(check.problems(self.site), [f"missing {path}"])
                    finally:
                        path.write_bytes(saved)


if __name__ == "__main__":
    unittest.main()
