#!/usr/bin/env python3
"""tools/check-trust-copies.py on matching, differing and incomplete trees.

The last two tests run tools/publish-trust-s3.sh on the same trees with PATH
holding a recording fake `aws` and the few real utilities the script uses, so
no real cloud CLI is reachable.

Run: python3 tools/test_check_trust_copies.py
"""

from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
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
PUBLISHER = SCRIPT.with_name("publish-trust-s3.sh")
FAKE_AWS = r"""#!/usr/bin/env python3
import json, os, sys
with open(os.environ["FAKE_LOG"], "a") as log:
    log.write(json.dumps(sys.argv[1:]) + "\n")
"""


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

    def publish(self) -> tuple[subprocess.CompletedProcess[str], list[list[str]]]:
        scratch = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, scratch)
        bin_dir = scratch / "bin"
        bin_dir.mkdir()
        (bin_dir / "aws").write_text(FAKE_AWS)
        (bin_dir / "aws").chmod(0o755)
        for real in ("python3", "dirname"):
            found = shutil.which(real)
            assert found, real
            (bin_dir / real).symlink_to(found)
        log = scratch / "aws.jsonl"
        log.touch()
        result = subprocess.run(
            ["/bin/bash", str(PUBLISHER), str(self.site)],
            env={"PATH": str(bin_dir), "HOME": str(scratch), "FAKE_LOG": str(log)},
            capture_output=True,
            text=True,
        )
        return result, [json.loads(line) for line in log.read_text().splitlines()]

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

    def test_the_s3_publisher_syncs_a_tree_whose_copies_match(self) -> None:
        result, calls = self.publish()

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([call[:4] for call in calls], [["s3", "sync", f"{self.site}/", "s3://trust.quill.lorehex.co/"]])

    def test_the_s3_publisher_refuses_a_tree_whose_copies_differ(self) -> None:
        (self.site / "pcr0-aws.txt").write_text("a newer measurement\n")

        result, calls = self.publish()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("differ", result.stderr)
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
