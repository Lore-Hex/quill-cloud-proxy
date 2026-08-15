"""The identity we tell verifiers to pin must be the one that actually signs.

This test exists because the gap it closes shipped. Three per-plane workflows
were created so Fulcio would mint three distinct pinnable identities, and the
trust page documented `--certificate-identity .../publish-trust-aws.yml@...`.
But `publish-trust-page.yml` also signed every file with a glob, and ITS bundles
were the ones uploaded to Pages — so every published record carried the page
publisher as its signer. Checked against the live bundle:

    documented: .../publish-trust-aws.yml@refs/heads/main
    actual:     .../publish-trust-page.yml@refs/heads/main

A verifier following our own documented command got an identity mismatch, which
reads as "someone other than TrustedRouter signed this" — the single worst thing
a trust page can cause a reader to conclude.

Nothing caught it because the workflows were internally consistent and the page
was internally consistent; they were only wrong about each other.

Run: python3 tools/test_signing_identity_matches_docs.py
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = REPO_ROOT / ".github" / "workflows"
PAGE_GENERATOR = REPO_ROOT / "tools" / "write-trust-artifacts.py"
CAPTURE = REPO_ROOT / "tools" / "capture-plane-measurements.py"

PLANES = ("gcp", "aws", "azure")


def _signed_files(plane: str) -> set[str]:
    """Files the per-plane workflow signs.

    Parsed from the step that actually runs `cosign sign-blob`, not by regexing
    the file. The workflow contains two identical-looking loops — one signs, one
    verifies — and an earlier version of this helper matched whichever came
    first, so removing a file from the SIGNING loop left the test green because
    it had read the verify loop instead. A test that reads the wrong line is
    indistinguishable from no test.
    """
    import yaml

    document = yaml.safe_load((WORKFLOWS / f"publish-trust-{plane}.yml").read_text())
    scripts = [
        step["run"]
        for step in document["jobs"]["sign"]["steps"]
        if isinstance(step, dict) and "cosign sign-blob" in str(step.get("run", ""))
    ]
    if not scripts:
        raise AssertionError(f"publish-trust-{plane}.yml no longer signs anything")
    files: set[str] = set()
    for script in scripts:
        for match in re.finditer(r"for f in ([^;]+); do", script):
            files.update(
                part
                for part in match.group(1).split()
                # Globs (the retractions loop) name no specific artifact.
                if part.startswith("trust-page/") and "*" not in part
            )
    if not files:
        raise AssertionError(f"publish-trust-{plane}.yml signing loop lists no files")
    return files


class SigningIdentityMatchesDocumentation(unittest.TestCase):
    def test_every_signed_source_file_triggers_its_plane_workflow(self) -> None:
        import yaml

        for plane in PLANES:
            workflow = WORKFLOWS / f"publish-trust-{plane}.yml"
            document = yaml.safe_load(workflow.read_text())
            # PyYAML's YAML 1.1 loader parses the unquoted `on` key as True.
            triggers = document.get("on", document.get(True, {}))
            paths = triggers["push"]["paths"]
            self.assertTrue(
                all(" " not in path for path in paths),
                f"{workflow.name} has a space-joined path entry that can never match",
            )
            for signed_file in _signed_files(plane):
                self.assertIn(
                    signed_file,
                    paths,
                    f"changing {signed_file} does not trigger {workflow.name}",
                )

    def test_page_publisher_does_not_sign(self) -> None:
        # The page publisher uploads what the per-plane workflows signed. If it
        # signs as well, its signature is the one that reaches the published
        # surface and every documented per-plane identity becomes wrong.
        text = (WORKFLOWS / "publish-trust-page.yml").read_text()
        self.assertNotIn(
            "cosign sign-blob",
            text,
            "publish-trust-page.yml signs trust artifacts again. Its bundles are "
            "the ones published, so this silently overrides every per-plane "
            "identity the trust page tells verifiers to pin.",
        )

    def test_every_plane_signs_a_disjoint_set_of_files(self) -> None:
        seen: dict[str, str] = {}
        for plane in PLANES:
            for path in _signed_files(plane):
                self.assertNotIn(
                    path,
                    seen,
                    f"{path} is signed by both publish-trust-{seen.get(path)}.yml and "
                    f"publish-trust-{plane}.yml. Two signers means whichever ran last "
                    "decides the identity, which is not a pinnable property.",
                )
                seen[path] = plane

    def test_documented_identity_matches_the_signing_workflow(self) -> None:
        page = PAGE_GENERATOR.read_text()
        documented = re.findall(
            r"--certificate-identity (https://github\.com/\S+/\.github/workflows/(\S+?)@\S+)",
            page,
        )
        self.assertTrue(documented, "the page no longer documents an exact identity to pin")
        for full, workflow_file in documented:
            self.assertTrue(
                (WORKFLOWS / workflow_file).is_file(),
                f"the page tells verifiers to pin {full}, but {workflow_file} does not exist",
            )
            self.assertTrue(
                workflow_file.startswith("publish-trust-"),
                f"{workflow_file} is not a per-plane publishing workflow",
            )

    def test_documented_bundle_is_signed_by_the_identity_documented_beside_it(self) -> None:
        # The page shows one worked example: a bundle name and an identity. They
        # must belong together, or the one command a reader copy-pastes fails.
        page = PAGE_GENERATOR.read_text()
        match = re.search(
            r"--bundle (\S+)\.bundle.*?--certificate-identity "
            r"https://github\.com/\S+/\.github/workflows/publish-trust-(\w+)\.yml",
            page,
            re.S,
        )
        self.assertIsNotNone(match, "the page's cosign example is no longer parseable")
        assert match is not None
        artifact, plane = match.group(1), match.group(2)
        signed = {Path(p).name for p in _signed_files(plane)}
        self.assertIn(
            artifact,
            signed,
            f"the page tells readers to verify {artifact} against the {plane} identity, "
            f"but publish-trust-{plane}.yml does not sign that file.",
        )

    def test_record_transparency_blocks_name_a_real_workflow(self) -> None:
        # Each record carries its own instructions; those must not outlive the
        # workflow they name, or a record read from an email points at nothing.
        capture = CAPTURE.read_text()
        match = re.search(r'f"publish-trust-\{plane\}\.yml@([^"]*)"', capture)
        self.assertIsNotNone(
            match, "capture-plane-measurements.py no longer derives a per-plane identity"
        )
        for plane in ("aws", "azure"):
            self.assertTrue(
                (WORKFLOWS / f"publish-trust-{plane}.yml").is_file(),
                f"records name publish-trust-{plane}.yml, which does not exist",
            )


if __name__ == "__main__":
    unittest.main()
