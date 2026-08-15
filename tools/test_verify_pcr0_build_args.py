"""verify-pcr0.sh must build the enclave exactly the way release-aws-enclave.sh does.

PCR0 measures the enclave image file, and the build args are baked into that
image. If the reproducible-build script and the real release script disagree on
even one arg, the script yields a PCR0 that can never match what is published —
and a third party running it sees a mismatch that looks like tampering.

This is not hypothetical. verify-pcr0.sh spent its whole life building from a
directory (`enclave/`) that has never existed in this repository, so the one
tool offering independent verification could not run at all. Nothing caught it
because nothing tested it.

Run: python3 tools/test_verify_pcr0_build_args.py
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
REPO_ROOT = TOOLS.parent
RELEASE = TOOLS / "release-aws-enclave.sh"
VERIFY = TOOLS / "verify-pcr0.sh"

# Every build input that lands in the measurement.
MEASURED_ARGS = ("BUILD_TAGS", "QUILL_TLS_MODE", "QUILL_API_HOST", "PLATFORM")


def _assignments(script: Path) -> dict[str, str]:
    """Top-level NAME="value" assignments, ignoring ${VAR:-default} indirection."""
    found: dict[str, str] = {}
    for line in script.read_text().splitlines():
        match = re.match(r'^(\w+)="([^"$]*)"', line.strip())
        if match:
            found.setdefault(match.group(1), match.group(2))
    return found


class VerifyPcr0BuildArgs(unittest.TestCase):
    def test_measured_build_args_match_the_release_script(self) -> None:
        release = _assignments(RELEASE)
        verify = _assignments(VERIFY)
        for name in MEASURED_ARGS:
            self.assertIn(name, release, f"{RELEASE.name} no longer defines {name}")
            self.assertIn(name, verify, f"{VERIFY.name} no longer defines {name}")
            self.assertEqual(
                verify[name],
                release[name],
                f"{name} differs between the release and verify scripts. A "
                "reproducible build with different args yields a different PCR0, "
                "which reads as tampering to whoever runs it.",
            )

    def test_verify_script_builds_from_paths_that_exist(self) -> None:
        text = VERIFY.read_text()
        dockerfile = re.search(r"--file (\S+)", text)
        self.assertIsNotNone(dockerfile, "verify-pcr0.sh no longer names a Dockerfile")
        assert dockerfile is not None
        self.assertTrue(
            (REPO_ROOT / dockerfile.group(1)).is_file(),
            f"{dockerfile.group(1)} does not exist; the verification path is broken",
        )
        # The build context must exist too — the original defect was a `cd` into
        # a directory that was never in the repository.
        for match in re.finditer(r'cd "\$REPO_ROOT(/[^"]*)?"', text):
            target = REPO_ROOT / (match.group(1) or "").lstrip("/")
            self.assertTrue(
                target.is_dir(), f"verify-pcr0.sh cd's into a missing directory: {target}"
            )

    def test_compares_against_a_published_file_that_exists(self) -> None:
        published = re.search(r'PUBLISHED_FILE="\$REPO_ROOT/([^"]+)"', VERIFY.read_text())
        self.assertIsNotNone(published, "verify-pcr0.sh no longer names a published PCR0 file")
        assert published is not None
        self.assertTrue(
            (REPO_ROOT / published.group(1)).is_file(),
            f"verify-pcr0.sh compares against {published.group(1)}, which does not exist. "
            "Comparing against a missing file silently skips the only check that matters.",
        )


class PublishedMeasurementsAgreeAcrossPaths(unittest.TestCase):
    """The same measurement must not be published twice with different values."""

    def test_legacy_pcr0_matches_the_canonical_record(self) -> None:
        import json

        record = json.loads((REPO_ROOT / "trust-page/trust/aws-release.json").read_text())
        canonical = (REPO_ROOT / "trust-page/trust/pcr0-aws.txt").read_text().strip()
        legacy = (REPO_ROOT / "trust-page/pcr0.txt").read_text().strip()
        self.assertEqual(canonical, record["pcr0"])
        self.assertEqual(
            legacy,
            record["pcr0"],
            "trust-page/pcr0.txt disagrees with the current AWS record. Two paths "
            "publishing different measurements is the defect that shipped for "
            "months; re-run tools/capture-plane-measurements.py --write.",
        )

    def test_primary_measurement_is_in_its_own_accepted_set(self) -> None:
        import json

        for name, scalar, accepted in (
            ("aws-release.json", "pcr0", "accepted_pcr0s"),
            ("azure-release.json", "hostdata", "accepted_hostdata"),
        ):
            record = json.loads((REPO_ROOT / "trust-page/trust" / name).read_text())
            self.assertIn(
                record[scalar],
                record[accepted],
                f"{name}: the value expected to be serving is absent from its own "
                "accepted set, so a verifier following this record would reject the "
                "enclave that is answering.",
            )


if __name__ == "__main__":
    unittest.main()
