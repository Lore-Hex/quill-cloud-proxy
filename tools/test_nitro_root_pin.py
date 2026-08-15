"""The inlined Nitro root must stay byte-identical to the reviewable file.

verify-attestation.py inlines the AWS Nitro root certificate so the whole
verifier runs from a URL with no clone and no packaging:

    uv run https://raw.githubusercontent.com/.../tools/verify-attestation.py

That is worth doing — a tool a reviewer must clone and install is a tool most
reviewers never run — but it duplicates a root of trust. Two copies that can
drift apart is a bad trade for convenience: an attacker who edits only the
inlined copy changes what every URL-run verification trusts, while the file a
human reviews still looks correct.

So the duplication is allowed and the drift is not. This test is the thing that
makes that true.

Run: python3 tools/test_nitro_root_pin.py
"""

from __future__ import annotations

import hashlib
import re
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
PEM_FILE = TOOLS / "aws-nitro-root.pem"
VERIFIER = TOOLS / "verify-attestation.py"

# The published AWS Nitro Enclaves root (AWS_NitroEnclaves_Root-G1). Pinned as a
# literal so that changing BOTH copies still fails: a root of trust should only
# ever change through a deliberate, reviewed edit to this line.
EXPECTED_SHA256 = "6eb9688305e4bbca67f44b59c29a0661ae930f09b5945b5d1d9ae01125c8d6c0"


def _inlined_pem() -> bytes:
    source = VERIFIER.read_text()
    match = re.search(r'(AWS_NITRO_ROOT_PEM = b""".*?""")', source, re.S)
    if match is None:
        raise AssertionError("verify-attestation.py no longer inlines AWS_NITRO_ROOT_PEM")
    namespace: dict[str, object] = {}
    exec(match.group(1), namespace)  # noqa: S102 - a single literal assignment
    value = namespace["AWS_NITRO_ROOT_PEM"]
    assert isinstance(value, bytes)
    return value


class NitroRootPin(unittest.TestCase):
    def test_inlined_root_matches_the_reviewable_file_byte_for_byte(self) -> None:
        self.assertEqual(
            _inlined_pem(),
            PEM_FILE.read_bytes(),
            "the inlined Nitro root differs from tools/aws-nitro-root.pem. Whichever "
            "one you edited, the other is what somebody is trusting.",
        )

    def test_root_matches_the_pinned_digest(self) -> None:
        digest = hashlib.sha256(PEM_FILE.read_bytes()).hexdigest()
        self.assertEqual(
            digest,
            EXPECTED_SHA256,
            "the AWS Nitro root certificate changed. This is the anchor every AWS "
            "attestation chains to, so it must never change as a side effect — if "
            "AWS genuinely rotated the root, update EXPECTED_SHA256 deliberately "
            "and say why in the commit.",
        )

    def test_verifier_stays_url_runnable(self) -> None:
        source = VERIFIER.read_text()
        self.assertIn(
            "# /// script",
            source[:400],
            "PEP 723 metadata is what makes `uv run <raw URL>` work; without it the "
            "documented one-liner silently stops resolving dependencies.",
        )
        # A sibling-file read would break URL execution even with the header.
        self.assertNotRegex(
            source,
            r"Path\(__file__\)\.parent\s*/\s*[\"']aws-nitro-root\.pem[\"']",
            "reading the PEM from a sibling file breaks `uv run <raw URL>`, which is "
            "the entire reason it was inlined.",
        )


if __name__ == "__main__":
    unittest.main()
