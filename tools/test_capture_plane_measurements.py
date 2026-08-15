#!/usr/bin/env python3
"""The AWS and Azure records must carry a source_commit, or say they do not.

THE LAW. Every release record this repository publishes names the commit whose
enclave-go tree produced the measurement it publishes, and when nobody can name
that commit the record says `not-configured` rather than naming a plausible one.

WHY THIS IS A PROOF AND NOT A PREFERENCE. A measurement with no commit is
unmappable to source. tools/verify-pcr0.sh reproduces PCR0 *from a commit*, so
without one an auditor cannot check our headline claim at all; and downstream,
quill-router's scripts/check_format_ordering.py answers "which BYOK envelope
formats does the enclave serving this cloud ACCEPT?" by reading that commit's
enclave-go/internal/byokcache/cache.go. No commit means no answer, and the only
safe response to no answer is to refuse the deploy. That refusal is worth
nothing if this side quietly supplies a *wrong* commit instead, because then the
gate reads a real file at a real commit and confidently concludes the wrong
thing. So the interesting assertions here are the negative ones.

THE REAL GAP THIS CLOSES. Verified before the change: gcp-release.json carried
`"source_commit": "f57b791"`, and aws-release.json and azure-release.json had no
source_commit key at all — not empty, not not-configured, absent. GCP had one
because its producer is a deploy pipeline that knows the digest it is rolling to.
AWS and Azure are produced by a capture of what is already running, and a capture
cannot measure a commit. That asymmetry is the whole reason the AWS and Azure
BYOK envelope ordering could not be machine-checked.

SCOPE LIMIT, stated plainly. This proves the record carries a commit and that a
dirty or unknowable tree yields the sentinel instead of a guess. It does NOT
prove the commit is the one that built the running enclave — nothing here can,
because PCR0 and hostdata carry no commit. It also does not prove the Azure
regions run the same build: the record describes two regions and carries one
commit, and this file asserts nothing about that gap beyond its existence.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).with_name("capture-plane-measurements.py")
SPEC = importlib.util.spec_from_file_location("capture_plane_measurements", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
capture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(capture)

PCR0 = "ab" * 24
HOSTDATA_UAEN = "c5" * 32
HOSTDATA_SEA = "f3" * 32

AWS_LIVE = {"pcr0": PCR0, "module_id": "i-0-enc0"}
AZURE_LIVE = [
    {
        "url": "https://api-azure.trustedrouter.com/attestation",
        "hostdata": HOSTDATA_UAEN,
        "issuer": "https://trquilluaen.uaen.attest.azure.net",
        "launch_measurement": "dc" * 24,
        "compliance": "azure-compliant-uvm",
    },
    {
        "url": "https://api-azure-sea.trustedrouter.com/attestation",
        "hostdata": HOSTDATA_SEA,
        "issuer": "https://trquillsea.sasia.attest.azure.net",
        "launch_measurement": "dc" * 24,
        "compliance": "azure-compliant-uvm",
    },
]


class SourceCommitTests(unittest.TestCase):
    def test_aws_record_carries_the_source_commit(self) -> None:
        record = capture.build_aws_record(AWS_LIVE, keep=False, source_commit="1a2b3c4")

        self.assertEqual(record["source_commit"], "1a2b3c4")

    def test_azure_record_carries_the_source_commit(self) -> None:
        record = capture.build_azure_record(AZURE_LIVE, keep=False, source_commit="1a2b3c4")

        self.assertEqual(record["source_commit"], "1a2b3c4")
        # Two regions, one commit. Asserted so the limit is visible in the
        # record rather than only in prose.
        self.assertEqual(len(record["regions"]), 2)

    def test_records_default_to_the_sentinel_rather_than_omitting_the_key(self) -> None:
        # An ABSENT key is what aws-release.json and azure-release.json had,
        # and it is indistinguishable from a consumer that forgot to look. The
        # sentinel is a statement; a missing key is a silence.
        self.assertEqual(
            capture.build_aws_record(AWS_LIVE, keep=False)["source_commit"],
            capture.SOURCE_COMMIT_UNSET,
        )
        self.assertEqual(
            capture.build_azure_record(AZURE_LIVE, keep=False)["source_commit"],
            capture.SOURCE_COMMIT_UNSET,
        )

    def test_an_explicit_commit_that_is_not_an_object_id_is_refused(self) -> None:
        # A branch name, a tag, or "latest" resolves differently tomorrow than
        # today, which is the one thing a provenance field may not do.
        for bad in ("main", "HEAD", "v1.2.3", "not a commit", "ZZZZZZZ"):
            with self.subTest(bad=bad), self.assertRaisesRegex(ValueError, "not a git object id"):
                capture.resolve_source_commit(bad)

    def test_the_sentinel_may_be_passed_explicitly(self) -> None:
        # An operator who knows the commit is unknowable can say so, and that
        # must not trip the object-id check.
        self.assertEqual(
            capture.resolve_source_commit(capture.SOURCE_COMMIT_UNSET),
            capture.SOURCE_COMMIT_UNSET,
        )


class DirtyTreeTests(unittest.TestCase):
    """A dirty enclave-go tree corresponds to no commit, so it yields none.

    release-aws-enclave.sh already refuses to BUILD from a dirty enclave-go
    because PCR0 would be unreproducible. The same fact has to hold on the
    publish side: HEAD names a tree that is not the tree that was built, so
    recording HEAD would be a fabrication with a plausible shape.
    """

    def _repo(self, directory: str) -> Path:
        root = Path(directory)
        subprocess.run(["git", "init", "-q", str(root)], check=True)
        subprocess.run(["git", "-C", str(root), "config", "user.email", "t@t"], check=True)
        subprocess.run(["git", "-C", str(root), "config", "user.name", "t"], check=True)
        (root / "enclave-go").mkdir()
        (root / "enclave-go" / "main.go").write_text("package main\n")
        subprocess.run(["git", "-C", str(root), "add", "-A"], check=True)
        subprocess.run(["git", "-C", str(root), "commit", "-qm", "initial"], check=True)
        return root

    def test_clean_tree_records_head(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self._repo(directory)
            original = capture.REPO_ROOT
            capture.REPO_ROOT = root
            try:
                recorded = capture.resolve_source_commit()
            finally:
                capture.REPO_ROOT = original
            expected = subprocess.run(
                ["git", "-C", str(root), "rev-parse", "--short", "HEAD"],
                capture_output=True,
                text=True,
                check=True,
            ).stdout.strip()
            self.assertEqual(recorded, expected)

    def test_dirty_enclave_go_records_the_sentinel(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self._repo(directory)
            (root / "enclave-go" / "main.go").write_text("package main // edited\n")
            original = capture.REPO_ROOT
            capture.REPO_ROOT = root
            try:
                recorded = capture.resolve_source_commit()
            finally:
                capture.REPO_ROOT = original
            self.assertEqual(recorded, capture.SOURCE_COMMIT_UNSET)

    def test_no_git_at_all_records_the_sentinel(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            original = capture.REPO_ROOT
            capture.REPO_ROOT = Path(directory)
            try:
                recorded = capture.resolve_source_commit()
            finally:
                capture.REPO_ROOT = original
            self.assertEqual(recorded, capture.SOURCE_COMMIT_UNSET)


class PublishedRecordTests(unittest.TestCase):
    """What is committed today, so a regression is visible in the diff."""

    def test_gcp_record_still_names_its_source_commit(self) -> None:
        record = json.loads(
            (capture.REPO_ROOT / "trust-page" / "trust" / "gcp-release.json").read_text()
        )
        self.assertTrue(record.get("source_commit"))

    def test_aws_and_azure_records_are_honest_about_provenance(self) -> None:
        # As of this change the published aws and azure records still predate
        # the capture that writes source_commit, so they have none. That is
        # recorded here as a FACT rather than fixed by inventing a value: the
        # commit that built the running AWS enclave is not derivable from
        # anything in this repository, and a guess would defeat the gate that
        # reads it. The next capture-and-publish fills them in.
        for plane in ("aws", "azure"):
            record = json.loads(
                (capture.REPO_ROOT / "trust-page" / "trust" / f"{plane}-release.json").read_text()
            )
            commit = record.get("source_commit")
            self.assertIn(
                commit,
                (None, capture.SOURCE_COMMIT_UNSET),
                msg=(
                    f"{plane}-release.json now names source_commit {commit!r}. If that is a real "
                    "captured commit, delete this assertion — it exists only to pin that we did "
                    "NOT backfill a guess."
                ),
            )


if __name__ == "__main__":
    unittest.main()
