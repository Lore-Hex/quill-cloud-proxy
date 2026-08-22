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

THE DEFECT THIS FILE NOW ALSO PINS. source_commit used to DEFAULT to HEAD
whenever `git status --porcelain -- enclave-go` was clean, which is the normal
state. The justification was that release-aws-enclave.sh refuses to build from a
dirty enclave-go, so at BUILD time HEAD is the build — but this script runs
against an already-running enclave at an arbitrary later time, and both
documented invocations (the AWS runbook and the freshness check's auto-filed
drift issue) omitted the flag. The drift-remediation path fires precisely
BECAUSE the published measurement no longer matches what is running, i.e. exactly
when HEAD has moved past the released enclave. The default therefore
manufactured, unattended, a real-but-wrong commit — the one error the publish
workflow's `git cat-file` check cannot see, and the one the docstring itself
called worse than recording nothing. There is no default now, and
`NoDefaultCommitTests` is what keeps it from coming back.

SCOPE LIMIT, stated plainly. This proves the record carries a commit or the
sentinel, that no value is invented when none is given, and that a supplied
commit is checked against this repository. It does NOT prove the commit is the
one that built the running enclave — nothing here can, because PCR0 and hostdata
carry no commit, and a commit that is genuinely in this history but belongs to
the wrong build passes every check in this file. That is why the record now
publishes `source_commit_provenance: operator-asserted` rather than implying
more. It also does not prove the Azure regions run the same build: the record
describes two regions and carries one commit, and this file asserts nothing
about that gap beyond its existence.
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
        "url": "https://api-azure-syd.trustedrouter.com/attestation",
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

    def test_aws_and_azure_records_carry_the_client_telemetry_claim(self) -> None:
        for record in (
            capture.build_aws_record(AWS_LIVE, keep=False, source_commit="1a2b3c4"),
            capture.build_azure_record(AZURE_LIVE, keep=False, source_commit="1a2b3c4"),
        ):
            policy = record["data_policy"]
            self.assertIs(policy["client_telemetry_content_free"], True)
            self.assertEqual(
                policy["client_telemetry_disclosure"],
                "https://trustedrouter.com/docs/telemetry",
            )

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


class NoDefaultCommitTests(unittest.TestCase):
    """No --source-commit, no commit. The tree's state is not evidence.

    A clean enclave-go once meant "HEAD is the build". It never did: the build
    guard runs at build time, this runs whenever someone captures. So a clean
    tree, a dirty tree, and no git at all now all produce the same answer —
    the sentinel — and the only way to publish a commit is to name one.
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

    def _at(self, root: Path, *args: str) -> str:
        original = capture.REPO_ROOT
        capture.REPO_ROOT = root
        try:
            return capture.resolve_source_commit(*args)
        finally:
            capture.REPO_ROOT = original

    def _head(self, root: Path) -> str:
        return subprocess.run(
            ["git", "-C", str(root), "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()

    def test_a_clean_tree_does_not_record_head(self) -> None:
        # The regression this file exists for. A clean enclave-go is the normal
        # state; if it produced a commit, every unattended re-run of the
        # documented remediation would publish HEAD as the running build.
        with tempfile.TemporaryDirectory() as directory:
            root = self._repo(directory)

            recorded = self._at(root)

            self.assertEqual(recorded, capture.SOURCE_COMMIT_UNSET)
            self.assertNotEqual(recorded, self._head(root))

    def test_a_dirty_tree_records_the_sentinel(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self._repo(directory)
            (root / "enclave-go" / "main.go").write_text("package main // edited\n")

            self.assertEqual(self._at(root), capture.SOURCE_COMMIT_UNSET)

    def test_no_git_at_all_records_the_sentinel(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(self._at(Path(directory)), capture.SOURCE_COMMIT_UNSET)

    def test_a_supplied_commit_that_is_in_this_repository_is_recorded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self._repo(directory)
            head = self._head(root)

            self.assertEqual(self._at(root, head), head)

    def test_a_supplied_commit_that_is_not_in_this_repository_is_refused(self) -> None:
        # A sha from another clone, or a typo that happens to be well-formed
        # hex. It would send an auditor to a commit that does not exist and the
        # deploy gate to a file it cannot fetch.
        with tempfile.TemporaryDirectory() as directory:
            root = self._repo(directory)

            with self.assertRaisesRegex(ValueError, "not a commit in this repository"):
                self._at(root, "0123456789abcdef0123456789abcdef01234567")

    def test_a_supplied_commit_outside_this_history_is_refused(self) -> None:
        # Real object, real commit, never merged. An enclave release is built
        # from this history, so a commit off it names a tree nobody shipped.
        with tempfile.TemporaryDirectory() as directory:
            root = self._repo(directory)
            subprocess.run(["git", "-C", str(root), "checkout", "-qb", "side"], check=True)
            (root / "enclave-go" / "side.go").write_text("package main\n")
            subprocess.run(["git", "-C", str(root), "add", "-A"], check=True)
            subprocess.run(["git", "-C", str(root), "commit", "-qm", "side"], check=True)
            unmerged = self._head(root)
            subprocess.run(["git", "-C", str(root), "checkout", "-q", "-"], check=True)

            with self.assertRaisesRegex(ValueError, "not reachable from HEAD"):
                self._at(root, unmerged)


class ProvenanceFieldTests(unittest.TestCase):
    """The record says how strong its own source_commit is.

    "Which commit" and "how do you know" are different questions, and a reader
    holding only the bytes cannot ask the second one unless the record answers
    it. Nothing here reproduces PCR0 from the commit, so the answer is
    operator-asserted, and it says so.
    """

    def test_a_named_commit_is_published_as_operator_asserted(self) -> None:
        for record in (
            capture.build_aws_record(AWS_LIVE, keep=False, source_commit="1a2b3c4"),
            capture.build_azure_record(AZURE_LIVE, keep=False, source_commit="1a2b3c4"),
        ):
            self.assertEqual(record["source_commit_provenance"], capture.PROVENANCE_ASSERTED)
        # "operator-asserted" is only honest if the record also names the tool
        # that could upgrade it, which is the one that rebuilds PCR0 from a
        # commit and is not run by this script.
        aws = capture.build_aws_record(AWS_LIVE, keep=False, source_commit="1a2b3c4")
        self.assertEqual(aws["reproduce"], "tools/verify-pcr0.sh")

    def test_no_commit_is_published_as_no_provenance(self) -> None:
        for record in (
            capture.build_aws_record(AWS_LIVE, keep=False),
            capture.build_azure_record(AZURE_LIVE, keep=False),
        ):
            self.assertEqual(record["source_commit_provenance"], capture.PROVENANCE_NONE)


class PublishedRecordTests(unittest.TestCase):
    """What is committed today, so a regression is visible in the diff."""

    def test_gcp_record_still_names_its_source_commit(self) -> None:
        record = json.loads(
            (capture.REPO_ROOT / "trust-page" / "trust" / "gcp-release.json").read_text()
        )
        self.assertTrue(record.get("source_commit"))

    def test_published_records_are_honest_about_provenance(self) -> None:
        # AWS has not been recaptured from a release whose source commit is
        # known, so preserving the explicit absence remains the honest result.
        aws = json.loads(
            (capture.REPO_ROOT / "trust-page" / "trust" / "aws-release.json").read_text()
        )
        self.assertIn(aws.get("source_commit"), (None, capture.SOURCE_COMMIT_UNSET))

        # The current Azure record was recaptured without an operator-supplied
        # source commit. Preserve that explicit absence so downstream format
        # gates continue to fail closed instead of implying false provenance.
        azure = json.loads(
            (capture.REPO_ROOT / "trust-page" / "trust" / "azure-release.json").read_text()
        )
        self.assertEqual(azure.get("source_commit"), capture.SOURCE_COMMIT_UNSET)
        self.assertEqual(azure.get("source_commit_provenance"), capture.PROVENANCE_NONE)


if __name__ == "__main__":
    unittest.main()
