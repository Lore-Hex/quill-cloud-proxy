#!/usr/bin/env python3
"""Hermetic release-gate tests. No network, credentials or inference."""

import base64
import copy
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import maple_policy as policy
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils


class VendorRepo(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name) / "vendor"
        self.repo.mkdir()
        self.git("init", "-q")
        self.key = ec.generate_private_key(ec.SECP384R1())
        self.write("services/opensecret/src/provider_registry.rs", "dedicated only\n")
        self.write("services/opensecret/Cargo.lock", "locked\n")
        self.write("apps/chat/ui.rs", "UI v1\n")
        self.write(policy.HISTORY, "[]")
        self.first = self.commit()
        self.baseline = {
            "source_commit": self.first,
            "pcr0": "1" * 96,
            "security_boundary_sha256": policy.boundary(self.repo, self.first),
            "history_public_key_der": base64.b64encode(
                self.key.public_key().public_bytes(
                    serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            ).decode(),
        }

    def git(self, *args):
        return (
            subprocess.run(
                ["git", "-C", str(self.repo), *args], capture_output=True, check=True
            )
            .stdout.decode()
            .strip()
        )

    def write(self, path, text):
        target = self.repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)

    def commit(self):
        self.git("add", ".")
        self.git(
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-qm",
            "fixture",
        )
        return self.git("rev-parse", "HEAD")

    def approve(self, pcr="2" * 96):
        before = json.loads((self.repo / policy.HISTORY).read_text())
        signature = self.key.sign(pcr.encode(), ec.ECDSA(hashes.SHA384()))
        r, s = utils.decode_dss_signature(signature)
        before.append(
            {
                "PCR0": pcr,
                "signature": base64.b64encode(
                    r.to_bytes(48, "big") + s.to_bytes(48, "big")
                ).decode(),
            }
        )
        self.write(policy.HISTORY, json.dumps(before))
        approval = self.commit()
        self.git("update-ref", "refs/remotes/origin/master", approval)
        return approval


class ReleaseTests(VendorRepo):
    def test_app_only_update_is_automatic(self):
        self.write("apps/chat/ui.rs", "UI v2\n")
        source = self.commit()
        approval = self.approve()
        result = policy.discover(self.repo, self.baseline)
        self.assertEqual(result["status"], "automatic")
        self.assertEqual(result["source_commit"], source)
        self.assertEqual(result["approval_commit"], approval)
        self.assertEqual(result["security_sensitive_paths"], [])

    def test_each_sensitive_change_requires_review(self):
        for path in (
            "services/opensecret/src/provider_registry.rs",
            "services/opensecret/Cargo.lock",
            "services/opensecret/src/auth.rs",
            "services/opensecret/src/maple_inference.rs",
            "sdk/src/transport.rs",
            "scripts/build.sh",
            ".github/workflows/release.yml",
            "new-unclassified-file",
            ".gitmodules",
            "flake.lock",
        ):
            with self.subTest(path=path):
                self.write(path, "changed\n")
                source = self.commit()
                result = policy.classify(self.repo, source, self.baseline)
                self.assertFalse(result["automatic"])
                self.assertIn(path, result["security_sensitive_paths"])

    def test_deleting_protected_file_requires_review(self):
        (self.repo / "services/opensecret/Cargo.lock").unlink()
        self.assertFalse(
            policy.classify(self.repo, self.commit(), self.baseline)["automatic"]
        )

    def test_wrong_reviewed_boundary_fails(self):
        self.baseline["security_boundary_sha256"] = "0" * 64
        with self.assertRaises(policy.Refused):
            policy.classify(self.repo, self.first, self.baseline)

    def test_rewind_fails(self):
        self.write("apps/chat/ui.rs", "next")
        self.baseline["source_commit"] = self.commit()
        with self.assertRaises(subprocess.CalledProcessError):
            policy.classify(self.repo, self.first, self.baseline)

    def test_history_signature_and_wrong_pin(self):
        approval = self.approve()
        policy.verify_history(self.repo, self.first, approval, "2" * 96, self.baseline)
        with self.assertRaises(policy.Refused):
            policy.verify_history(
                self.repo, self.first, approval, "3" * 96, self.baseline
            )
        bad = copy.deepcopy(self.baseline)
        other = ec.generate_private_key(ec.SECP384R1())
        bad["history_public_key_der"] = base64.b64encode(
            other.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        ).decode()
        with self.assertRaises(InvalidSignature):
            policy.verify_history(self.repo, self.first, approval, "2" * 96, bad)

    def test_approval_cannot_change_runtime_code(self):
        self.write(
            "services/opensecret/src/provider_registry.rs", "third-party fallback"
        )
        approval = self.approve()
        with self.assertRaisesRegex(policy.Refused, "also changes source"):
            policy.verify_history(
                self.repo, self.first, approval, "2" * 96, self.baseline
            )

    def test_dev_approval_is_not_mistaken_for_built_source(self):
        self.write("apps/chat/ui.rs", "new release")
        source = self.commit()
        self.write("services/opensecret/pcrDev.json", "dev approval")
        self.commit()
        approval = self.approve()
        self.assertEqual(
            policy.discover(self.repo, self.baseline)["source_commit"], source
        )
        policy.verify_history(self.repo, source, approval, "2" * 96, self.baseline)

    def test_history_cannot_be_rewritten(self):
        self.approve()
        self.write("apps/chat/ui.rs", "next")
        source = self.commit()
        self.write(policy.HISTORY, "[]")
        approval = self.approve("3" * 96)
        with self.assertRaisesRegex(policy.Refused, "append-only"):
            policy.verify_history(self.repo, source, approval, "3" * 96, self.baseline)

    def test_unapproved_source_cannot_stage(self):
        self.write(
            "services/opensecret/src/provider_registry.rs", "third-party fallback"
        )
        self.commit()
        self.approve()
        candidate = policy.discover(self.repo, self.baseline)
        root = Path(self.temp.name) / "tr"
        baseline_path = root / policy.BASELINE.relative_to(policy.REPO)
        baseline_path.parent.mkdir(parents=True)
        baseline_path.write_text(json.dumps(self.baseline))
        with self.assertRaisesRegex(policy.Refused, "security-sensitive"):
            policy.stage(self.repo, candidate, {}, root)

    def test_zero_and_malformed_measurements_fail(self):
        approval = self.approve()
        for pcr in ("0" * 96, "*", "2" * 95, "2" * 97, "https://live-server"):
            with self.subTest(pcr=pcr), self.assertRaises(policy.Refused):
                policy.verify_history(
                    self.repo, self.first, approval, pcr, self.baseline
                )

    def test_stage_binds_exact_candidate_and_evidence(self):
        self.write("apps/chat/ui.rs", "next")
        self.commit()
        self.approve()
        candidate = policy.discover(self.repo, self.baseline)
        root = Path(self.temp.name) / "tr"
        baseline_path = root / policy.BASELINE.relative_to(policy.REPO)
        baseline_path.parent.mkdir(parents=True)
        baseline_path.write_text(json.dumps(self.baseline))
        lib = baseline_path.parent / "src/lib.rs"
        lib.parent.mkdir()
        original = 'pub const PCR0: &str = "' + self.baseline["pcr0"] + '";\n'
        lib.write_text(original)
        evidence = {
            "source_commit": candidate["source_commit"],
            "build_commit": candidate["source_commit"],
            "pcr0": candidate["pcr0"],
            "security_boundary_sha256": candidate["security_boundary_sha256"],
            "reproduction_verified": True,
            "provenance_verified": True,
            "history_verified": True,
            "files": {"image.eif": "4" * 64},
        }
        for field in (
            "reproduction_verified",
            "provenance_verified",
            "history_verified",
        ):
            bad = dict(evidence, **{field: False})
            with self.subTest(field=field), self.assertRaises(policy.Refused):
                policy.stage(self.repo, candidate, bad, root)
            self.assertEqual(lib.read_text(), original)
        bad = dict(evidence, source_commit="0" * 40)
        with self.assertRaises(policy.Refused):
            policy.stage(self.repo, candidate, bad, root)
        for build in (None, "0" * 40, self.first):
            bad = dict(evidence, build_commit=build)
            with self.subTest(build=build), self.assertRaises(policy.Refused):
                policy.stage(self.repo, candidate, bad, root)
            self.assertEqual(lib.read_text(), original)
        policy.stage(self.repo, candidate, evidence, root)
        self.assertIn(candidate["pcr0"], lib.read_text())
        self.assertNotIn(self.baseline["pcr0"], lib.read_text())
        updated = json.loads(baseline_path.read_text())
        self.assertEqual(
            updated["security_boundary_sha256"],
            self.baseline["security_boundary_sha256"],
        )


class BuildCommitTests(VendorRepo):
    """The final artifact may be built at a measurement-approval descendant."""

    def setUp(self):
        super().setUp()
        self.write("apps/chat/ui.rs", "release\n")
        self.source = self.commit()
        self.write("services/opensecret/pcrDev.json", "dev approval")
        self.write("services/opensecret/pcrDevHistory.json", "[]")
        self.dev = self.commit()
        self.write("services/opensecret/pcrProd.json", "prod approval")
        self.approval = self.approve()

    def release(self, build, *, reproduced_pcr="2" * 96, vendor_pcr="2" * 96):
        root = Path(tempfile.mkdtemp(prefix="artifacts-", dir=self.temp.name))
        vendor, rebuilt = root / "vendor", root / "rebuilt"
        for directory, pcr0 in ((vendor, vendor_pcr), (rebuilt, reproduced_pcr)):
            pcr = {"PCR0": pcr0, "PCR1": "5" * 96, "PCR2": "6" * 96}
            handoff = {
                "environment": "prod",
                "source_sha": build,
                "measurements": pcr,
                "eif_sha256": hashlib.sha256(b"EIF").hexdigest(),
                "approval_needed": False,
            }
            directory.mkdir(parents=True)
            (directory / "image.eif").write_bytes(b"EIF")
            (directory / "pcr.json").write_text(json.dumps(pcr))
            (directory / "handoff.json").write_text(json.dumps(handoff))
            (directory / "SHA256SUMS").write_text("sums")
        return vendor, rebuilt

    def provenance(self, digest):
        cert = {
            "issuer": "https://token.actions.githubusercontent.com",
            "subjectAlternativeName": policy.WORKFLOW,
            "sourceRepositoryURI": "https://github.com/" + policy.VENDOR,
            "sourceRepositoryDigest": digest,
            "buildSignerDigest": digest,
            "sourceRepositoryRef": "refs/heads/master",
            "sourceRepositoryIdentifier": "923138240",
            "sourceRepositoryOwnerIdentifier": "322649754",
        }
        row = {
            "verificationResult": {
                "signature": {"certificate": cert},
                "verifiedTimestamps": [{"type": "Tlog"}],
            }
        }
        return json.dumps([row]).encode()

    def verify(self, candidate, build, attested=None, **artifacts):
        vendor, rebuilt = self.release(build, **artifacts)
        calls = []

        def fake_run(command, **kwargs):
            if command[:3] == ["gh", "attestation", "verify"]:
                calls.append(command)
                return subprocess.CompletedProcess(
                    command, 0, self.provenance(attested or build), b""
                )
            return real_run(command, **kwargs)

        real_run = subprocess.run
        with patch.object(policy.subprocess, "run", fake_run):
            result = policy.verify_release(
                self.repo, candidate, vendor, rebuilt, build, review_only=True
            )
        for command in calls:
            for flag in ("--source-digest", "--signer-digest"):
                self.assertEqual(command[command.index(flag) + 1], build)
        self.assertEqual(len(calls), 2)
        return result

    def test_discover_lists_source_then_approval_descendants(self):
        candidate = policy.discover(self.repo, self.baseline)
        self.assertEqual(candidate["source_commit"], self.source)
        self.assertEqual(
            candidate["build_commits"], [self.source, self.dev, self.approval]
        )

    def test_build_at_source_still_verifies(self):
        candidate = policy.discover(self.repo, self.baseline)
        policy.verify_build_commit(self.repo, self.source, self.source)
        result = self.verify(candidate, self.source)
        self.assertEqual(result["build_commit"], self.source)
        self.assertEqual(result["source_commit"], self.source)

    def test_measurement_only_descendant_build_verifies(self):
        candidate = policy.discover(self.repo, self.baseline)
        for build in (self.dev, self.approval):
            with self.subTest(build=build):
                policy.verify_build_commit(self.repo, self.source, build)
                result = self.verify(candidate, build)
                self.assertEqual(result["build_commit"], build)
                self.assertEqual(result["source_commit"], self.source)
                self.assertEqual(result["pcr0"], "2" * 96)

    def test_descendant_with_any_other_change_refuses(self):
        for path in (
            "apps/chat/ui.rs",
            "README.md",
            "services/opensecret/src/provider_registry.rs",
            "services/opensecret/pcrProd.json.bak",
            "services/opensecret/pcrStaging.json",
        ):
            with self.subTest(path=path):
                self.write(path, "changed " + path)
                build = self.commit()
                with self.assertRaisesRegex(policy.Refused, "more than measurement"):
                    policy.verify_build_commit(self.repo, self.source, build)
                self.git("reset", "-q", "--hard", self.approval)

    def test_rename_onto_measurement_path_refuses(self):
        # At the source, pcrDev.json does not exist yet, so git would report
        # this as a pure rename and print only the measurement path.
        self.git("checkout", "-q", "-b", "rename", self.source)
        self.git(
            "mv", "services/opensecret/Cargo.lock", "services/opensecret/pcrDev.json"
        )
        build = self.commit()
        with self.assertRaisesRegex(policy.Refused, "more than measurement"):
            policy.verify_build_commit(self.repo, self.source, build)

    def test_non_descendant_build_refuses(self):
        self.git("checkout", "-q", "-b", "side", self.first)
        self.write("services/opensecret/pcrDev.json", "side approval")
        side = self.commit()
        for build in (side, self.first):
            with (
                self.subTest(build=build),
                self.assertRaisesRegex(policy.Refused, "not a descendant"),
            ):
                policy.verify_build_commit(self.repo, self.source, build)

    def merge(self, branch):
        self.git(
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "merge",
            "-q",
            "--no-ff",
            "--no-edit",
            branch,
        )
        return self.git("rev-parse", "HEAD")

    def test_merge_in_build_chain_refuses(self):
        # Both parents and the merge itself touch only measurement files, so
        # only the single-parent rule can refuse this chain.
        self.git("checkout", "-q", "-b", "side", self.approval)
        self.write("services/opensecret/pcrDevHistory.json", "[1]")
        side = self.commit()
        self.git("checkout", "-q", "-")
        self.write("services/opensecret/pcrDev.json", "dev approval 2")
        self.commit()
        merge = self.merge("side")
        for commit in (side, merge):
            self.assertTrue(
                set(policy.changed_paths(self.repo, commit + "^", commit))
                <= policy.MEASUREMENTS
            )
        with self.assertRaisesRegex(policy.Refused, "merge"):
            policy.verify_build_commit(self.repo, self.source, merge)

    def test_chain_over_bound_refuses(self):
        for index in range(33):
            self.write("services/opensecret/pcrDev.json", f"dev {index}")
            tip = self.commit()
        with self.assertRaisesRegex(policy.Refused, "exceeds bound"):
            policy.verify_build_commit(self.repo, self.source, tip)
        self.assertEqual(policy.build_commits(self.repo, self.source, tip), [self.source])

    def test_build_commits_stop_at_first_refused_commit(self):
        self.write("apps/chat/ui.rs", "post-approval change")
        self.commit()
        self.write("services/opensecret/pcrDev.json", "later approval")
        later = self.commit()
        self.assertEqual(
            policy.build_commits(self.repo, self.source, later),
            [self.source, self.dev, self.approval],
        )

    def test_build_commits_unexpected_error_stops_list_without_crashing(self):
        real = policy.verify_build_commit
        for error in (
            subprocess.CalledProcessError(1, "git"),
            UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid"),
        ):

            def fake(repo, source, build, error=error):
                if build == self.approval:
                    raise error
                return real(repo, source, build)

            with (
                self.subTest(error=type(error).__name__),
                patch.object(policy, "verify_build_commit", fake),
                patch("sys.stderr"),
            ):
                self.assertEqual(
                    policy.build_commits(self.repo, self.source, self.approval),
                    [self.source, self.dev],
                )
        real_git = policy.git

        def failing_walk(repo, *args):
            if args[:2] == ("rev-list", "--reverse"):
                raise subprocess.CalledProcessError(128, "git")
            return real_git(repo, *args)

        with patch.object(policy, "git", failing_walk), patch("sys.stderr"):
            self.assertEqual(
                policy.build_commits(self.repo, self.source, self.approval),
                [self.source],
            )
        # A failure on the measured source itself still refuses discovery.
        with (
            patch.object(
                policy,
                "measurement_source",
                side_effect=subprocess.CalledProcessError(128, "git"),
            ),
            self.assertRaises(subprocess.CalledProcessError),
        ):
            policy.discover(self.repo, self.baseline)

    def test_measurement_path_mode_or_type_change_refuses(self):
        target = self.repo / "services/opensecret/pcrDev.json"
        target.chmod(0o755)
        executable = self.commit()
        with self.assertRaisesRegex(policy.Refused, "regular file|more than"):
            policy.verify_build_commit(self.repo, self.source, executable)
        self.git("reset", "-q", "--hard", self.approval)
        target.unlink()
        target.symlink_to("../../services/opensecret/Cargo.lock")
        link = self.commit()
        with self.assertRaisesRegex(policy.Refused, "regular file"):
            policy.verify_build_commit(self.repo, self.source, link)

    def test_build_outside_candidate_list_refuses(self):
        candidate = policy.discover(self.repo, self.baseline)
        candidate["build_commits"] = [self.source]
        with self.assertRaisesRegex(policy.Refused, "not permitted"):
            self.verify(candidate, self.approval)

    def test_provenance_bound_to_another_commit_refuses(self):
        candidate = policy.discover(self.repo, self.baseline)
        for build, attested in (
            (self.approval, self.source),
            (self.approval, self.dev),
            (self.source, self.approval),
        ):
            with (
                self.subTest(build=build, attested=attested),
                self.assertRaisesRegex(policy.Refused, "attestation signer"),
            ):
                self.verify(candidate, build, attested=attested)

    def test_artifact_naming_a_different_commit_refuses(self):
        candidate = policy.discover(self.repo, self.baseline)
        vendor, rebuilt = self.release(self.source)
        with self.assertRaisesRegex(policy.Refused, "source or environment"):
            policy.compare_artifacts(vendor, rebuilt, self.approval, "2" * 96)
        self.assertIn(self.approval, candidate["build_commits"])

    def test_reproduced_pcr_mismatch_refuses(self):
        candidate = policy.discover(self.repo, self.baseline)
        with self.assertRaisesRegex(policy.Refused, "reproduction mismatch"):
            self.verify(candidate, self.approval, reproduced_pcr="7" * 96)
        with self.assertRaisesRegex(policy.Refused, "measurement mismatch"):
            self.verify(
                candidate, self.approval, reproduced_pcr="7" * 96, vendor_pcr="7" * 96
            )

    def test_review_required_without_review_only_refuses(self):
        candidate = dict(policy.discover(self.repo, self.baseline), status="review_required")
        vendor, rebuilt = self.release(self.approval)
        with self.assertRaisesRegex(policy.Refused, "requires approval"):
            policy.verify_release(
                self.repo, candidate, vendor, rebuilt, self.approval
            )


class SubmoduleTests(VendorRepo):
    """A gitlink change must stay visible even if .gitmodules ignores it."""

    SUB = "services/opensecret/privatemode-public"

    def gitmodules(self, extra=""):
        self.write(
            ".gitmodules",
            f'[submodule "{self.SUB}"]\n\tpath = {self.SUB}\n'
            f"\turl = https://example.invalid/pm.git\n{extra}",
        )

    def gitlink(self, oid):
        self.git("update-index", "--add", "--cacheinfo", f"160000,{oid},{self.SUB}")

    def setUp(self):
        super().setUp()
        self.gitmodules()
        (self.repo / self.SUB).mkdir(parents=True)
        self.gitlink("1" * 40)
        base = self.commit()
        self.baseline.update(
            source_commit=base,
            security_boundary_sha256=policy.boundary(self.repo, base),
        )
        self.write("apps/chat/ui.rs", "v2\n")
        self.source = self.commit()
        # A "dev approval" that also swaps the submodule pointer.
        self.gitlink("e" * 40)
        self.write("services/opensecret/pcrDev.json", "dev")
        self.dev = self.commit()
        self.approval = self.approve()
        # A later, never-built master commit hides submodule changes from
        # porcelain diff for the whole clone.
        self.gitmodules("\tignore = all\n")
        self.commit()

    def test_fixture_reproduces_porcelain_blind_spot(self):
        hidden = self.git("diff", "--name-only", self.source, self.dev).split()
        self.assertNotIn(self.SUB, hidden)
        self.assertIn(self.SUB, policy.changed_paths(self.repo, self.source, self.dev))

    def test_ignored_gitlink_swap_cannot_be_a_build_commit(self):
        for build in (self.dev, self.approval):
            with (
                self.subTest(build=build),
                self.assertRaisesRegex(policy.Refused, "more than measurement"),
            ):
                policy.verify_build_commit(self.repo, self.source, build)
        self.assertEqual(
            policy.build_commits(self.repo, self.source, self.approval), [self.source]
        )
        stale = {
            "status": "automatic",
            "source_commit": self.source,
            "pcr0": "2" * 96,
            "security_boundary_sha256": self.baseline["security_boundary_sha256"],
            "build_commits": [self.source, self.dev, self.approval],
        }
        vendor, rebuilt = BuildCommitTests.release(self, self.approval)
        with self.assertRaisesRegex(policy.Refused, "more than measurement"):
            policy.verify_release(self.repo, stale, vendor, rebuilt, self.approval)

    def test_each_lineage_layer_alone_refuses_ignored_gitlink(self):
        def porcelain(repo, before, after):
            raw = policy.git(repo, "diff", "--name-only", "-z", before, after)
            return [path.decode() for path in raw.split(b"\0") if path]

        def permissive_tree(repo, before, after):
            return None

        with patch.object(policy, "changed_paths", porcelain):
            self.assertNotIn(self.SUB, porcelain(self.repo, self.source, self.dev))
            with self.assertRaisesRegex(policy.Refused, "more than measurement"):
                policy.verify_build_commit(self.repo, self.source, self.dev)
            with (
                patch.object(policy, "same_tree_except_measurements", permissive_tree),
                self.assertRaisesRegex(policy.Refused, "protected source tree"),
            ):
                policy.verify_build_commit(self.repo, self.source, self.dev)

    def test_ignored_gitlink_swap_is_source_for_existing_checks(self):
        self.assertEqual(policy.measurement_source(self.repo, self.approval), self.dev)
        with self.assertRaisesRegex(policy.Refused, "approvals only"):
            policy.verify_history(
                self.repo, self.source, self.approval, "2" * 96, self.baseline
            )
        candidate = policy.discover(self.repo, self.baseline)
        self.assertEqual(candidate["source_commit"], self.dev)
        self.assertEqual(candidate["status"], "review_required")
        self.assertIn(self.SUB, candidate["security_sensitive_paths"])
        self.assertEqual(candidate["build_commits"], [self.dev, self.approval])


class CommandLineTests(unittest.TestCase):
    def test_verify_requires_explicit_build(self):
        result = subprocess.run(
            [
                sys.executable,
                str(Path(policy.__file__)),
                "verify",
                "--vendor",
                "missing",
                "--candidate",
                "missing.json",
            ],
            capture_output=True,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"verify requires --build", result.stderr)


class ArtifactTests(unittest.TestCase):
    def test_full_bytes_not_just_measurement_must_match(self):
        with tempfile.TemporaryDirectory() as directory:
            vendor, rebuilt = (Path(directory) / name for name in ("vendor", "rebuilt"))
            pcr = {
                name: digit * 96
                for name, digit in (("PCR0", "1"), ("PCR1", "2"), ("PCR2", "3"))
            }
            handoff = {
                "source_sha": "a" * 40,
                "environment": "prod",
                "measurements": pcr,
                "eif_sha256": hashlib.sha256(b"example EIF").hexdigest(),
            }
            for root in (vendor, rebuilt):
                root.mkdir()
                (root / "image.eif").write_bytes(b"example EIF")
                (root / "pcr.json").write_text(json.dumps(pcr))
                (root / "handoff.json").write_text(json.dumps(handoff))
                (root / "SHA256SUMS").write_text("fixture")
            policy.compare_artifacts(vendor, rebuilt, "a" * 40, "1" * 96)
            (rebuilt / "image.eif").write_bytes(b"different EIF, identical PCR file")
            with self.assertRaisesRegex(policy.Refused, "reproduction mismatch"):
                policy.compare_artifacts(vendor, rebuilt, "a" * 40, "1" * 96)
            (rebuilt / "image.eif").unlink()
            (rebuilt / "image.eif").symlink_to(vendor / "image.eif")
            with self.assertRaisesRegex(policy.Refused, "symlinked"):
                policy.compare_artifacts(vendor, rebuilt, "a" * 40, "1" * 96)

    def test_provenance_checks_certificate_not_untrusted_predicate(self):
        cert = {
            "issuer": "https://token.actions.githubusercontent.com",
            "subjectAlternativeName": policy.WORKFLOW,
            "sourceRepositoryURI": "https://github.com/" + policy.VENDOR,
            "sourceRepositoryDigest": "a" * 40,
            "buildSignerDigest": "a" * 40,
            "sourceRepositoryRef": "refs/heads/master",
            "sourceRepositoryIdentifier": "923138240",
            "sourceRepositoryOwnerIdentifier": "322649754",
        }
        rows = [
            {
                "verificationResult": {
                    "signature": {"certificate": cert},
                    "verifiedTimestamps": [{"type": "Tlog"}],
                }
            }
        ]
        policy.verify_provenance_result(rows, "a" * 40)
        for field in cert:
            bad = copy.deepcopy(rows)
            bad[0]["verificationResult"]["signature"]["certificate"][field] = "wrong"
            with self.subTest(field=field), self.assertRaises(policy.Refused):
                policy.verify_provenance_result(bad, "a" * 40)
        with self.assertRaises(policy.Refused):
            policy.verify_provenance_result([], "a" * 40)

    def test_json_duplicates_and_nonfinite_fail(self):
        for raw in ('{"pcr0":"a","pcr0":"b"}', '{"value":NaN}', '{"value":Infinity}'):
            with self.subTest(raw=raw), self.assertRaises(policy.Refused):
                policy.strict_json(raw)


if __name__ == "__main__":
    unittest.main()
