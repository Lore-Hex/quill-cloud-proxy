#!/usr/bin/env python3
"""Hermetic release-gate tests. No network, credentials or inference."""

import base64
import copy
import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

import maple_policy as policy
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils


class ReleaseTests(unittest.TestCase):
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
        policy.stage(self.repo, candidate, evidence, root)
        self.assertIn(candidate["pcr0"], lib.read_text())
        self.assertNotIn(self.baseline["pcr0"], lib.read_text())
        updated = json.loads(baseline_path.read_text())
        self.assertEqual(
            updated["security_boundary_sha256"],
            self.baseline["security_boundary_sha256"],
        )


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
