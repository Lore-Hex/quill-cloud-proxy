from __future__ import annotations

import copy
import io
import json
import subprocess
import unittest
import urllib.error
from unittest.mock import patch

from tools import aws_eif_admission as admission
from tools import test_aws_eif_manifest as fixtures


class AdmissionTests(unittest.TestCase):
    def setUp(self):
        fixtures.EIFManifestTests.setUp(self)
        self.trust = self.root / "trust-page" / "trust"
        self.trust.mkdir(parents=True)
        self.current = {
            "platform": "aws-nitro-enclaves", "pcr0": "4" * 96,
            "accepted_pcr0s": ["4" * 96, "5" * 96], "source_commit": "d" * 40,
            "source_commit_provenance": "operator-asserted", "observed_module_id": "live-instance",
        }
        (self.trust / "aws-release.json").write_text(json.dumps(self.current))

    def test_stage_preserves_all_serving_provenance_and_old_measurements(self):
        with patch.object(admission.manifests.subprocess, "run"):
            result = admission.prepare(self.path, self.signature, "a" * 40, write=True, trust=self.trust)
            artifact = admission.verify_record(self.trust / "aws-release.json")
        self.assertEqual(artifact, self.record)
        for key in ("pcr0", "source_commit", "source_commit_provenance", "observed_module_id"):
            self.assertEqual(result[key], self.current[key])
        self.assertEqual(set(result["accepted_pcr0s"]), {"1" * 96, "4" * 96, "5" * 96})
        self.assertFalse(result["candidate_eif"]["observed_serving"])
        self.assertEqual((self.trust / "aws-release.json").read_bytes(),
                         (self.trust.parent / "aws-release.json").read_bytes())

    def test_bad_signature_and_source_fail_before_writes(self):
        baseline = (self.trust / "aws-release.json").read_bytes()
        for error in (ValueError("wrong source"), subprocess.CalledProcessError(1, "cosign")):
            with patch.object(admission, "verified_snapshot", side_effect=error), self.assertRaises(type(error)):
                admission.prepare(self.path, self.signature, "a" * 40, write=True, trust=self.trust)
            self.assertEqual((self.trust / "aws-release.json").read_bytes(), baseline)
            self.assertFalse((self.trust / "eif").exists())

    def test_conflicting_pending_candidate_is_not_overwritten(self):
        first = admission.staged_record(self.current, self.record, self.path.read_bytes())
        changed = copy.deepcopy(self.record)
        changed["source_commit"] = "e" * 40
        with self.assertRaisesRegex(ValueError, "another candidate"):
            admission.staged_record(first, changed, self.path.read_bytes())

    def test_candidate_probe_uses_ci_pcr0_not_a_host_report(self):
        with patch.object(admission, "verified_snapshot", return_value=(self.record, b"", b"")), \
             patch.object(admission.subprocess, "run") as run:
            admission.verify_candidate(self.path, self.signature, "a" * 40, 18444)
        args = run.call_args.args[0]
        self.assertEqual(args[-2:], ["--expected-pcr0", "1" * 96])
        self.assertTrue(run.call_args.kwargs["check"])

    def test_wrong_candidate_measurement_aborts_without_writes(self):
        before = (self.trust / "aws-release.json").read_bytes()
        with patch.object(admission, "verified_snapshot", return_value=(self.record, b"", b"")), \
             patch.object(admission.subprocess, "run", side_effect=subprocess.CalledProcessError(1, "verify-attestation")), \
             self.assertRaises(subprocess.CalledProcessError):
            admission.verify_candidate(self.path, self.signature, "a" * 40, 18444)
        self.assertEqual((self.trust / "aws-release.json").read_bytes(), before)

    def test_public_candidate_reference_tampering_is_rejected(self):
        with patch.object(admission.manifests.subprocess, "run"):
            result = admission.prepare(self.path, self.signature, "a" * 40, write=True, trust=self.trust)
            for field, wrong in (("pcr0", "6" * 96), ("manifest", "../../other"),
                                 ("signing_identity", "other"), ("observed_serving", True)):
                changed = copy.deepcopy(result)
                changed["candidate_eif"][field] = wrong
                (self.trust / "aws-release.json").write_text(json.dumps(changed))
                with self.assertRaises(ValueError):
                    admission.verify_record(self.trust / "aws-release.json")

    def test_public_record_must_match_local_bytes_and_aws_signer_identity(self):
        path = self.trust / "aws-release.json"
        raw = path.read_bytes()
        with patch.object(admission.urllib.request, "urlopen",
                          side_effect=[io.BytesIO(raw), io.BytesIO(b"public-signature")]) as fetch, \
             patch.object(admission.subprocess, "run") as run:
            self.assertEqual(admission.require_published(path), self.current)
        self.assertEqual([call.args[0] for call in fetch.call_args_list], [
            "https://trust.trustedrouter.com/trust/aws-release.json",
            "https://trust.trustedrouter.com/trust/aws-release.json.bundle",
        ])
        self.assertTrue(all(call.kwargs["timeout"] == 20 for call in fetch.call_args_list))
        self.assertIn(admission.PUBLIC_IDENTITY, run.call_args.args[0])
        with patch.object(admission.urllib.request, "urlopen",
                          side_effect=[io.BytesIO(b"stale"), io.BytesIO(b"signature")]), \
             patch.object(admission.subprocess, "run") as run, \
             self.assertRaisesRegex(ValueError, "not caught up"):
            admission.require_published(path)
        run.assert_not_called()

    def test_public_http_failure_cannot_widen_runtime(self):
        error = urllib.error.HTTPError(admission.PUBLIC_RECORD, 404, "Not Found", {}, None)
        self.addCleanup(error.close)
        with patch.object(admission, "TRUST", self.trust), \
             patch.object(admission, "verify_record", return_value=self.record), \
             patch.object(admission.urllib.request, "urlopen", side_effect=error), \
             patch.object(admission.subprocess, "run") as run, self.assertRaises(urllib.error.HTTPError):
            admission.widen_runtime()
        run.assert_not_called()

    def test_bad_public_signature_cannot_widen_runtime(self):
        with patch.object(admission, "verify_record", return_value=self.record), \
             patch.object(admission, "require_published",
                          side_effect=subprocess.CalledProcessError(1, "cosign")), \
             patch.object(admission.subprocess, "run") as run, \
             self.assertRaises(subprocess.CalledProcessError):
            admission.widen_runtime()
        run.assert_not_called()

    def test_runtime_widening_checks_fence_first_and_preserves_serving_source(self):
        with patch.object(admission, "verify_record", return_value=self.record), \
             patch.object(admission, "require_published", return_value=self.current), \
             patch.object(admission.subprocess, "run") as run:
            admission.widen_runtime()
        calls = [call.args[0] for call in run.call_args_list]
        self.assertIn("assert", calls[0])
        self.assertEqual(calls[1][-3:], ["--keep-accepted", "--source-commit", "d" * 40])
        self.assertNotIn("--write", calls[1])
        self.assertIn("--check-published", calls[2])

    def test_lost_fence_aborts_before_runtime_change(self):
        with patch.object(admission, "verify_record", return_value=self.record), \
             patch.object(admission, "require_published", return_value=self.current), \
             patch.object(admission.subprocess, "run",
                          side_effect=subprocess.CalledProcessError(1, "cloud-rollout")) as run, \
             self.assertRaises(subprocess.CalledProcessError):
            admission.widen_runtime()
        self.assertEqual(run.call_count, 1)

    def test_kms_disagreement_blocks_runtime_widening(self):
        with patch.object(admission, "verify_record", return_value=self.record), \
             patch.object(admission, "require_published", return_value=self.current), \
             patch.object(admission.subprocess, "run") as run, \
             patch.object(admission.aws_kms_admission, "check_keys", side_effect=ValueError("stale KMS set")) as kms, \
             self.assertRaisesRegex(ValueError, "stale KMS"):
            admission.widen_runtime()
        kms.assert_called_once_with(self.current["accepted_pcr0s"])
        self.assertEqual(run.call_count, 1)
        self.assertIn("assert", run.call_args.args[0])

    def test_kms_disagreement_blocks_candidate_readiness(self):
        with patch.object(admission, "verified_snapshot", return_value=(self.record, b"", b"")), \
             patch.object(admission, "verify_record", return_value=self.record), \
             patch.object(admission, "require_published", return_value=self.current), \
             patch.object(admission.subprocess, "run") as run, \
             patch.object(admission.aws_kms_admission, "check_keys", side_effect=ValueError("stale KMS set")) as kms, \
             self.assertRaisesRegex(ValueError, "stale KMS"):
            admission.check_ready(self.path, self.signature, "a" * 40)
        kms.assert_called_once_with(self.current["accepted_pcr0s"])
        self.assertEqual(run.call_count, 1)
        self.assertIn("assert", run.call_args.args[0])

    def test_ready_gate_requires_exact_staged_artifact_before_public_or_runtime_reads(self):
        with patch.object(admission, "TRUST", self.trust), \
             patch.object(admission, "verified_snapshot", return_value=(self.record, b"", b"")), \
             patch.object(admission, "verify_record", return_value=None), \
             patch.object(admission, "require_published") as public, \
             patch.object(admission.subprocess, "run") as run, \
             self.assertRaisesRegex(ValueError, "not the exact current"):
            admission.check_ready(self.path, self.signature, "a" * 40)
        public.assert_not_called()
        run.assert_not_called()

    def test_parent_only_roll_requires_exact_completed_ci_release(self):
        current = {**self.current, "pcr0": "1" * 96, "accepted_pcr0s": ["1" * 96],
                   "source_commit": "a" * 40, "release_state": "current"}
        (self.trust / "aws-release.json").write_text(json.dumps(current))
        with patch.object(admission, "TRUST", self.trust), \
             patch.object(admission, "verified_snapshot", return_value=(self.record, b"", b"")), \
             patch.object(admission, "require_published", return_value=current) as public, \
             patch.object(admission.aws_kms_admission, "check_keys") as kms, \
             patch.object(admission.subprocess, "run") as run:
            admission.check_ready(self.path, self.signature, "a" * 40)
        public.assert_called_once_with(self.trust / "aws-release.json")
        kms.assert_called_once_with(["1" * 96])
        calls = [call.args[0] for call in run.call_args_list]
        self.assertIn("assert", calls[0])
        self.assertEqual(calls[1][-3:], ["--plane", "aws", "--check-published"])
        self.assertEqual(len(calls), 2)

    def test_parent_only_roll_rejects_changed_source_measurement_and_transition(self):
        current = {**self.current, "pcr0": "1" * 96, "accepted_pcr0s": ["1" * 96],
                   "source_commit": "a" * 40, "release_state": "current"}
        for change in ({"source_commit": "d" * 40}, {"release_state": "rolling"},
                       {"accepted_pcr0s": ["1" * 96, "4" * 96]},
                       {"pcr0": "4" * 96, "accepted_pcr0s": ["4" * 96]}):
            with self.subTest(change=change):
                (self.trust / "aws-release.json").write_text(json.dumps({**current, **change}))
                with patch.object(admission, "TRUST", self.trust), \
                     patch.object(admission, "verified_snapshot", return_value=(self.record, b"", b"")), \
                     patch.object(admission, "require_published") as public, \
                     patch.object(admission.subprocess, "run") as run, \
                     self.assertRaisesRegex(ValueError, "not the exact current"):
                    admission.check_ready(self.path, self.signature, "a" * 40)
                public.assert_not_called()
                run.assert_not_called()

    def test_active_candidate_cannot_be_bypassed_by_current_eif(self):
        wrong = copy.deepcopy(self.record)
        wrong["source_commit"] = "e" * 40
        with patch.object(admission, "verified_snapshot", return_value=(self.record, b"", b"")), \
             patch.object(admission, "verify_record", return_value=wrong), \
             patch.object(admission, "require_published") as public, \
             self.assertRaisesRegex(ValueError, "not the staged"):
            admission.check_ready(self.path, self.signature, "a" * 40)
        public.assert_not_called()

    def test_current_release_change_during_public_check_blocks_readiness(self):
        current = {**self.current, "pcr0": "1" * 96, "accepted_pcr0s": ["1" * 96],
                   "source_commit": "a" * 40, "release_state": "current"}
        (self.trust / "aws-release.json").write_text(json.dumps(current))
        with patch.object(admission, "TRUST", self.trust), \
             patch.object(admission, "verified_snapshot", return_value=(self.record, b"", b"")), \
             patch.object(admission, "require_published", return_value=self.current), \
             patch.object(admission.subprocess, "run") as run, \
             self.assertRaisesRegex(ValueError, "changed during verification"):
            admission.check_ready(self.path, self.signature, "a" * 40)
        run.assert_not_called()

    def test_ready_gate_checks_public_fence_and_runtime_without_mutation(self):
        with patch.object(admission, "verified_snapshot", return_value=(self.record, b"", b"")), \
             patch.object(admission, "verify_record", return_value=self.record), \
             patch.object(admission, "require_published", return_value=self.current) as public, \
             patch.object(admission.subprocess, "run") as run:
            admission.check_ready(self.path, self.signature, "a" * 40)
        public.assert_called_once()
        calls = [call.args[0] for call in run.call_args_list]
        self.assertIn("assert", calls[0])
        self.assertEqual(calls[1][-3:], ["--plane", "aws", "--check-published"])
        self.assertTrue(all("--repin-aws-monitor" not in call and "--write" not in call for call in calls))

    def test_malformed_current_record_fails_closed(self):
        for bad in ([], [{}], ["0" * 96], ["4" * 96, "4" * 96]):
            with self.assertRaises(ValueError):
                admission.validate_current({**self.current, "accepted_pcr0s": bad})
        with self.assertRaises(ValueError):
            admission.validate_current({**self.current, "source_commit": None})


if __name__ == "__main__":
    unittest.main()
