from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools import aws_eif_manifest as manifest
from tools import publish_aws_eif as publisher


class StorageError(Exception):
    def __init__(self, code):
        self.response = {"Error": {"Code": code}}


class Store:
    def __init__(self):
        self.objects = {}
        self.writes = []

    def head_object(self, *, Bucket, Key, ChecksumMode):
        if Key not in self.objects:
            raise StorageError("404")
        body = self.objects[Key]
        return {"ContentLength": len(body), "ChecksumSHA256": base64.b64encode(hashlib.sha256(body).digest()).decode()}

    def put_object(self, **args):
        assert args["IfNoneMatch"] == "*"
        assert args["ServerSideEncryption"] == "AES256"
        key = args["Key"]
        if key in self.objects:
            raise StorageError("PreconditionFailed")
        body = args["Body"].read() if hasattr(args["Body"], "read") else args["Body"]
        assert len(body) == args["ContentLength"]
        assert base64.b64encode(hashlib.sha256(body).digest()).decode() == args["ChecksumSHA256"]
        self.objects[key] = body
        self.writes.append(key)

    def get_object(self, *, Bucket, Key):
        return {"ContentLength": len(self.objects[Key]), "Body": io.BytesIO(self.objects[Key])}


class PublicationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.eif = Path(self.temp.name) / "enclave.eif"
        self.eif.write_bytes(b"test-only EIF")
        self.record = {
            "schema": manifest.SCHEMA, "source_commit": "a" * 40,
            "builder_image": "330422590279.dkr.ecr.eu-west-1.amazonaws.com/quill-enclave-eif-builder@sha256:" + "b" * 64,
            "enclave_image_id": "sha256:" + "c" * 64, "nitro_cli_version": "1.5.3",
            "eif_sha256": hashlib.sha256(self.eif.read_bytes()).hexdigest(),
            "eif_size_bytes": self.eif.stat().st_size,
            "measurements": {"PCR0": "1" * 96, "PCR1": "2" * 96, "PCR2": "3" * 96},
        }
        self.data = json.dumps(self.record).encode()
        self.prefix = manifest.artifact_prefix(self.record)
        self.store = Store()

    def publish(self, signature=b"{}"):
        return publisher.publish_region(self.store, "eu-west-1", self.record, self.eif, self.data, signature)

    def test_idempotent_publish_commits_manifest_last(self):
        with patch.object(manifest, "verify", return_value=self.record) as verify:
            location = self.publish()
            self.publish(b'{"different_valid_signature":true}')
        self.assertEqual(len(self.store.writes), 3)
        self.assertEqual(self.store.writes[-1], self.prefix + "/manifest.json")
        self.assertEqual(self.store.objects[self.prefix + "/manifest.json.bundle"], b"{}")
        self.assertEqual(verify.call_count, 2)
        self.assertEqual(location, "s3://quill-enclave-eif-eu-west-1-330422590279/" + self.prefix + "/")

    def test_partial_release_resumes_without_replacing_existing_eif(self):
        self.store.objects[self.prefix + "/enclave.eif"] = self.eif.read_bytes()
        with patch.object(manifest, "verify", return_value=self.record):
            self.publish()
        self.assertEqual(len(self.store.writes), 2)

    def test_substituted_eif_blocks_metadata_publication(self):
        self.store.objects[self.prefix + "/enclave.eif"] = b"attacker"
        with self.assertRaisesRegex(ValueError, "checksum/size"), patch.object(manifest, "verify") as verify:
            self.publish()
        verify.assert_not_called()
        self.assertEqual(self.store.writes, [])

    def test_bad_published_signature_blocks_completion_marker(self):
        with (patch.object(manifest, "verify", side_effect=ValueError("bad signature")),
              self.assertRaisesRegex(ValueError, "bad signature")):
            self.publish()
        self.assertNotIn(self.prefix + "/manifest.json", self.store.objects)

    def test_permission_failure_is_not_treated_as_missing(self):
        with (patch.object(self.store, "head_object", side_effect=StorageError("AccessDenied")),
              self.assertRaises(StorageError)):
            self.publish()
        self.assertEqual(self.store.writes, [])

    def test_manifest_collision_is_not_overwritten(self):
        self.store.objects[self.prefix + "/manifest.json"] = b"substituted metadata"
        with (patch.object(manifest, "verify", return_value=self.record),
              self.assertRaisesRegex(ValueError, "manifest differs")):
            self.publish()
        self.assertEqual(self.store.objects[self.prefix + "/manifest.json"], b"substituted metadata")

    def test_unknown_region_is_rejected_before_storage(self):
        with self.assertRaisesRegex(ValueError, "unapproved"):
            publisher.publish_region(self.store, "us-east-1", self.record, self.eif, self.data, b"{}")
        self.assertEqual(self.store.writes, [])

    def test_oversized_signature_is_rejected(self):
        self.store.objects[self.prefix + "/manifest.json.bundle"] = b" " * (manifest.MAX_BUNDLE_BYTES + 1)
        with self.assertRaisesRegex(ValueError, "size limit"):
            self.publish()
        self.assertNotIn(self.prefix + "/manifest.json", self.store.objects)


class WorkflowTests(unittest.TestCase):
    def test_publication_is_main_only_digest_pinned_and_not_a_deploy(self):
        import yaml
        root = Path(__file__).resolve().parents[1]
        workflow = yaml.safe_load((root / ".github/workflows/publish-aws-eif.yml").read_text())
        job = workflow["jobs"]["publish"]
        self.assertEqual(job["if"], "github.ref == 'refs/heads/main'")
        self.assertRegex(job["env"]["BUILDER_IMAGE"], r"^330422590279\.dkr\.ecr\.eu-west-1\.amazonaws\.com/quill-enclave-eif-builder@sha256:[0-9a-f]{64}$")
        self.assertEqual(workflow["permissions"], {"contents": "read", "actions": "read", "id-token": "write"})
        scripts = "\n".join(step.get("run", "") for step in job["steps"])
        for value in ("SOURCE_REVISION=$GITHUB_SHA", "BUILD_TAGS=cloud_aws,llm_multi", "QUILL_TLS_MODE=acme",
                      "QUILL_API_HOST=api-aws.trustedrouter.com", "QUILL_ACME_DNS_GCP_PROJECT=quill-cloud-proxy",
                      "QUILL_ACME_DNS_MANAGED_ZONE=trustedrouter-com", "--platform linux/amd64", "--expected-source"):
            self.assertIn(value, scripts)
        self.assertNotIn("run-enclave", scripts)
        self.assertNotIn("start-instance-refresh", scripts)
        self.assertNotIn("put-key-policy", scripts)

    def test_independent_public_recipe_agrees_before_signing(self):
        import yaml
        root = Path(__file__).resolve().parents[1]
        jobs = yaml.safe_load((root / ".github/workflows/publish-aws-eif.yml").read_text())["jobs"]
        self.assertEqual(jobs["independent"]["permissions"], {"contents": "read"})
        self.assertEqual(jobs["publish"]["needs"], "independent")
        steps = jobs["publish"]["steps"]
        names = [s.get("name") for s in steps]
        check = names.index("Verify independent full EIF bytes before signing")
        self.assertLess(check, names.index("Sign and verify with this workflow identity"))
        self.assertLess(check, names.index("Publish create-only artifacts to both regions"))
        self.assertNotIn("continue-on-error", steps[check])
        self.assertNotIn("if", steps[check])
        for key in ("eif_sha256", "eif_size_bytes", "source_commit", "enclave_image_id", "measurements"):
            self.assertIn(key, steps[check]["run"])
        self.assertIn("diff -u", steps[check]["run"])

    def test_full_ci_gate_refuses_missing_pending_failed_or_wrong_source(self):
        import yaml
        root = Path(__file__).resolve().parents[1]
        workflow = yaml.safe_load((root / ".github/workflows/publish-aws-eif.yml").read_text())
        steps = workflow["jobs"]["publish"]["steps"]
        gate_index = next(i for i, step in enumerate(steps)
                          if step.get("name") == "Require successful complete CI for this source")
        gate = steps[gate_index]
        self.assertNotIn("if", gate)
        self.assertNotIn("continue-on-error", gate)
        self.assertLess(gate_index, next(i for i, step in enumerate(steps)
                                       if step.get("name", "").startswith("Build the measured")))
        self.assertLess(gate_index, next(i for i, step in enumerate(steps)
                                       if "/aws-credentials@" in step.get("uses", "")))
        good = {"status": "completed", "conclusion": "success", "headSha": "a" * 40,
                "headBranch": "main", "event": "push"}
        cases = [([], False), ([good], True)]
        for key, value in (("status", "queued"), ("conclusion", "failure"),
                           ("headSha", "b" * 40), ("headBranch", "topic"), ("event", "pull_request")):
            cases.append(([{**good, key: value}], False))
        with tempfile.TemporaryDirectory() as directory:
            temporary = Path(directory)
            gh = temporary / "gh"
            gh.write_text("#!/bin/sh\nprintf '%s' \"$FAKE_CI_RUNS\"\n")
            gh.chmod(0o700)
            for runs, accepted in cases:
                with self.subTest(runs=runs):
                    env = {"PATH": directory + os.pathsep + os.environ["PATH"],
                           "GITHUB_SHA": good["headSha"], "GITHUB_REPOSITORY": "Lore-Hex/quill-cloud-proxy",
                           "RUNNER_TEMP": directory, "FAKE_CI_RUNS": json.dumps(runs)}
                    result = subprocess.run(["bash", "-e", "-c", gate["run"]], env=env,
                                            capture_output=True, text=True, check=False, timeout=10)
                    self.assertEqual(result.returncode == 0, accepted, result.stderr)


if __name__ == "__main__":
    unittest.main()
