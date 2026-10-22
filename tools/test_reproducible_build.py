"""Offline fail-closed tests; real two-builder digest comparisons gate releases."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("repro", ROOT / "tools/reproducible_build.py")
repro = importlib.util.module_from_spec(spec)
spec.loader.exec_module(repro)


class Reproducibility(unittest.TestCase):
    def record(self):
        return {"schema": "trustedrouter-reproducible-image/1", "source_commit": "a" * 40,
                "source_date_epoch": 1000, "plane": "gcp", "platform": "linux/amd64",
                "build_args": {}, "image_digest": "sha256:" + "b" * 64,
                "client_image": "docker@sha256:" + "c" * 64, "image_reference": "registry/repo:a"}

    def test_compare_complete_image_not_binary(self):
        a = self.record()
        b = copy.deepcopy(a)
        b["image_reference"] = "registry/repo:b"
        self.assertEqual(repro.compare([a, b]), a["image_digest"])
        for field in ("source_commit", "source_date_epoch", "plane", "platform", "build_args", "image_digest", "client_image"):
            with self.subTest(field=field):
                b = copy.deepcopy(a)
                b[field] = "different"
                with self.assertRaisesRegex(ValueError, "mismatch"):
                    repro.compare([a, b])

    def test_no_promotion_on_mismatch(self):
        a, b = self.record(), self.record()
        b["image_digest"] = "sha256:" + "d" * 64
        with patch.object(repro.subprocess, "run") as mutation:
            with self.assertRaises(ValueError):
                repro.promote([a, b], "prod/image:release")
            mutation.assert_not_called()

    def test_two_builds_required(self):
        with self.assertRaises(ValueError):
            repro.compare([self.record()])

    def test_dirty_source_rejected_before_docker(self):
        with patch.object(repro, "run", return_value=" M enclave-go/main.go"):
            with self.assertRaisesRegex(ValueError, "dirty"):
                repro.require_clean()

    def test_full_revision_resolution(self):
        for ref in ("a" * 7, "a" * 8, "a" * 40):
            with patch.object(repro, "run", return_value="a" * 40) as git:
                self.assertEqual(repro.source_commit(ref), "a" * 40)
                self.assertIn(ref + "^{commit}", git.call_args.args)

    def test_reserved_build_arguments_cannot_be_overridden(self):
        for plane in ("gcp", "aws", "azure"):
            for key in ("SOURCE_REVISION", "SOURCE_DATE_EPOCH", "BUILDKIT_SYNTAX"):
                with self.assertRaises(ValueError):
                    repro.build_args(plane, [key + "=evil"])

    def test_production_dockerfiles_pin_inputs_and_include_every_binary(self):
        for name in ("Dockerfile.enclave", "Dockerfile.enclave.gcp.multi", "Dockerfile.enclave.azure.multi"):
            text = (ROOT / "enclave-go" / name).read_text()
            self.assertRegex(text.splitlines()[0], r"^# syntax=.+@sha256:[0-9a-f]{64}$")
            self.assertNotIn("apt-get", text)
            self.assertIn("GOTOOLCHAIN=local", text)
            self.assertIn("GOFLAGS=-mod=readonly", text)
            for binary in ("/quill-enclave", "/attest-sidecar", "/privatemode-proxy"):
                self.assertIn(binary, text)

    def test_worker_normalizes_timestamps_without_embedded_provenance(self):
        text = (ROOT / "tools/build-enclave-context.sh").read_text()
        for flag in ("--no-cache", "SOURCE_DATE_EPOCH=$epoch", "rewrite-timestamp=true",
                     "--provenance=false", "--sbom=false", "--metadata-file",
                     '--driver-opt "image=$REPRO_BUILDKIT"'):
            self.assertIn(flag, text)


if __name__ == "__main__":
    unittest.main()
