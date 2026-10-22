"""Offline fail-closed tests; real two-builder digest comparisons gate releases."""
import copy
import hashlib
import importlib.util
import io
import json
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("repro", ROOT / "tools/reproducible_build.py")
repro = importlib.util.module_from_spec(spec)
spec.loader.exec_module(repro)


class Reproducibility(unittest.TestCase):
    def archive(self, destination, corruption=None):
        config = b'{"architecture":"amd64","os":"linux"}'
        layer = b"all binaries, certificates and file metadata"
        def digest(data):
            return "sha256:" + hashlib.sha256(data).hexdigest()
        manifest = json.dumps({"config": {"digest": digest(config)},
                               "layers": [{"digest": digest(layer)}]}).encode()
        descriptor = {"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": digest(manifest)}
        manifests = [descriptor, descriptor] if corruption == "index" else [descriptor]
        with tarfile.open(destination, "w") as archive:
            entries = {"index.json": json.dumps({"manifests": manifests}).encode(),
                       "blobs/sha256/" + digest(manifest)[7:]: manifest,
                       "blobs/sha256/" + digest(config)[7:]: config,
                       "blobs/sha256/" + digest(layer)[7:]: layer}
            bad = {"manifest": manifest, "config": config, "layer": layer}.get(corruption)
            if bad is not None:
                entries["blobs/sha256/" + digest(bad)[7:]] = b"changed"
            for name, data in entries.items():
                entry = tarfile.TarInfo(name)
                entry.size = len(data)
                archive.addfile(entry, io.BytesIO(data))
        return digest(manifest)

    def test_archive_verifies_manifest_config_and_every_layer(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "image.tar"
            expected = self.archive(path)
            self.assertEqual(repro.archive_digest(path), expected)
            for corruption in ("manifest", "config", "layer", "index"):
                with self.subTest(corruption=corruption):
                    self.archive(path, corruption)
                    with self.assertRaises(ValueError):
                        repro.archive_digest(path)

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

    def test_manual_release_never_builds_or_promotes_after_vendor_rebuild_failure(self):
        argv = ["reproducible_build.py", "release", "--plane", "aws", "--commit", "a" * 40,
                "--image", "registry.example.invalid/release", "--output-dir", "/tmp/test-evidence"]
        with patch.object(sys, "argv", argv), \
                patch.object(repro, "require_clean"), \
                patch.object(repro, "source_commit", return_value="a" * 40), \
                patch.object(repro, "verify_vendor_source", side_effect=subprocess.CalledProcessError(1, "verify")), \
                patch.object(repro, "build") as build, patch.object(repro, "promote") as promote:
            with self.assertRaises(subprocess.CalledProcessError):
                repro.main()
            build.assert_not_called()
            promote.assert_not_called()

    def test_wrong_release_commit_is_not_promoted(self):
        with patch.object(repro.subprocess, "run") as mutation:
            with self.assertRaisesRegex(ValueError, "different release commit"):
                repro.promote([self.record(), self.record()], "prod/image:release", "d" * 40)
            mutation.assert_not_called()

    def test_release_gate_uses_independent_runners_and_no_rollout_bypass(self):
        import yaml
        workflow = yaml.safe_load((ROOT / ".github/workflows/deploy-enclave-gcp.yml").read_text())
        jobs = workflow["jobs"]
        self.assertEqual(jobs["reproduce-image"]["strategy"]["matrix"]["builder"], [1, 2])
        self.assertIn("reproduce-image", jobs["build-and-release"]["needs"])
        steps = jobs["build-and-release"]["steps"]
        compare_at = next(i for i, s in enumerate(steps) if "reproducible_build.py promote" in s.get("run", ""))
        publish_at = next(i for i, s in enumerate(steps) if "write-trust-artifacts.py" in s.get("run", ""))
        self.assertLess(compare_at, publish_at)

    def test_dirty_source_rejected_before_docker(self):
        with patch.object(repro, "run", return_value=" M enclave-go/main.go"), self.assertRaisesRegex(ValueError, "dirty"):
            repro.require_clean()

    def test_client_auth_is_read_only_and_buildx_state_is_not_host_mounted(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config = root / "docker"
            config.mkdir()
            (config / "config.json").write_text(json.dumps({
                "auths": {"registry.example.invalid": {"auth": "test-only"}},
                "currentContext": "host-only",
                "credsStore": "host-keychain",
            }))

            def source(_commit, context):
                (context / "tools").mkdir()
                (context / "tools/reproducible-build.env").write_text(
                    "REPRO_CLIENT='docker@sha256:" + "c" * 64 + "'\n"
                )

            def client(command, **_kwargs):
                mounts = [command[i + 1] for i, arg in enumerate(command) if arg == "--volume"]
                auth = next(item for item in mounts if "/root/.docker/" in item)
                self.assertTrue(auth.endswith(":/root/.docker/config.json:ro"))
                self.assertFalse(any(item.endswith(":/root/.docker") for item in mounts))
                self.assertEqual(json.loads(Path(auth.split(":")[0]).read_text()), {
                    "auths": {"registry.example.invalid": {"auth": "test-only"}}
                })
                (root / "output/build-metadata.json").write_text(json.dumps({
                    "containerimage.digest": "sha256:" + "b" * 64
                }))

            with patch.dict(repro.os.environ, {"DOCKER_CONFIG": str(config)}), \
                    patch.object(repro, "archive_source", side_effect=source), \
                    patch.object(repro, "docker_socket", return_value="/test/docker.sock"), \
                    patch.object(repro, "run", return_value="1000"), \
                    patch.object(repro.subprocess, "run", side_effect=client):
                repro.build("gcp", "a" * 40, root / "output", [], "registry.example.invalid/test:build")

    def test_vulnerable_cosign_cannot_verify_a_release(self):
        for version in ("v2.6.4", "v3.1.2", "v2.6.5", "v3.1.4"):
            with patch.object(repro, "run", return_value=json.dumps({"gitVersion": version})):
                if version in ("v2.6.4", "v3.1.2"):
                    with self.assertRaises(ValueError):
                        repro.require_safe_cosign()
                else:
                    repro.require_safe_cosign()

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
