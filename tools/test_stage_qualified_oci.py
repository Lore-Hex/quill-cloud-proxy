import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class StageComparedBytes(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.archive = self.dir / "image.tar"
        self.log = self.dir / "calls"
        with tarfile.open(self.archive, "w") as arc:
            def add(name, data):
                info = tarfile.TarInfo(name)
                info.size = len(data)
                arc.addfile(info, io.BytesIO(data))

            def blob(kind, data):
                h = hashlib.sha256(data).hexdigest()
                add("blobs/sha256/" + h, data)
                return {"mediaType": "application/vnd.oci.image." + kind, "size": len(data),
                        "digest": "sha256:" + h}

            config = blob("config.v1+json", b'{"os":"linux","architecture":"amd64"}')
            layer = blob("layer.v1.tar+gzip", b"layer")
            data = json.dumps({"schemaVersion": 2, "config": config, "layers": [layer]}).encode()
            (self.dir / "manifest").write_bytes(data)
            manifest = blob("manifest.v1+json", data)
            self.digest = manifest["digest"]
            add("index.json", json.dumps({"manifests": [manifest]}).encode())
        for name, body in {
            "az": 'echo az >> "$LOG"; echo fixture',
            "gcloud": 'echo gcloud >> "$LOG"; echo fixture',
            "skopeo": 'echo "$*" >> "$LOG"; case "$1" in login) cat >/dev/null;; inspect) cat "$MANIFEST";; copy) exit 0;; *) exit 1;; esac',
        }.items():
            path = self.dir / name
            path.write_text("#!/bin/sh\n" + body + "\n")
            path.chmod(0o700)

    def stage(self, plane, digest):
        return subprocess.run(["bash", str(ROOT / "tools/stage-qualified-oci.sh"), plane,
                               "a" * 40, digest, str(self.archive)], text=True, capture_output=True,
                              env={**os.environ, "PATH": str(self.dir) + ":" + os.environ["PATH"],
                                   "LOG": str(self.log), "MANIFEST": str(self.dir / "manifest")})

    def test_both_registry_targets_preserve_digest(self):
        for plane, registry in [("gcp", "us-central1-docker.pkg.dev"), ("azure", "trquillacr.azurecr.io")]:
            with self.subTest(plane=plane):
                p = self.stage(plane, self.digest)
                self.assertEqual(0, p.returncode, p.stderr)
                receipt = json.loads(p.stdout)
                self.assertTrue(receipt["registry_image"].startswith(registry + "/"))
                self.assertTrue(receipt["registry_image"].endswith("@" + self.digest))
                self.assertIn("--preserve-digests", self.log.read_text())

    def test_mismatch_is_rejected_before_obtaining_credentials(self):
        self.assertNotEqual(0, self.stage("gcp", "sha256:" + "c" * 64).returncode)
        self.assertFalse(self.log.exists())

    def test_changed_registry_bytes_cannot_produce_a_receipt(self):
        (self.dir / "manifest").write_text("changed")
        run = self.stage("azure", self.digest)
        self.assertNotEqual(0, run.returncode)
        self.assertEqual("", run.stdout)
