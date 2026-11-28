import hashlib
import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path

from tools.verify_release_oci import verify


class ReleaseOCI(unittest.TestCase):
    def check(self, mutation=None):
        blobs = {}

        def descriptor(data, kind):
            digest = hashlib.sha256(data).hexdigest()
            blobs["blobs/sha256/" + digest] = data
            return {"mediaType": "application/vnd.oci.image." + kind,
                    "size": len(data), "digest": "sha256:" + digest}

        layer = descriptor(b"compressed layer bytes", "layer.v1.tar+gzip")
        arch = "arm64" if mutation == "arch" else "amd64"
        config = descriptor(json.dumps({"os": "linux", "architecture": arch}).encode(), "config.v1+json")
        if mutation == "size":
            layer["size"] += 1
        manifest = descriptor(json.dumps({"schemaVersion": 2, "layers": [layer], "config": config}).encode(),
                              "manifest.v1+json")
        index = [manifest, manifest] if mutation == "multi" else [manifest]
        blobs["index.json"] = json.dumps({"manifests": index}).encode()
        if mutation in {"layer", "config", "manifest"}:
            digest = {"layer": layer, "config": config, "manifest": manifest}[mutation]["digest"]
            key = "blobs/sha256/" + digest[7:]
            blobs[key] = b"x" * len(blobs[key])
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "image.tar"
            with tarfile.open(path, "w") as archive:
                for name, data in blobs.items():
                    member = tarfile.TarInfo(name)
                    member.size = len(data)
                    archive.addfile(member, io.BytesIO(data))
                    if mutation == "duplicate" and name == "index.json":
                        archive.addfile(member, io.BytesIO(data))
            digest = layer["digest"] if mutation == "exporter" else manifest["digest"]
            return verify(path, {"containerimage.digest": digest}, "azure", "a" * 40)

    def test_complete(self):
        self.assertEqual("azure", self.check()["plane"])

    def test_no_partial_or_ambiguous_proof(self):
        for mutation in ("layer", "config", "manifest", "size", "multi", "exporter", "duplicate", "arch"):
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.check(mutation)
