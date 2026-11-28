"""Verify the single runnable OCI manifest and every referenced blob, not the transport tar."""

import hashlib
import json
import re
import sys
import tarfile


def verify(path, build, plane, source):
    if plane not in {"gcp", "azure"} or not re.fullmatch("[0-9a-f]{40}", source):
        raise ValueError("invalid plane or source")
    with tarfile.open(path, mode="r:") as archive:
        names = archive.getnames()
        if len(set(names)) != len(names):
            raise ValueError("duplicate archive names")

        def read(name):
            member = archive.getmember(name)
            if not member.isfile():
                raise ValueError("expected a regular file")
            return archive.extractfile(member)

        def blob(descriptor, kind, parse=False):
            digest = descriptor["digest"]
            if (not re.fullmatch("sha256:[0-9a-f]{64}", digest)
                    or descriptor["mediaType"] != "application/vnd.oci.image." + kind):
                raise ValueError("invalid OCI descriptor")
            name = "blobs/sha256/" + digest[7:]
            if (descriptor["size"] != archive.getmember(name).size
                    or hashlib.file_digest(read(name), "sha256").hexdigest() != digest[7:]):
                raise ValueError("OCI blob failed verification")
            return json.load(read(name)) if parse else None

        descriptor, = json.load(read("index.json"))["manifests"]
        if descriptor["digest"] != build["containerimage.digest"]:
            raise ValueError("exporter digest does not match the archive")
        manifest = blob(descriptor, "manifest.v1+json", True)
        if manifest["schemaVersion"] != 2 or not manifest["layers"]:
            raise ValueError("empty or unsupported manifest")
        config = blob(manifest["config"], "config.v1+json", True)
        if (config["os"], config["architecture"]) != ("linux", "amd64"):
            raise ValueError("not a Linux amd64 image")
        for layer in manifest["layers"]:
            blob(layer, "layer.v1.tar+gzip")
        return {"plane": plane, "source": source, "digest": descriptor["digest"]}


if __name__ == "__main__":
    with open(sys.argv[2]) as metadata:
        print(json.dumps(verify(sys.argv[1], json.load(metadata), *sys.argv[3:]), sort_keys=True))
