"""Build two scratch images with different input mtimes and inspect their actual layers."""
from __future__ import annotations

import json
import os
import subprocess
import tarfile
import tempfile
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="aws-eif-mtime-") as directory:
        work = Path(directory)
        context = work / "context"
        context.mkdir()
        (context / "Dockerfile").write_text("FROM scratch\nCOPY fixture /fixture\n")
        fixture = context / "fixture"
        fixture.write_bytes(b"same enclave build input\n")
        tags = []
        ids = []
        try:
            for stamp in (1_600_000_000, 1_750_000_000):
                os.utime(fixture, (stamp, stamp))
                tag = f"aws-eif-mtime-check:{uuid.uuid4().hex}"
                tags.append(tag)
                subprocess.run(["bash", str(ROOT / "tools/build-aws-eif-image.sh"),
                                "--platform", "linux/amd64", "--tag", tag, str(context)], check=True)
                ids.append(subprocess.check_output(["docker", "image", "inspect", tag, "--format",
                                                    "{{.Id}}"], text=True).strip())
                archive = work / "scratch.tar"
                subprocess.run(["docker", "save", "-o", str(archive), tag], check=True)
                with tarfile.open(archive) as outer:
                    record, = json.load(outer.extractfile("manifest.json"))
                    layer, = record["Layers"]
                    with tarfile.open(fileobj=outer.extractfile(layer), mode="r|*") as contents:
                        payload, = (f for f in contents if f.name.lstrip("./") == "fixture")
                        if not payload.isfile() or payload.mtime != 0:
                            raise ValueError("measured file retained its input timestamp")
            if len(set(ids)) != 1:
                raise ValueError("identical payloads produced different image configs")
        finally:
            for tag in tags:
                subprocess.run(["docker", "image", "rm", tag], stdout=subprocess.DEVNULL, check=False)
    print("Two independent scratch builds normalized different mtimes to zero.")


if __name__ == "__main__":
    main()
