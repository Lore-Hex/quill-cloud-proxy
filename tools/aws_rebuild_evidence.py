"""Compare rebuild products against an already authenticated CI manifest."""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


def compare(output: Path) -> dict:
    signed = json.loads((output / "signed-manifest.json").read_text())
    measured = json.loads((output / "describe.json").read_text())["Measurements"]
    image = (output / "image-id.txt").read_text().strip()
    hasher = hashlib.sha256()
    with (output / "enclave.eif").open("rb") as eif:
        for block in iter(lambda: eif.read(1 << 20), b""):
            hasher.update(block)
    digest = hasher.hexdigest()
    actual = {"enclave_image_id": image, "eif_sha256": digest,
              "eif_size_bytes": (output / "enclave.eif").stat().st_size,
              **{p: measured[p] for p in ("PCR0", "PCR1", "PCR2")}}
    expected = {**signed, **signed["measurements"]}
    return {"source_commit": signed["source_commit"], "actual": actual,
            "matches": {k: v == expected[k] for k, v in actual.items()}}


if __name__ == "__main__":
    report = compare(Path(sys.argv[1]))
    encoded = json.dumps(report, sort_keys=True, indent=2)
    Path(sys.argv[2]).write_text(encoded + "\n")
    print(encoded)
    if not all(report["matches"].values()):
        raise SystemExit("rebuild differs from signed release; not byte-for-byte reproducible")
