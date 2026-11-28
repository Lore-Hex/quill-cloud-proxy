"""Bind a protected staging receipt to the requested source and ACR workload."""

import json
from pathlib import Path
import re
import sys


def receipt_digest(receipt, source):
    digest = receipt.get("digest")
    if (not re.fullmatch("[0-9a-f]{40}", source) or receipt.get("source") != source
            or receipt.get("plane") != "azure" or not isinstance(digest, str)
            or not re.fullmatch("sha256:[0-9a-f]{64}", digest)
            or set(receipt) != {"source", "plane", "digest"}):
        raise ValueError("receipt must identify the authorized source, Azure plane and exact image")
    return digest


def prepare(workdir, source, digest):
    if not re.fullmatch("[0-9a-f]{40}", source) or not re.fullmatch("sha256:[0-9a-f]{64}", digest):
        raise ValueError("invalid release identity")
    workdir.mkdir(mode=0o700, exist_ok=False)
    (workdir / "build-commit.txt").write_text(source)
    (workdir / "image-digest.txt").write_text(digest)


if __name__ == "__main__":
    command, *args = sys.argv[1:]
    if command == "receipt":
        with open(args[0]) as handle:
            print(receipt_digest(json.load(handle), args[1]))
    elif command == "prepare":
        prepare(Path(args[0]), args[1], args[2])
    else:
        raise ValueError("unknown operation")
