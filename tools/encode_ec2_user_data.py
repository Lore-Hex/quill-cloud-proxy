#!/usr/bin/env python3
"""Encode EC2 user data as deterministic gzip plus base64.

EC2 limits the decoded UserData field to 16 KiB. Cloud-init detects the gzip
magic bytes after EC2 decodes the field, so a compressed shell script retains
normal cloud-init execution while leaving room for the measured Nitro bootstrap
allowlist.
"""

from __future__ import annotations

import base64
import gzip
import sys

MAX_USER_DATA_BYTES = 16 * 1024


def encode_user_data(payload: bytes) -> str:
    compressed = compress_user_data(payload)
    return base64.b64encode(compressed).decode("ascii")


def compress_user_data(payload: bytes) -> bytes:
    if not payload:
        raise ValueError("EC2 user data must not be empty")
    # mtime=0 removes the current-time header, making output stable for a given
    # Python/zlib build and avoiding needless launch-template churn.
    compressed = gzip.compress(payload, compresslevel=9, mtime=0)
    if len(compressed) > MAX_USER_DATA_BYTES:
        raise ValueError(
            "compressed EC2 user data is "
            f"{len(compressed)} bytes; maximum is {MAX_USER_DATA_BYTES}"
        )
    return compressed


def main() -> int:
    payload = sys.stdin.buffer.read()
    try:
        compressed = compress_user_data(payload)
    except ValueError as exc:
        print(f"FATAL: {exc}", file=sys.stderr)
        return 1
    print(
        f"EC2 user data: {len(compressed)} bytes compressed "
        f"(limit {MAX_USER_DATA_BYTES}, {len(payload)} bytes raw)",
        file=sys.stderr,
    )
    sys.stdout.write(base64.b64encode(compressed).decode("ascii"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
