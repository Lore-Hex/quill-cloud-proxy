#!/usr/bin/env python3
"""Generate device API keys, KMS-seal the hash list, push to S3.

Operator runs this with admin AWS credentials. Outputs:
  - The plaintext device keys (printed ONCE on stdout — record them; you
    can't recover later).
  - An encrypted JSON blob uploaded to s3://<bucket>/<key>.

The KMS CMK used for `Encrypt` here MUST be the `device-keys-cmk` whose
key-policy allows `Decrypt` only when the request is from a Nitro Enclave
with the published PCR0 measurement. The encryption side has no
attestation requirement; only decryption does.

Schema written:
  [
    {"key_hash": "<hex sha256>", "owner": "alice@x", "device_id": "q-002"},
    ...
  ]

Usage:
  python tools/seal-keys.py \
    --bucket quill-device-keys \
    --object blob.enc \
    --kms-key-id alias/quill-device-keys \
    --owner alice@example.com:q-002 \
    --owner bob@example.com:q-003

  (Each --owner is `email:device_id`. Generates one fresh key per pair.)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import secrets
import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence


def _new_key() -> str:
    return secrets.token_urlsafe(32)


def _hash(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Seal Quill device keys for the enclave.")
    parser.add_argument("--bucket", required=True, help="S3 bucket for the sealed blob.")
    parser.add_argument(
        "--object", default="blob.enc", help="S3 object key (default: blob.enc)."
    )
    parser.add_argument(
        "--kms-key-id",
        required=True,
        help="KMS key ID/alias of device-keys-cmk (e.g. alias/quill-device-keys).",
    )
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument(
        "--owner",
        action="append",
        required=True,
        help="email:device_id (may repeat to add multiple devices).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the JSON blob and the keys but don't call AWS.",
    )
    args = parser.parse_args(argv)

    devices: list[dict[str, str]] = []
    issued: list[tuple[str, str, str]] = []  # (owner, device_id, plaintext_key)
    for owner_spec in args.owner:
        if ":" not in owner_spec:
            print(f"--owner must be email:device_id (got {owner_spec!r})", file=sys.stderr)
            return 2
        owner, _, device_id = owner_spec.partition(":")
        owner = owner.strip()
        device_id = device_id.strip()
        if not owner or not device_id:
            print(f"--owner must have non-empty email and device_id (got {owner_spec!r})", file=sys.stderr)
            return 2
        plaintext_key = _new_key()
        devices.append(
            {"key_hash": _hash(plaintext_key), "owner": owner, "device_id": device_id}
        )
        issued.append((owner, device_id, plaintext_key))

    blob = json.dumps(devices, separators=(",", ":")).encode("utf-8")

    if args.dry_run:
        sys.stdout.write("--- sealed blob (plaintext, dry-run) ---\n")
        sys.stdout.write(blob.decode("utf-8") + "\n")
    else:
        # Lazy boto3 import: this script is callable without boto3 in --dry-run.
        import boto3  # noqa: PLC0415

        kms = boto3.client("kms", region_name=args.region)
        ct = kms.encrypt(KeyId=args.kms_key_id, Plaintext=blob)["CiphertextBlob"]
        s3 = boto3.client("s3", region_name=args.region)
        s3.put_object(Bucket=args.bucket, Key=args.object, Body=ct)
        sys.stdout.write(f"sealed blob uploaded to s3://{args.bucket}/{args.object}\n")

    sys.stdout.write("\n--- ISSUED KEYS (record these; cannot be recovered later) ---\n")
    for owner, device_id, key in issued:
        sys.stdout.write(f"{owner:30s}  {device_id:10s}  {key}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
