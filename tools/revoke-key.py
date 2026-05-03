#!/usr/bin/env python3
"""Drop a device from the sealed blob, re-encrypt, push.

The enclave polls S3 every 60 seconds for blob etag changes; revocation
takes effect within a minute, no enclave restart.

Usage:
  python tools/revoke-key.py --owner alice@example.com \
    --bucket quill-device-keys --kms-key-id alias/quill-device-keys

This downloads the current blob, decrypts it (which the operator IS
allowed to do with admin creds — KMS attestation locks DECRYPT to the
enclave PCR0, not to the operator), removes the matching device, re-
encrypts, and uploads.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Revoke a Quill device key.")
    parser.add_argument("--bucket", required=True)
    parser.add_argument("--object", default="blob.enc")
    parser.add_argument("--kms-key-id", required=True)
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument(
        "--owner", help="Drop the device whose owner field equals this string."
    )
    parser.add_argument(
        "--device-id", help="Drop the device whose device_id field equals this string."
    )
    args = parser.parse_args(argv)

    if not args.owner and not args.device_id:
        print("must pass --owner OR --device-id", file=sys.stderr)
        return 2

    import boto3  # noqa: PLC0415

    s3 = boto3.client("s3", region_name=args.region)
    kms = boto3.client("kms", region_name=args.region)

    obj = s3.get_object(Bucket=args.bucket, Key=args.object)
    ct = obj["Body"].read()
    plaintext = kms.decrypt(KeyId=args.kms_key_id, CiphertextBlob=ct)["Plaintext"]
    devices = json.loads(plaintext)
    if not isinstance(devices, list):
        print("blob is not a JSON array", file=sys.stderr)
        return 2

    before = len(devices)
    devices = [
        d
        for d in devices
        if not (
            (args.owner and d.get("owner") == args.owner)
            or (args.device_id and d.get("device_id") == args.device_id)
        )
    ]
    after = len(devices)

    if before == after:
        print("no matching device found; blob unchanged", file=sys.stderr)
        return 1

    new_blob = json.dumps(devices, separators=(",", ":")).encode("utf-8")
    new_ct = kms.encrypt(KeyId=args.kms_key_id, Plaintext=new_blob)["CiphertextBlob"]
    s3.put_object(Bucket=args.bucket, Key=args.object, Body=new_ct)
    sys.stdout.write(f"removed {before - after} device(s); enclave will pick up within ~60s\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
