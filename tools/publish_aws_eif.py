#!/usr/bin/env python3
"""Publish a verified, create-only EIF release to both private regional buckets."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import tempfile
from pathlib import Path
from typing import Any

from tools import aws_eif_manifest as manifest

ACCOUNT = "330422590279"
REGIONS = ("eu-west-1", "eu-west-3")


def _error_code(error: Exception) -> str:
    return str(getattr(error, "response", {}).get("Error", {}).get("Code", ""))


def _head(client: Any, bucket: str, key: str) -> dict | None:
    try:
        return client.head_object(Bucket=bucket, Key=key, ChecksumMode="ENABLED")
    except Exception as error:
        if _error_code(error) not in {"404", "NoSuchKey", "NotFound"}:
            raise
        return None


def _put_once(client: Any, bucket: str, key: str, body: Any,
              size: int, digest: str, content_type: str) -> None:
    try:
        client.put_object(
            Bucket=bucket, Key=key, Body=body, ContentLength=size,
            ContentType=content_type, IfNoneMatch="*", ServerSideEncryption="AES256",
            ChecksumSHA256=base64.b64encode(bytes.fromhex(digest)).decode("ascii"),
        )
    except Exception as error:
        # A retry may find a completed concurrent write. It still has to pass
        # the independent read-back checks below; never overwrite the object.
        if _error_code(error) not in {"412", "PreconditionFailed"}:
            raise


def _matches(head: dict | None, size: int, digest: str) -> bool:
    return bool(head and head.get("ContentLength") == size and
                head.get("ChecksumSHA256") == base64.b64encode(bytes.fromhex(digest)).decode("ascii"))


def _small_object(client: Any, bucket: str, key: str, limit: int) -> bytes:
    response = client.get_object(Bucket=bucket, Key=key)
    stream = response["Body"]
    try:
        if response.get("ContentLength", limit + 1) > limit:
            raise ValueError("published metadata exceeds size limit")
        content = stream.read(limit + 1)
        if len(content) > limit:
            raise ValueError("published metadata exceeds size limit")
        return content
    finally:
        stream.close()


def publish_region(client: Any, region: str, record: dict, eif: Path,
                   manifest_bytes: bytes, signature_bytes: bytes) -> str:
    if region not in REGIONS:
        raise ValueError("unapproved artifact region")
    bucket = f"quill-enclave-eif-{region}-{ACCOUNT}"
    prefix = manifest.artifact_prefix(record)
    eif_key = f"{prefix}/enclave.eif"
    size, digest = record["eif_size_bytes"], record["eif_sha256"]
    existing = _head(client, bucket, eif_key)
    if existing is None:
        with eif.open("rb") as stream:
            _put_once(client, bucket, eif_key, stream, size, digest, "application/octet-stream")
    if not _matches(_head(client, bucket, eif_key), size, digest):
        raise ValueError("published EIF checksum/size differs; refusing release")

    # A prior interrupted run may have signed the same manifest differently.
    # Preserve its signature only after authenticating it under the same CI
    # identity. Publish the manifest last as the release-completion marker.
    signature_key = f"{prefix}/manifest.json.bundle"
    if _head(client, bucket, signature_key) is None:
        _put_once(client, bucket, signature_key, signature_bytes, len(signature_bytes),
                  hashlib.sha256(signature_bytes).hexdigest(), "application/json")
    published_signature = _small_object(client, bucket, signature_key, manifest.MAX_BUNDLE_BYTES)
    with tempfile.TemporaryDirectory(prefix="quill-eif-publish-") as directory:
        snapshot = Path(directory) / "manifest.json"
        bundle = Path(directory) / "manifest.json.bundle"
        snapshot.write_bytes(manifest_bytes)
        bundle.write_bytes(published_signature)
        if manifest.verify(snapshot, bundle, expected_source=record["source_commit"]) != record:
            raise ValueError("published signature does not authenticate this release")

    manifest_key = f"{prefix}/manifest.json"
    _put_once(client, bucket, manifest_key, manifest_bytes, len(manifest_bytes),
              hashlib.sha256(manifest_bytes).hexdigest(), "application/json")
    if _small_object(client, bucket, manifest_key, manifest.MAX_MANIFEST_BYTES) != manifest_bytes:
        raise ValueError("published manifest differs; refusing release")
    return f"s3://{bucket}/{prefix}/"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--signature", type=Path, required=True)
    parser.add_argument("--eif", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    args = parser.parse_args()
    # Copy metadata before authentication and publish those same bytes.
    with tempfile.TemporaryDirectory(prefix="quill-eif-source-") as directory:
        snapshot = Path(directory) / "manifest.json"
        bundle = Path(directory) / "manifest.json.bundle"
        snapshot.write_bytes(manifest._read_bytes(args.manifest, manifest.MAX_MANIFEST_BYTES))
        bundle.write_bytes(manifest._read_bytes(args.signature, manifest.MAX_BUNDLE_BYTES))
        record = manifest.verify(snapshot, bundle, args.eif, args.source_commit)
        import boto3
        from botocore.config import Config

        identity = boto3.client("sts", region_name="eu-west-1").get_caller_identity()
        if identity["Account"] != ACCOUNT:
            raise ValueError("refusing publication to an unexpected AWS account")
        config = Config(connect_timeout=10, read_timeout=120, retries={"mode": "standard", "total_max_attempts": 3})
        for region in REGIONS:
            location = publish_region(
                boto3.client("s3", region_name=region, config=config), region, record,
                args.eif, snapshot.read_bytes(), bundle.read_bytes(),
            )
            print(json.dumps({"region": region, "location": location, "pcr0": record["measurements"]["PCR0"]}))


if __name__ == "__main__":
    main()
