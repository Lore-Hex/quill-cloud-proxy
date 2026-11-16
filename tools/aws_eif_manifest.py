#!/usr/bin/env python3
"""Create or verify the bounded, signed CI record for a published Nitro EIF."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any

SCHEMA = "trustedrouter.aws-eif.v1"
IDENTITY = "https://github.com/Lore-Hex/quill-cloud-proxy/.github/workflows/publish-aws-eif.yml@refs/heads/main"
ISSUER = "https://token.actions.githubusercontent.com"
MAX_MANIFEST_BYTES = 16 * 1024
MAX_BUNDLE_BYTES = 2 * 1024 * 1024
MAX_EIF_BYTES = 2 * 1024 * 1024 * 1024
FIELDS = {
    "schema", "source_commit", "builder_image", "enclave_image_id",
    "nitro_cli_version", "eif_sha256", "eif_size_bytes", "measurements",
}


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def _read_bytes(path: Path, limit: int) -> bytes:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > limit:
        raise ValueError("JSON input must be a bounded regular file, not a symlink")
    with path.open("rb") as stream:
        content = stream.read(limit + 1)
    if len(content) > limit:
        raise ValueError("JSON input exceeds limit")
    return content


def _read_json(path: Path, limit: int = MAX_MANIFEST_BYTES) -> Any:
    return json.loads(_read_bytes(path, limit), object_pairs_hook=_unique_object)


def _matches(value: Any, pattern: str) -> bool:
    return isinstance(value, str) and re.fullmatch(pattern, value) is not None


def validate(record: Any) -> dict[str, Any]:
    if not isinstance(record, dict) or set(record) != FIELDS or record["schema"] != SCHEMA:
        raise ValueError("wrong or incomplete EIF manifest schema")
    if not _matches(record["source_commit"], r"[0-9a-f]{40}"):
        raise ValueError("source_commit must be a full Git object ID")
    if not _matches(record["builder_image"], r"330422590279\.dkr\.ecr\.eu-west-1\.amazonaws\.com/quill-enclave-eif-builder@sha256:[0-9a-f]{64}"):
        raise ValueError("builder must use the dedicated repository and an immutable digest")
    if not _matches(record["enclave_image_id"], r"sha256:[0-9a-f]{64}"):
        raise ValueError("enclave_image_id must be an immutable Docker image ID")
    if not _matches(record["nitro_cli_version"], r"[0-9]+\.[0-9]+\.[0-9]+"):
        raise ValueError("nitro_cli_version must be an exact version")
    if not _matches(record["eif_sha256"], r"[0-9a-f]{64}"):
        raise ValueError("invalid EIF digest")
    if type(record["eif_size_bytes"]) is not int or not 0 < record["eif_size_bytes"] <= MAX_EIF_BYTES:
        raise ValueError("EIF exceeds size limit or is empty")
    measurements = record["measurements"]
    if not isinstance(measurements, dict) or set(measurements) != {"PCR0", "PCR1", "PCR2"}:
        raise ValueError("PCR0, PCR1 and PCR2 are required")
    for value in measurements.values():
        if not _matches(value, r"[0-9a-f]{96}") or value == "0" * 96:
            raise ValueError("invalid or debug-zero measurement")
    return record


def hash_eif(path: Path) -> tuple[str, int]:
    if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= MAX_EIF_BYTES:
        raise ValueError("EIF must be a bounded regular file, not a symlink")
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            size += len(chunk)
            if size > MAX_EIF_BYTES:
                raise ValueError("EIF exceeds size limit")
            digest.update(chunk)
    return digest.hexdigest(), size


def create(eif: Path, measurements: Path, source: str, builder: str,
           image_id: str, cli_version: str) -> dict[str, Any]:
    measured = _read_json(measurements)
    if not isinstance(measured, dict) or not isinstance(measured.get("Measurements"), dict):
        raise ValueError("expected Nitro CLI Measurements object")
    values = measured["Measurements"]
    if values.get("HashAlgorithm") != "Sha384":
        raise ValueError("expected Nitro SHA-384 measurements")
    digest, size = hash_eif(eif)
    return validate({
        "schema": SCHEMA, "source_commit": source, "builder_image": builder,
        "enclave_image_id": image_id, "nitro_cli_version": cli_version,
        "eif_sha256": digest, "eif_size_bytes": size,
        "measurements": {name: values.get(name) for name in ("PCR0", "PCR1", "PCR2")},
    })


def verify(manifest: Path, signature: Path, eif: Path | None = None,
           expected_source: str | None = None) -> dict[str, Any]:
    # Validate bounds before invoking a parser or signature verifier. Only the
    # CI workflow on protected main may authenticate an admission measurement.
    manifest_bytes = _read_bytes(manifest, MAX_MANIFEST_BYTES)
    signature_bytes = _read_bytes(signature, MAX_BUNDLE_BYTES)
    record = validate(json.loads(manifest_bytes, object_pairs_hook=_unique_object))
    json.loads(signature_bytes, object_pairs_hook=_unique_object)
    # Verify a private snapshot so the record returned below is precisely the
    # byte sequence authenticated by Cosign, even if an input path changes.
    with tempfile.TemporaryDirectory(prefix="quill-eif-verify-") as directory:
        snapshot = Path(directory) / "manifest.json"
        bundle = Path(directory) / "manifest.json.bundle"
        snapshot.write_bytes(manifest_bytes)
        bundle.write_bytes(signature_bytes)
        subprocess.run([
            "cosign", "verify-blob", "--bundle", str(bundle),
            "--certificate-identity", IDENTITY,
            "--certificate-oidc-issuer", ISSUER, str(snapshot),
        ], check=True, timeout=60, stdout=subprocess.DEVNULL)
    if expected_source is not None and record["source_commit"] != expected_source:
        raise ValueError("artifact does not match the intended source commit")
    if eif is not None:
        digest, size = hash_eif(eif)
        if digest != record["eif_sha256"] or size != record["eif_size_bytes"]:
            raise ValueError("EIF bytes do not match the signed manifest")
    return record


def artifact_prefix(record: dict[str, Any]) -> str:
    validate(record)
    return f"releases/{record['source_commit']}/{record['eif_sha256']}"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    build = sub.add_parser("create")
    build.add_argument("--eif", type=Path, required=True)
    build.add_argument("--measurements", type=Path, required=True)
    build.add_argument("--source-commit", required=True)
    build.add_argument("--builder-image", required=True)
    build.add_argument("--image-id", required=True)
    build.add_argument("--nitro-cli-version", required=True)
    check = sub.add_parser("verify")
    check.add_argument("--manifest", type=Path, required=True)
    check.add_argument("--signature", type=Path, required=True)
    check.add_argument("--eif", type=Path)
    check.add_argument("--expected-source")
    args = parser.parse_args()
    if args.command == "create":
        record = create(args.eif, args.measurements, args.source_commit,
                        args.builder_image, args.image_id, args.nitro_cli_version)
    else:
        record = verify(args.manifest, args.signature, args.eif, args.expected_source)
    print(json.dumps(record, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
