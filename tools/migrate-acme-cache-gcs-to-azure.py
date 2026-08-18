#!/usr/bin/env python3
# /// script
# dependencies = ["cryptography>=42"]
# requires-python = ">=3.11"
# ///
"""One-time operator migration from the old GCS ACME cache to Azure Blob.

This tool is deliberately outside the enclave runtime. It reads the existing
cache with the operator's GCP login, encrypts every object locally with the
Azure-only cache key, and writes ciphertext using the operator's Azure login.
After this migration, Azure needs neither credential nor cloud at runtime.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import pathlib
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

AZURE_API_VERSION = "2023-11-03"
AZURE_MANAGEMENT_API_VERSION = "2023-05-01"
ENVELOPE_VERSION = 1
MAX_OBJECT_BYTES = 1 << 20
MIGRATION_MARKER_VERSION = "v1"
HTTP_MAX_ATTEMPTS = 4
RETRYABLE_HTTP_STATUS = {408, 429, 500, 502, 503, 504}


def fail(message: str) -> "NoReturn":
    raise SystemExit(f"[FAIL] {message}")


def command_token(command: list[str], label: str) -> str:
    try:
        token = subprocess.check_output(command, text=True, stderr=subprocess.DEVNULL).strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        fail(f"could not obtain {label} access token: {exc}")
    if not token:
        fail(f"{label} access token was empty")
    return token


def command_text(command: list[str], label: str) -> str:
    try:
        value = subprocess.check_output(
            command, text=True, stderr=subprocess.DEVNULL
        ).strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        fail(f"could not obtain {label}: {exc}")
    if not value:
        fail(f"{label} was empty")
    return value


def request(
    method: str,
    url: str,
    token: str,
    *,
    body: bytes | None = None,
    azure: bool = False,
) -> tuple[int, bytes]:
    headers = {"Authorization": f"Bearer {token}"}
    if azure:
        headers.update({"x-ms-version": AZURE_API_VERSION})
        if method == "PUT":
            headers.update({
                "x-ms-blob-type": "BlockBlob",
                "Content-Type": "application/octet-stream",
            })
    host = urllib.parse.urlsplit(url).netloc
    for attempt in range(HTTP_MAX_ATTEMPTS):
        req = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=30) as response:
                return response.status, response.read(MAX_OBJECT_BYTES + 128)
        except urllib.error.HTTPError as exc:
            response_body = exc.read(2048)
            if exc.code not in RETRYABLE_HTTP_STATUS or attempt == HTTP_MAX_ATTEMPTS - 1:
                return exc.code, response_body
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            if attempt == HTTP_MAX_ATTEMPTS - 1:
                reason = getattr(exc, "reason", exc)
                fail(f"{method} {host} failed after {HTTP_MAX_ATTEMPTS} attempts: {reason}")
        time.sleep(0.25 * (2**attempt))
    fail(f"{method} {host} exhausted retries")


def aad(account: str, container: str, cache_key: str) -> bytes:
    return (
        "trustedrouter/azure-acme-cache/v1\x00"
        f"{account}\x00{container}\x00{cache_key}"
    ).encode()


def seal(key: bytes, account: str, container: str, cache_key: str, plaintext: bytes) -> bytes:
    if len(plaintext) > MAX_OBJECT_BYTES:
        fail(f"cache object {cache_key!r} is {len(plaintext)} bytes; limit is {MAX_OBJECT_BYTES}")
    return seal_with_nonce(
        key, account, container, cache_key, plaintext, os.urandom(12)
    )


def seal_with_nonce(
    key: bytes,
    account: str,
    container: str,
    cache_key: str,
    plaintext: bytes,
    nonce: bytes,
) -> bytes:
    """Deterministic wire helper used by the cross-language contract tests."""
    if len(nonce) != 12:
        fail(f"Azure cache nonce is {len(nonce)} bytes; want 12")
    return bytes([ENVELOPE_VERSION]) + nonce + AESGCM(key).encrypt(
        nonce, plaintext, aad(account, container, cache_key)
    )


def open_envelope(key: bytes, account: str, container: str, cache_key: str, sealed: bytes) -> bytes:
    if len(sealed) < 1 + 12 + 16:
        fail(f"Azure blob for {cache_key!r} is a truncated encrypted envelope")
    if sealed[0] != ENVELOPE_VERSION:
        fail(f"Azure blob for {cache_key!r} has envelope version {sealed[0]}")
    return AESGCM(key).decrypt(
        sealed[1:13], sealed[13:], aad(account, container, cache_key)
    )


def azure_blob_url(account: str, container: str, cache_key: str) -> str:
    encoded = base64.urlsafe_b64encode(cache_key.encode()).rstrip(b"=").decode()
    return (
        f"https://{account}.blob.core.windows.net/"
        f"{urllib.parse.quote(container, safe='')}/autocert-v1/{encoded}"
    )


def list_gcs_objects(bucket: str, token: str) -> list[str]:
    names: list[str] = []
    page_token = ""
    while True:
        query = {"fields": "nextPageToken,items(name,size)"}
        if page_token:
            query["pageToken"] = page_token
        url = (
            "https://storage.googleapis.com/storage/v1/b/"
            f"{urllib.parse.quote(bucket, safe='')}/o?{urllib.parse.urlencode(query)}"
        )
        status, body = request("GET", url, token)
        if status != 200:
            fail(f"GCS object listing returned HTTP {status}")
        try:
            payload = json.loads(body)
        except json.JSONDecodeError as exc:
            fail(f"GCS object listing returned invalid JSON: {exc}")
        names.extend(item["name"] for item in payload.get("items", []))
        page_token = payload.get("nextPageToken", "")
        if not page_token:
            return sorted(set(names))


def read_gcs_object(bucket: str, name: str, token: str) -> bytes:
    url = (
        "https://storage.googleapis.com/storage/v1/b/"
        f"{urllib.parse.quote(bucket, safe='')}/o/"
        f"{urllib.parse.quote(name, safe='')}?alt=media"
    )
    status, body = request("GET", url, token)
    if status != 200:
        fail(f"GCS read for {name!r} returned HTTP {status}")
    if len(body) > MAX_OBJECT_BYTES:
        fail(f"GCS object {name!r} exceeds {MAX_OBJECT_BYTES} bytes")
    return body


def load_key(path: pathlib.Path) -> bytes:
    try:
        raw = path.read_text(encoding="ascii").strip()
        key = base64.b64decode(raw, validate=True)
    except (OSError, ValueError) as exc:
        fail(f"cannot read Azure cache key {path}: {exc}")
    if len(key) != 32:
        fail(f"Azure cache key {path} is {len(key)} bytes; want 32")
    return key


def migration_marker_payload(source_count: int) -> dict[str, object]:
    if source_count <= 0:
        fail("refusing to mark an empty ACME cache migration complete")
    return {
        "properties": {
            "publicAccess": "None",
            "metadata": {
                "trustedrouterAcmeSeedVersion": MIGRATION_MARKER_VERSION,
                "trustedrouterAcmeSeedSourceCount": str(source_count),
            },
        }
    }


def mark_migration_complete(
    subscription_id: str,
    resource_group: str,
    account: str,
    container: str,
    source_count: int,
) -> None:
    url = (
        "https://management.azure.com/subscriptions/"
        f"{urllib.parse.quote(subscription_id, safe='')}/resourceGroups/"
        f"{urllib.parse.quote(resource_group, safe='')}/providers/"
        "Microsoft.Storage/storageAccounts/"
        f"{urllib.parse.quote(account, safe='')}/blobServices/default/containers/"
        f"{urllib.parse.quote(container, safe='')}?api-version={AZURE_MANAGEMENT_API_VERSION}"
    )
    payload = json.dumps(
        migration_marker_payload(source_count), separators=(",", ":")
    )
    try:
        subprocess.run(
            [
                "az", "rest", "--method", "put", "--url", url,
                "--headers", "Content-Type=application/json",
                "--body", payload, "--output", "none",
            ],
            check=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        fail(f"could not write the Azure ACME migration marker: {exc}")


@dataclass
class Counts:
    already: int = 0
    copied: int = 0
    pending: int = 0


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--replace", action="store_true", help="replace a destination object whose decrypted bytes differ")
    parser.add_argument("--gcs-bucket", default="quill-acme-cache")
    parser.add_argument("--azure-account", default="trquillacmecache")
    parser.add_argument("--azure-container", default="acme-cache")
    parser.add_argument("--azure-resource-group", default="TR-TEE-DUBAI")
    parser.add_argument(
        "--key-file",
        type=pathlib.Path,
        default=pathlib.Path.home() / ".quill-secrets" / "tr-azure-acme-cache-key",
    )
    args = parser.parse_args()
    if args.replace and not args.apply:
        fail("--replace requires --apply")

    key = load_key(args.key_file)
    google_token = command_token(["gcloud", "auth", "print-access-token"], "GCP")
    azure_token = command_token(
        [
            "az", "account", "get-access-token",
            "--resource", "https://storage.azure.com/",
            "--query", "accessToken", "-o", "tsv",
        ],
        "Azure Storage",
    )
    subscription_id = command_text(
        ["az", "account", "show", "--query", "id", "-o", "tsv"],
        "Azure subscription ID",
    )
    names = list_gcs_objects(args.gcs_bucket, google_token)
    if not names:
        fail(f"GCS cache gs://{args.gcs_bucket} is empty; refusing an unseeded cutover")
    print(f"==> found {len(names)} source cache object(s)", file=sys.stderr)

    counts = Counts()
    for name in names:
        plaintext = read_gcs_object(args.gcs_bucket, name, google_token)
        url = azure_blob_url(args.azure_account, args.azure_container, name)
        status, existing = request("GET", url, azure_token, azure=True)
        if status == 200:
            try:
                decoded = open_envelope(
                    key, args.azure_account, args.azure_container, name, existing
                )
            except Exception as exc:
                fail(f"cannot verify existing Azure object {name!r}: {type(exc).__name__}")
            if decoded == plaintext:
                counts.already += 1
                continue
            if not args.replace:
                fail(
                    f"Azure object {name!r} decrypts but differs from GCS; "
                    "refusing overwrite without --replace"
                )
        elif status != 404:
            fail(f"Azure read for {name!r} returned HTTP {status}")

        if not args.apply:
            counts.pending += 1
            continue
        ciphertext = seal(key, args.azure_account, args.azure_container, name, plaintext)
        status, _ = request("PUT", url, azure_token, body=ciphertext, azure=True)
        if status != 201:
            fail(f"Azure write for {name!r} returned HTTP {status}")
        status, written = request("GET", url, azure_token, azure=True)
        if status != 200 or open_envelope(
            key, args.azure_account, args.azure_container, name, written
        ) != plaintext:
            fail(f"Azure read-back verification failed for {name!r}")
        counts.copied += 1

    print(
        f"[ok] cache migration: already={counts.already} copied={counts.copied} "
        f"pending={counts.pending} total={len(names)}",
        file=sys.stderr,
    )
    if counts.pending:
        print("dry-run only; re-run with --apply", file=sys.stderr)
    elif args.apply:
        mark_migration_complete(
            subscription_id,
            args.azure_resource_group,
            args.azure_account,
            args.azure_container,
            len(names),
        )
        print(
            f"[ok] Azure migration marker written for {len(names)} source object(s)",
            file=sys.stderr,
        )


if __name__ == "__main__":
    main()
