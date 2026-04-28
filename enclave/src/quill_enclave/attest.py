"""NSM (Nitro Security Module) attestation document → KMS-attested decrypt.

The enclave reads the sealed device-key blob (ciphertext) over a vsock
relay from the parent, then asks KMS to decrypt it. The KMS key policy
says decrypt is only allowed when `kms:RecipientAttestation:PCR0` matches
the published measurement of THIS exact build.

V1 surface area: tiny. We only need:
  1. NSM ioctl to fetch a fresh attestation document.
  2. Send a kms:Decrypt request containing the doc + ciphertext.
  3. Parse the plaintext from the response.

Production uses /dev/nsm via ctypes (see `_nsm_real.py`). The local test
path uses a passthrough mock (see `_nsm_mock.py`). Selection happens at
startup based on `QUILL_TRANSPORT`.
"""

from __future__ import annotations

import json
import os
from typing import Protocol

from quill_enclave.types import DeviceConfig


class AttestationError(Exception):
    pass


class AttestationProvider(Protocol):
    def attestation_document(self) -> bytes: ...

    def kms_decrypt(self, ciphertext: bytes, attestation_doc: bytes) -> bytes: ...


def parse_device_blob(plaintext: bytes) -> dict[bytes, DeviceConfig]:
    """Parse the JSON list of devices into the in-memory map keyed by raw key_hash bytes.

    Schema:
      [{"key_hash": "<hex>", "owner": "...", "device_id": "..."}, ...]
    """
    try:
        raw = json.loads(plaintext)
    except json.JSONDecodeError as exc:
        raise AttestationError(f"sealed blob is not valid JSON: {exc}") from exc
    if not isinstance(raw, list):
        raise AttestationError("sealed blob must be a JSON array of device entries")
    out: dict[bytes, DeviceConfig] = {}
    for entry in raw:
        if not isinstance(entry, dict):
            raise AttestationError("each device entry must be a JSON object")
        key_hash_hex = entry.get("key_hash")
        owner = entry.get("owner")
        device_id = entry.get("device_id")
        if not isinstance(key_hash_hex, str) or len(key_hash_hex) != 64:
            raise AttestationError("each entry needs a 64-char hex key_hash")
        if not isinstance(owner, str) or not owner:
            raise AttestationError("each entry needs an owner string")
        if not isinstance(device_id, str) or not device_id:
            raise AttestationError("each entry needs a device_id string")
        try:
            kh = bytes.fromhex(key_hash_hex)
        except ValueError as exc:
            raise AttestationError(f"invalid key_hash hex: {exc}") from exc
        out[kh] = {"key_hash": key_hash_hex, "owner": owner, "device_id": device_id}
    return out


def get_provider() -> AttestationProvider:
    """Pick mock vs real provider based on environment.

    Production: real NSM. Local dev / tests: mock that uses the same
    interface but doesn't talk to /dev/nsm or KMS.
    """
    if os.environ.get("QUILL_TRANSPORT") == "unix-socket":
        from quill_enclave._nsm_mock import MockAttestationProvider

        return MockAttestationProvider()
    from quill_enclave._nsm_real import RealAttestationProvider

    return RealAttestationProvider()


__all__ = ["AttestationError", "AttestationProvider", "get_provider", "parse_device_blob"]
