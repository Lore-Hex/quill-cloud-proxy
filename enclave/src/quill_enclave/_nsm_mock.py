"""Mock NSM provider for local dev + tests.

NEVER selected in production. The selector in `attest.get_provider()`
gates on `QUILL_TRANSPORT=unix-socket` — if you set that env var on a real
Nitro host, you'd get the mock and the trust property would collapse. The
deploy systemd unit explicitly omits the env var; only `make run-mock` in
this repo sets it.

The mock reads the plaintext sealed blob from a local file path passed
via `QUILL_MOCK_BLOB_PATH`. Tests set this in conftest.
"""

from __future__ import annotations

import os
from pathlib import Path

from quill_enclave.attest import AttestationError, AttestationProvider


class MockAttestationProvider(AttestationProvider):
    def attestation_document(self) -> bytes:
        # Mock doc: a non-cryptographic marker so test asserts can sanity-check.
        return b"MOCK_ATTESTATION_DOC"

    def kms_decrypt(self, ciphertext: bytes, attestation_doc: bytes) -> bytes:
        # Local test mode: ciphertext IS plaintext (no real encryption).
        # Optionally read from a file if QUILL_MOCK_BLOB_PATH is set so tests
        # don't have to round-trip the parent's S3 fetch.
        path_env = os.environ.get("QUILL_MOCK_BLOB_PATH")
        if path_env:
            blob = Path(path_env).read_bytes()
            return blob
        if ciphertext == b"":
            raise AttestationError("mock: no ciphertext passed and QUILL_MOCK_BLOB_PATH unset")
        return ciphertext
