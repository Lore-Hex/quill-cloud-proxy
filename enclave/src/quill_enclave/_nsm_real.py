"""Real NSM + KMS-attested-decrypt. Only runnable on a Nitro Enclave host.

The Nitro Enclaves SDK (`aws-nitro-enclaves-sdk-py` upstream) provides:
  - /dev/nsm ioctl for fetching attestation documents
  - a SigV4-signed kms:Decrypt that includes the attestation doc as the
    `Recipient` field

V1 keeps this stub-shaped: imports are fine on any platform, but the call
site raises NotImplementedError if exercised outside an enclave. The
intent is that `make sync` / `make check` work everywhere; only an actual
Nitro deployment exercises this code path.

When ready to flip on real attestation, fill in the bodies below — the
shape of the calls is stable.
"""

from __future__ import annotations

import base64
from typing import cast

import aws_nsm_interface  # type: ignore[import-untyped]
import boto3  # type: ignore[import-untyped]

from quill_enclave.attest import AttestationProvider


class RealAttestationProvider(AttestationProvider):
    def attestation_document(self) -> bytes:
        fd = aws_nsm_interface.open_nsm_device()
        try:
            doc = aws_nsm_interface.get_attestation_doc(fd)
            return cast(bytes, doc)
        finally:
            aws_nsm_interface.close_nsm_device(fd)

    def kms_decrypt(self, ciphertext: bytes, attestation_doc: bytes) -> bytes:
        client = boto3.client("kms", region_name="us-east-1")
        b64_doc = base64.b64encode(attestation_doc).decode("utf-8")
        response = client.decrypt(
            CiphertextBlob=ciphertext,
            Recipient={
                "KeyEncryptionAlgorithm": "RSAES_OAEP_SHA_256",
                "AttestationDocument": b64_doc,
            },
        )
        return cast(bytes, response["Plaintext"])
