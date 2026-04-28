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

from quill_enclave.attest import AttestationProvider


class RealAttestationProvider(AttestationProvider):
    def attestation_document(self) -> bytes:
        raise NotImplementedError(
            "Real NSM attestation requires running inside a Nitro Enclave. "
            "Implement via /dev/nsm IOCTL (NSM_REQUEST_ATTESTATION_DOC). "
            "Unblock for V1 deployment by adding aws-nitro-enclaves-sdk-py."
        )

    def kms_decrypt(self, ciphertext: bytes, attestation_doc: bytes) -> bytes:
        raise NotImplementedError(
            "Real KMS-attested decrypt requires the SDK's signed Decrypt call. "
            "Unblock for V1 deployment by adding aws-nitro-enclaves-sdk-py."
        )
