# /// script
# requires-python = ">=3.11"
# dependencies = ["cryptography==50.0.2"]
# ///
"""Off-host AWS bootstrap sealing. Importable producer; no implicit cloud writes.

Callers supply separately authorized regional KMS and signing clients. This
module never reads local credentials, prints plaintext, or publishes a secret.
The parent must use encryption_context(manifest) for recipient-only Decrypt.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

DOMAIN = b"trustedrouter.aws-bootstrap.v2\x00"
MAX_PLAINTEXT = 48 << 10
MAX_BUNDLE = 64 << 10
REGIONS = frozenset({"eu-west-1", "eu-west-3"})


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for name, item in pairs:
        if name in value:
            raise ValueError("duplicate bootstrap field")
        value[name] = item
    return value


def reject_constant(value: str) -> None:
    raise ValueError("nonfinite bootstrap number")


def canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def encryption_context(manifest: dict[str, Any]) -> dict[str, str]:
    region, version = manifest["region"], manifest["version"]
    if region not in REGIONS or type(version) is not int or not 1 <= version < 2**53:
        raise ValueError("invalid AWS bundle region or version")
    return {
        "purpose": "trustedrouter.aws-bootstrap.v2",
        "region": region,
        "version": str(version),
    }


def seal(
    plaintext: bytes,
    *,
    region: str,
    version: int,
    key_arn: str,
    signer_arn: str,
    signer_public_der: bytes,
    kms: Any,
    signer_kms: Any,
) -> bytes:
    """Return a signed, encrypted bundle after locally verifying the KMS signature.

    The complete BootstrapData is encrypted, including configuration. The
    caller, not a parent host, selects and audits all its values. AWS clients
    are injected so every unit/contract test runs without cloud credentials.
    """
    manifest: dict[str, Any] = {"region": region, "version": version}
    context = encryption_context(manifest)
    if not key_arn.startswith(
        f"arn:aws:kms:{region}:330422590279:key/"
    ) or not signer_arn.startswith("arn:aws:kms:eu-west-1:330422590279:key/"):
        raise ValueError("bundle keys must be explicit expected-account regional ARNs")
    if not plaintext or len(plaintext) > MAX_PLAINTEXT:
        raise ValueError("bootstrap plaintext size")
    try:
        payload = json.loads(
            plaintext.decode("utf-8"),
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
        )
    except (ValueError, UnicodeError):
        raise ValueError("bootstrap plaintext must be a JSON object") from None
    if not isinstance(payload, dict) or not payload:
        raise ValueError("bootstrap plaintext must be a nonempty JSON object")
    public = serialization.load_der_public_key(signer_public_der)
    if not isinstance(public, ec.EllipticCurvePublicKey) or not isinstance(
        public.curve, ec.SECP384R1
    ):
        raise TypeError("bundle signer must be pinned P-384")

    response = kms.generate_data_key(
        KeyId=key_arn, KeySpec="AES_256", EncryptionContext=context
    )
    key = bytearray(response.pop("Plaintext", b""))
    try:
        encrypted_key = response.get("CiphertextBlob", b"")
        if (
            response.get("KeyId") != key_arn
            or len(key) != 32
            or not 0 < len(encrypted_key) <= 6144
        ):
            raise ValueError("KMS returned an invalid data key")
        nonce = secrets.token_bytes(12)
        aad = canonical({"region": region, "version": version})
        ciphertext = AESGCM(bytes(key)).encrypt(nonce, plaintext, aad)
    finally:
        # Best effort only: Python/crypto libraries may retain immutable copies.
        key[:] = b"\0" * len(key)

    manifest.update(
        encrypted_data_key_sha384=hashlib.sha384(encrypted_key).hexdigest(),
        ciphertext_sha384=hashlib.sha384(nonce + ciphertext).hexdigest(),
    )
    digest = hashlib.sha384(DOMAIN + canonical(manifest)).digest()
    signed = signer_kms.sign(
        KeyId=signer_arn,
        Message=digest,
        MessageType="DIGEST",
        SigningAlgorithm="ECDSA_SHA_384",
    )
    signature = signed.get("Signature", b"")
    if (
        signed.get("KeyId") != signer_arn
        or signed.get("SigningAlgorithm") != "ECDSA_SHA_384"
        or not 0 < len(signature) <= 128
    ):
        raise ValueError("KMS returned an invalid signature")
    public.verify(signature, digest, ec.ECDSA(utils.Prehashed(hashes.SHA384())))

    def b64(value: bytes) -> str:
        return base64.b64encode(value).decode("ascii")

    bundle = canonical(
        {
            "ciphertext": b64(ciphertext),
            "encrypted_data_key": b64(encrypted_key),
            "manifest": manifest,
            "nonce": b64(nonce),
            "signature": b64(signature),
        }
    )
    if len(bundle) > MAX_BUNDLE:
        raise ValueError("sealed bundle exceeds Secrets Manager limit")
    return bundle
