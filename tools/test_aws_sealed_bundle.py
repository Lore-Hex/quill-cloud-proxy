"""Producer tests also act as the offline Python-to-Go contract fixture."""

from __future__ import annotations

import base64
import hashlib
import json
import unittest
from unittest.mock import Mock

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from tools import aws_sealed_bundle as bundle

DATA_ARN = "arn:aws:kms:eu-west-3:330422590279:key/00000000-0000-0000-0000-000000000001"
SIGN_ARN = "arn:aws:kms:eu-west-1:330422590279:key/00000000-0000-0000-0000-000000000002"


def contract_fixture() -> dict[str, object]:
    """Only synthetic data and a fresh test signer; no network or AWS calls."""
    signer = ec.generate_private_key(ec.SECP384R1())
    public = signer.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    key = bytes(range(32))
    kms = Mock()
    kms.generate_data_key.return_value = {
        "KeyId": DATA_ARN,
        "Plaintext": key,
        "CiphertextBlob": b"offline test KMS ciphertext",
    }
    signing = Mock()

    def sign(**kwargs: object) -> dict[str, object]:
        assert kwargs["MessageType"] == "DIGEST"
        assert kwargs["SigningAlgorithm"] == "ECDSA_SHA_384"
        assert kwargs["KeyId"] == SIGN_ARN
        return {
            "KeyId": SIGN_ARN,
            "SigningAlgorithm": "ECDSA_SHA_384",
            "Signature": signer.sign(
                kwargs["Message"], ec.ECDSA(utils.Prehashed(hashes.SHA384()))
            ),
        }

    signing.sign.side_effect = sign
    plaintext = (
        b'{"trustedrouter_base_url":"https://trustedrouter.com","test_only":true}'
    )
    encoded = bundle.seal(
        plaintext,
        region="eu-west-3",
        version=7,
        key_arn=DATA_ARN,
        signer_arn=SIGN_ARN,
        signer_public_der=public,
        kms=kms,
        signer_kms=signing,
    )
    kms.generate_data_key.assert_called_once_with(
        KeyId=DATA_ARN,
        KeySpec="AES_256",
        EncryptionContext={
            "purpose": "trustedrouter.aws-bootstrap.v2",
            "region": "eu-west-3",
            "version": "7",
        },
    )
    return {
        "bundle": json.loads(encoded),
        "public_key": base64.b64encode(public).decode(),
        "key": base64.b64encode(key).decode(),
        "plaintext": base64.b64encode(plaintext).decode(),
    }


class BundleTests(unittest.TestCase):
    def test_kms_response_and_signer_binding_fail_closed(self) -> None:
        signer = ec.generate_private_key(ec.SECP384R1())
        other = ec.generate_private_key(ec.SECP384R1())
        public = signer.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        for fault in (
            "short key",
            "wrong key id",
            "empty blob",
            "oversized blob",
            "wrong signer id",
            "wrong algorithm",
            "wrong signer",
            "bad signature",
        ):
            with self.subTest(fault=fault):
                kms, signing = Mock(), Mock()
                response = {
                    "KeyId": DATA_ARN,
                    "Plaintext": bytes(range(32)),
                    "CiphertextBlob": b"test",
                }
                if fault == "short key":
                    response["Plaintext"] = bytes(16)
                elif fault == "wrong key id":
                    response["KeyId"] = SIGN_ARN
                elif fault == "empty blob":
                    response["CiphertextBlob"] = b""
                elif fault == "oversized blob":
                    response["CiphertextBlob"] = bytes(6145)
                kms.generate_data_key.return_value = response

                def sign(fault: str = fault, **kwargs: object) -> dict[str, object]:
                    private = other if fault == "wrong signer" else signer
                    signature = private.sign(
                        kwargs["Message"], ec.ECDSA(utils.Prehashed(hashes.SHA384()))
                    )
                    return {
                        "KeyId": DATA_ARN if fault == "wrong signer id" else SIGN_ARN,
                        "SigningAlgorithm": "ECDSA_SHA_256"
                        if fault == "wrong algorithm"
                        else "ECDSA_SHA_384",
                        "Signature": b"invalid"
                        if fault == "bad signature"
                        else signature,
                    }

                signing.sign.side_effect = sign
                with self.assertRaises((ValueError, InvalidSignature)):
                    bundle.seal(
                        b'{"test":true}',
                        region="eu-west-3",
                        version=7,
                        key_arn=DATA_ARN,
                        signer_arn=SIGN_ARN,
                        signer_public_der=public,
                        kms=kms,
                        signer_kms=signing,
                    )

    def test_signed_encrypted_configuration(self) -> None:
        data = contract_fixture()
        sealed = data["bundle"]
        nonce, ciphertext = (
            base64.b64decode(sealed[k]) for k in ("nonce", "ciphertext")
        )
        manifest = sealed["manifest"]
        self.assertEqual(
            hashlib.sha384(nonce + ciphertext).hexdigest(),
            manifest["ciphertext_sha384"],
        )
        aad = bundle.canonical({"region": "eu-west-3", "version": 7})
        self.assertEqual(
            AESGCM(base64.b64decode(data["key"])).decrypt(nonce, ciphertext, aad),
            base64.b64decode(data["plaintext"]),
        )
        self.assertNotIn(b"trustedrouter_base_url", bundle.canonical(sealed))

    def test_invalid_metadata_never_calls_kms(self) -> None:
        signer = ec.generate_private_key(ec.SECP384R1())
        public = signer.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        for overrides in (
            {"version": True},
            {"version": 0},
            {"version": 2**53},
            {"region": "us-east-1"},
            {"key_arn": "alias/other"},
            {"signer_arn": "alias/other"},
            {"plaintext": b"[]"},
            {"plaintext": b"{}"},
            {"plaintext": b"not json"},
            {"plaintext": b'{"x":NaN}'},
            {"plaintext": b'{"x":1,"x":2}'},
            {"plaintext": '{"x":1}'.encode("utf-16")},
            {"plaintext": b"x" * (bundle.MAX_PLAINTEXT + 1)},
        ):
            with self.subTest(overrides=list(overrides)):
                kms, signing = Mock(), Mock()
                args = {
                    "plaintext": b'{"ok":true}',
                    "region": "eu-west-3",
                    "version": 7,
                    "key_arn": DATA_ARN,
                    "signer_arn": SIGN_ARN,
                    "signer_public_der": public,
                    "kms": kms,
                    "signer_kms": signing,
                }
                args.update(overrides)
                with self.assertRaises(ValueError):
                    bundle.seal(**args)
                kms.generate_data_key.assert_not_called()
                signing.sign.assert_not_called()


if __name__ == "__main__":
    unittest.main()
