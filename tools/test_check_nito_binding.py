import hashlib
import json
import unittest

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from tools.check_nito_binding import open_binding


class NitoBindingTest(unittest.TestCase):
    def test_model_and_challenge_are_authenticated_not_hardware_verified(self):
        local, peer = X25519PrivateKey.generate(), X25519PrivateKey.generate()
        model, nonce, iv = "org/model:encrypted", "a" * 64, bytes(range(12))
        key = hashlib.sha256(b"nito-attestation-model-binding-v1\0" + peer.exchange(local.public_key())).digest()
        fields = {"provider_model_id": "native", "proof_format": "near-attestation-report-v1"}
        ciphertext = AESGCM(key).encrypt(iv, json.dumps(fields).encode(), f"{model}\0{nonce}".encode())
        data = {"model": model, "nonce": nonce, "evidence": {"test": True}, "encrypted_supported": True,
                "attestation_available": True, "encryption_protocol": "chat-fields-v1",
                "proof_format": "attestation-evidence-v1",
                "model_binding": {"version": "x25519-aesgcm-v2", "nonce": iv.hex(), "ciphertext": ciphertext.hex(),
                                  "ephemeral_public_key": peer.public_key().public_bytes_raw().hex()}}
        self.assertEqual(open_binding(data, model, nonce, local), ("chat-fields-v1", fields))
        with self.assertRaises(ValueError):
            open_binding(data, model, "b" * 64, local)
        with self.assertRaises(ValueError):
            open_binding(dict(data, encryption_protocol="unknown"), model, nonce, local)
        with self.assertRaises(InvalidTag):
            open_binding(dict(data, model="other"), "other", nonce, local)
