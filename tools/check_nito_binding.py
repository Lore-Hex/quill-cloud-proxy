"""Inspect a Nito encrypted route's v2 binding; never authorize inference.

Supply NITO_API_KEY in the environment. No inference or evidence upload occurs.
The gateway supplies this sealed envelope; opening it is not hardware verification.
"""

import argparse
import hashlib
import http.client
import json
import os
import secrets
from pathlib import Path
from urllib.parse import urlencode

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def open_binding(data, model, nonce, private):
    if data.get("model") != model or data.get("nonce") != nonce:
        raise ValueError("response does not match challenge and model")
    if not data.get("evidence") or data.get("attestation_available") is not True or data.get("encrypted_supported") is not True:
        raise ValueError("missing evidence or encryption capability")
    protocol = data.get("encryption_protocol")
    if protocol not in ("chat-fields-v1", "chat-fields-aesgcm-v1", "ehbp-v1"):
        raise ValueError("unsupported encrypted transport")
    b = data["model_binding"]
    if b["version"] != "x25519-aesgcm-v2" or data.get("proof_format") != "attestation-evidence-v1":
        raise ValueError("unsupported binding format")
    peer = X25519PublicKey.from_public_bytes(bytes.fromhex(b["ephemeral_public_key"]))
    key = hashlib.sha256(b"nito-attestation-model-binding-v1\0" + private.exchange(peer)).digest()
    iv = bytes.fromhex(b["nonce"])
    if len(iv) != 12:
        raise ValueError("invalid binding nonce")
    binding = json.loads(AESGCM(key).decrypt(iv, bytes.fromhex(b["ciphertext"]), f"{model}\0{nonce}".encode()))
    if not all(isinstance(binding.get(k), str) and binding[k] for k in ("provider_model_id", "proof_format")):
        raise ValueError("missing native model or proof format")
    return protocol, binding


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("model")
    model = parser.parse_args().model
    key = os.environ.get("NITO_API_KEY", "").strip()
    if not key or not model.endswith(":encrypted"):
        parser.error("supply NITO_API_KEY and an exact :encrypted model ID")
    nonce = secrets.token_hex(32)
    private = X25519PrivateKey.generate()
    c = http.client.HTTPSConnection("app.trynito.ai", timeout=20)
    try:
        c.request("GET", "/api/v1/attestation?" + urlencode({"model": model, "nonce": nonce}), headers={
            "Authorization": f"Bearer {key}",
            "nito-attestation-model-binding-key": private.public_key().public_bytes_raw().hex(),
            "nito-attestation-model-binding-version": "2",
        })
        response = c.getresponse()
        raw = response.read(4_000_001)
        if response.status != 200 or len(raw) > 4_000_000:
            raise ValueError("attestation unavailable or oversized")
        protocol, binding = open_binding(json.loads(raw), model, nonce, private)
        summary = {"binding_opened": True, "protocol": protocol, "hardware_verified": False,
                   "trustedrouter_confidential": False}
        if binding["proof_format"] == "near-attestation-report-v1":
            policy = Path(__file__).resolve().parents[1] / "enclave-go/sidecar/near_ai_policy.json"
            summary["native_model_in_direct_near_policy"] = any(
                p["model"] == binding["provider_model_id"] for p in json.loads(policy.read_text())
            )
        print(json.dumps(summary))
    except Exception as exc:
        # Third-party exceptions can contain unsanitized provider data.
        raise SystemExit(f"Nito binding check failed ({type(exc).__name__})") from None
    finally:
        c.close()


if __name__ == "__main__":
    main()
