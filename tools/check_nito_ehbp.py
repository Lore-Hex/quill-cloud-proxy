"""Verify a Nito EHBP route. Optional synthetic inference; never retry or log content."""

import argparse
import hashlib
import http.client
import json
import os
import re
import secrets
import socket
import ssl
import subprocess
from urllib.parse import urlencode

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

if __package__:
    from .check_nito_binding import open_binding
else:
    from check_nito_binding import open_binding

# Cross-checked against the direct Tinfoil /v1/models list, not derived from the relay.
MODELS = {
    "openai/gpt-oss-120b:encrypted": "gpt-oss-120b",
    "deepseek/deepseek-v4.1-flash:encrypted": "deepseek-v4-1-flash",
    "google/gemma-4-31b-it:encrypted": "gemma4-31b",
    "z-ai/glm-5.3:encrypted": "glm-5-3",
    "moonshotai/kimi-k3.1-pro:encrypted": "kimi-k3-1-pro",
    "meta-llama/llama-3.3-70b-instruct:encrypted": "llama3-3-70b",
}


class CheckFailed(Exception):
    """Only fixed diagnostics and integer HTTP status codes, never provider content."""


def fetch(method, path, key, headers, body=None):
    conn = http.client.HTTPSConnection("app.trynito.ai", timeout=40)
    try:
        conn.request(method, path, body, {"Authorization": f"Bearer {key}", **headers})
        res = conn.getresponse()
        if res.status != 200:
            code = "unclassified"
            try:
                error = json.loads(res.read(8192))["error"]
                if error.get("code") in {"forbidden", "registered_free_unavailable", "invalid_request",
                                          "model_unavailable", "payment_required", "insufficient_quota",
                                          "rate_limited", "provider_error", "unauthorized"}:
                    code = error["code"]
            except (AttributeError, KeyError, TypeError, ValueError):
                pass
            trace = res.getheader("X-Request-ID", "")
            trace = trace if re.fullmatch(r"[0-9a-zA-Z_-]{8,90}", trace) else "unavailable"
            raise CheckFailed(f"upstream HTTP {res.status}, code={code}, request_id={trace}")
        raw = res.read(4_000_001)
        if len(raw) > 4_000_000:
            raise CheckFailed("oversized response")
        return raw, res.headers
    finally:
        conn.close()


def prove(model, key, verifier, digest):
    nonce = secrets.token_hex(32)
    private = X25519PrivateKey.generate()
    path = "/api/v1/attestation?" + urlencode({"model": model, "trust_tier": "encrypted", "nonce": nonce})
    raw, _ = fetch("GET", path, key, {
        "nito-attestation-model-binding-key": private.public_key().public_bytes_raw().hex(),
        "nito-attestation-model-binding-version": "2",
    })
    envelope = json.loads(raw)
    protocol, binding = open_binding(envelope, model, nonce, private)
    if (protocol, binding["proof_format"], binding["provider_model_id"]) != (
        "ehbp-v1", "tinfoil-verification-document-v1", MODELS[model]
    ):
        raise CheckFailed("unexpected transport, proof or native model")
    evidence = envelope["evidence"]
    # Verifier compares the claimed host and both claimed keys against verified
    # values. The parent never receives a peer-selected URL or signer as policy.
    proc = subprocess.run([verifier, digest], input=json.dumps(evidence).encode(), capture_output=True,
                          timeout=45, env={k: v for k, v in os.environ.items() if k != "NITO_API_KEY"})
    if proc.returncode != 0 or json.loads(proc.stdout).get("tinfoil_bundle_verified") is not True:
        raise CheckFailed("bundle or relay transport identity failed verification")
    identity = evidence["verification"]
    host = identity["enclave_host"]
    with socket.create_connection((host, 443), timeout=10) as sock:
        with ssl.create_default_context().wrap_socket(sock, server_hostname=host) as tls:
            cert = x509.load_der_x509_certificate(tls.getpeercert(binary_form=True))
    spki = cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    if hashlib.sha256(spki).hexdigest() != identity["tls_public_key"]:
        raise CheckFailed("live enclave TLS key differs from verified key")
    return host, identity["hpke_public_key"]


def canary(model, key, host, hpke_key):
    from ehbp.identity import ServerIdentity

    marker = secrets.token_hex(4)
    native = MODELS[model]
    chat = {"model": native, "stream": False, "max_tokens": 128,
            "messages": [{"role": "user", "content": f"Respond with exactly this string: {marker}"}]}
    if native == "gpt-oss-120b":
        chat["reasoning_effort"] = "low"
    req = ServerIdentity.from_public_key_hex(hpke_key).encrypt_request_body(json.dumps(chat).encode())
    raw, headers = fetch("POST", "/v1/chat/completions", key, {
        "Content-Type": "application/octet-stream", "Ehbp-Encapsulated-Key": req.encapsulated_key.hex(),
        "Nito-Encrypted-Model": native, "Nito-Encrypted-Enclave-Url": "https://" + host,
    }, req.body)
    check_reply(req.token, raw, headers, native, marker)


def check_reply(token, raw, headers, native, marker):
    nonces = headers.get_all("Ehbp-Response-Nonce") or []
    if len(nonces) != 1:
        raise CheckFailed("encrypted response nonce missing or duplicated")
    data = json.loads(token.decrypt_response_body(bytes.fromhex(nonces[0]), raw))
    content = data["choices"][0]["message"]["content"]
    if data.get("model") != native or not isinstance(content, str) or marker not in content:
        raise CheckFailed("decrypted reply did not confirm the native model and synthetic challenge")
    usage = data["usage"]
    inp, out, total = (usage[k] for k in ("prompt_tokens", "completion_tokens", "total_tokens"))
    if not all(type(x) is int and x > 0 for x in (inp, out, total)) or out > 128 or inp + out != total:
        raise CheckFailed("invalid decrypted usage")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("model", choices=MODELS)
    parser.add_argument("--verifier", required=True)
    parser.add_argument("--release-digest", required=True, help="current digest obtained independently from Tinfoil")
    parser.add_argument("--canary", action="store_true", help="send exactly one synthetic encrypted JSON request")
    args = parser.parse_args()
    key = os.environ["NITO_API_KEY"]
    stage = "attestation"
    try:
        host, pub = prove(args.model, key, args.verifier, args.release_digest)
        print("Bundle, native-model selection and live enclave TLS key verified.", flush=True)
        if args.canary:
            stage = "encrypted inference"
            canary(args.model, key, host, pub)
            print("Direct encrypted synthetic JSON response, model and usage verified.")
    except Exception as exc:
        reason = str(exc) if isinstance(exc, CheckFailed) else type(exc).__name__
        raise SystemExit(f"{stage} failed ({reason}); no retry") from None


if __name__ == "__main__":
    main()
