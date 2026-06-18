#!/usr/bin/env python3
# /// script
# dependencies = ["cbor2>=5.5", "cryptography>=42"]
# requires-python = ">=3.11"
# ///
"""Verify a TrustedRouter/Quill attestation document end-to-end.

Production GCP Confidential Space returns a Google-signed JWT from
`/attestation`; AWS Nitro returns a COSE/CBOR attestation document. This verifier
supports both formats and can sample the live endpoint over the same TLS socket
used to fetch the evidence, which catches cross-SNI certificate substitution
bugs.

Examples:
    # Live GCP production check, including same-connection cert binding.
    ./tools/verify-attestation.py \\
        --api-host api.trustedrouter.com \\
        --expect-digest "$(curl -fsS https://trust.trustedrouter.com/image-digest-gcp.txt)" \\
        --samples 8

    # Offline AWS Nitro CBOR check.
    ./tools/verify-attestation.py attestation.cbor \\
        --expected-pcr0 "$(curl -fsS https://trust.trustedrouter.com/pcr0.txt)" \\
        --api-host api.trustedrouter.com
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import secrets
import socket
import ssl
import sys
import urllib.request
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


AWS_NITRO_ROOT_PEM = (Path(__file__).parent / "aws-nitro-root.pem").read_bytes()
GCP_ISSUER = "https://confidentialcomputing.googleapis.com"
GCP_AUDIENCE = "quill-cloud"
_GCP_JWKS: dict[str, Any] | None = None


def b64url_decode(value: str) -> bytes:
    padded = value + "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def looks_like_jwt(blob: bytes) -> bool:
    return blob.count(b".") == 2 and blob[:1] in {b"e", b"E"}


def parse_jwt_payload(blob: bytes) -> dict[str, Any]:
    try:
        _, payload_b64, _ = blob.decode("ascii").split(".", 2)
        payload = json.loads(b64url_decode(payload_b64))
    except Exception as exc:
        sys.exit(f"[FAIL] invalid JWT attestation: {exc}")
    if not isinstance(payload, dict):
        sys.exit("[FAIL] JWT payload is not an object")
    return payload


def parse_jwt_header(blob: bytes) -> dict[str, Any]:
    try:
        header_b64, _, _ = blob.decode("ascii").split(".", 2)
        header = json.loads(b64url_decode(header_b64))
    except Exception as exc:
        sys.exit(f"[FAIL] invalid JWT header: {exc}")
    if not isinstance(header, dict):
        sys.exit("[FAIL] JWT header is not an object")
    return header


def fetch_gcp_jwks() -> dict[str, Any]:
    global _GCP_JWKS
    if _GCP_JWKS is not None:
        return _GCP_JWKS
    with urllib.request.urlopen(f"{GCP_ISSUER}/.well-known/openid-configuration", timeout=10) as response:
        config = json.load(response)
    jwks_uri = config.get("jwks_uri")
    if not isinstance(jwks_uri, str) or not jwks_uri.startswith("https://"):
        sys.exit(f"[FAIL] GCP issuer metadata has invalid jwks_uri: {jwks_uri!r}")
    with urllib.request.urlopen(jwks_uri, timeout=10) as response:
        jwks = json.load(response)
    if not isinstance(jwks, dict) or not isinstance(jwks.get("keys"), list):
        sys.exit("[FAIL] GCP JWKS response has no keys")
    _GCP_JWKS = jwks
    return jwks


def rsa_key_from_jwk(jwk: dict[str, Any]) -> rsa.RSAPublicKey:
    if jwk.get("kty") != "RSA":
        sys.exit(f"[FAIL] unsupported GCP JWT key type: {jwk.get('kty')!r}")
    n = int.from_bytes(b64url_decode(str(jwk["n"])), "big")
    e = int.from_bytes(b64url_decode(str(jwk["e"])), "big")
    return rsa.RSAPublicNumbers(e=e, n=n).public_key()


def verify_gcp_jwt_signature(blob: bytes) -> None:
    header = parse_jwt_header(blob)
    if header.get("alg") != "RS256":
        sys.exit(f"[FAIL] unsupported GCP JWT alg: {header.get('alg')!r}")
    kid = header.get("kid")
    if not isinstance(kid, str) or not kid:
        sys.exit("[FAIL] GCP JWT has no kid")
    jwks = fetch_gcp_jwks()
    key = next((item for item in jwks["keys"] if isinstance(item, dict) and item.get("kid") == kid), None)
    if key is None:
        sys.exit(f"[FAIL] GCP JWT kid not found in issuer JWKS: {kid}")
    signing_input, signature_b64 = blob.rsplit(b".", 1)
    signature = b64url_decode(signature_b64.decode("ascii"))
    rsa_key_from_jwk(key).verify(signature, signing_input, padding.PKCS1v15(), hashes.SHA256())
    print(f"[ok] GCP JWT signature validates against issuer JWKS kid={kid[:12]}...")


def parse_cose_payload(blob: bytes) -> tuple[dict[str, Any], bytes]:
    cose = cbor2.loads(blob)
    if not isinstance(cose, list) or len(cose) != 4:
        sys.exit("[FAIL] not a COSE_Sign1 document")
    _, _, payload_bytes, _ = cose
    payload = cbor2.loads(payload_bytes)
    if not isinstance(payload, dict):
        sys.exit("[FAIL] COSE payload is not a map")
    return payload, payload_bytes


def verify_cose_signature(blob: bytes) -> None:
    cose = cbor2.loads(blob)
    protected_header_bytes, _, payload_bytes, signature = cose
    payload = cbor2.loads(payload_bytes)

    cert_der = payload["certificate"]
    cabundle_der = payload.get("cabundle", []) or []
    leaf = x509.load_der_x509_certificate(cert_der)
    intermediates = [x509.load_der_x509_certificate(c) for c in cabundle_der]
    root = x509.load_pem_x509_certificate(AWS_NITRO_ROOT_PEM)

    sig_structure = cbor2.dumps(["Signature1", protected_header_bytes, b"", payload_bytes])
    public_key = leaf.public_key()
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        sys.exit("[FAIL] Nitro leaf cert public key is not EC")
    r = int.from_bytes(signature[: len(signature) // 2], "big")
    s = int.from_bytes(signature[len(signature) // 2 :], "big")
    public_key.verify(encode_dss_signature(r, s), sig_structure, ec.ECDSA(hashes.SHA384()))

    issuers = list(reversed(intermediates)) + [root]
    children = [leaf] + list(reversed(intermediates))
    for child, parent in zip(children, issuers):
        parent.public_key().verify(  # type: ignore[union-attr]
            child.signature,
            child.tbs_certificate_bytes,
            ec.ECDSA(child.signature_hash_algorithm),
        )
    print("[ok] COSE_Sign1 chain validates to AWS Nitro root")


def cert_spki(der: bytes) -> bytes:
    cert = x509.load_der_x509_certificate(der)
    return cert.public_key().public_bytes(
        encoding=Encoding.DER,
        format=PublicFormat.SubjectPublicKeyInfo,
    )


def fetch_attestation_same_tls_socket(
    host: str, nonce_hex: str, port: int = 443, connect_ip: str | None = None
) -> tuple[bytes, bytes]:
    # connect_ip lets a caller (e.g. the DNS reconciler) attest a SPECIFIC
    # instance by IP while still presenting/validating the canonical hostname
    # (SNI + cert SAN + Host header stay `host`). Without it, host is dialed.
    ctx = ssl.create_default_context()
    with socket.create_connection((connect_ip or host, port), timeout=10) as raw:
        with ctx.wrap_socket(raw, server_hostname=host) as tls:
            cert_der = tls.getpeercert(binary_form=True)
            if cert_der is None:
                sys.exit("[FAIL] TLS handshake returned no peer certificate")
            req = (
                f"GET /attestation?nonce={nonce_hex} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                "Accept: application/jwt, application/cbor, */*\r\n"
                "Connection: close\r\n"
                "\r\n"
            ).encode("ascii")
            tls.sendall(req)
            response = bytearray()
            while True:
                chunk = tls.recv(65536)
                if not chunk:
                    break
                response.extend(chunk)
    header, sep, body = bytes(response).partition(b"\r\n\r\n")
    if sep == b"":
        sys.exit("[FAIL] attestation HTTP response had no header/body separator")
    status_line = header.splitlines()[0].decode("latin1", "replace")
    if " 200 " not in status_line:
        sys.exit(f"[FAIL] attestation HTTP status was not 200: {status_line}")
    if not body:
        sys.exit("[FAIL] empty attestation body")
    return cert_der, body


def fetch_live_cert_der(host: str, port: int = 443, connect_ip: str | None = None) -> bytes:
    ctx = ssl.create_default_context()
    with socket.create_connection((connect_ip or host, port), timeout=10) as raw:
        with ctx.wrap_socket(raw, server_hostname=host) as tls:
            der = tls.getpeercert(binary_form=True)
            if der is None:
                sys.exit("[FAIL] TLS handshake returned no peer certificate")
            return der


def claim_path(payload: dict[str, Any], path: str) -> Any:
    current: Any = payload
    for part in path.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current


def first_claim(payload: dict[str, Any], *paths: str) -> Any:
    for path in paths:
        value = claim_path(payload, path)
        if value not in (None, ""):
            return value
    return None


def walk_values(obj: Any) -> Iterable[tuple[str, Any]]:
    if isinstance(obj, dict):
        for key, value in obj.items():
            yield str(key), value
            yield from walk_values(value)
    elif isinstance(obj, list):
        for value in obj:
            yield from walk_values(value)


def flatten_strings(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        out: list[str] = []
        for item in value:
            out.extend(flatten_strings(item))
        return out
    return [str(value)]


def gcp_nonce_values(payload: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for key, value in walk_values(payload):
        if key in {"eat_nonce", "nonces"}:
            values.extend(flatten_strings(value))
    return [v.lower() for v in values]


def verify_no_gcp_debug(payload: dict[str, Any]) -> None:
    debug_values: list[Any] = []
    for key, value in walk_values(payload):
        if key.lower() == "dbgstat":
            debug_values.append(value)
    if not debug_values:
        print("[ok] GCP dbgstat claim absent")
        return
    bad = [
        value
        for value in debug_values
        if str(value).strip().lower() in {"enabled", "enable", "true", "1", "debug"}
    ]
    if bad:
        sys.exit(f"[FAIL] Confidential Space debug status is enabled: {bad!r}")
    print(f"[ok] GCP dbgstat not enabled ({debug_values!r})")


def verify_gcp_jwt(
    blob: bytes,
    cert_der: bytes,
    *,
    expect_digest: str | None,
    nonce_hex: str | None,
    allow_debug: bool,
) -> None:
    verify_gcp_jwt_signature(blob)
    payload = parse_jwt_payload(blob)

    issuer = payload.get("iss")
    if issuer != GCP_ISSUER:
        sys.exit(f"[FAIL] GCP issuer mismatch: {issuer!r}")
    print(f"[ok] GCP issuer is {issuer}")

    audience = payload.get("aud")
    audiences = audience if isinstance(audience, list) else [audience]
    if GCP_AUDIENCE not in audiences:
        sys.exit(f"[FAIL] GCP audience mismatch: {audience!r}")
    print(f"[ok] GCP audience contains {GCP_AUDIENCE}")

    digest = first_claim(payload, "image_digest", "submods.container.image_digest")
    if expect_digest and str(digest).lower() != expect_digest.strip().lower():
        sys.exit(f"[FAIL] image_digest mismatch:\n  attestation: {digest}\n  expected:    {expect_digest}")
    if digest:
        print(f"[ok] image_digest {str(digest)[:24]}...")

    nonces = gcp_nonce_values(payload)
    cert_fp = hashlib.sha256(cert_der).hexdigest().lower()
    if cert_fp not in nonces:
        sys.exit(
            "[FAIL] live TLS cert fingerprint is not bound in GCP attestation:\n"
            f"  cert sha256: {cert_fp}\n"
            f"  nonces:      {nonces}"
        )
    print(f"[ok] live TLS cert fingerprint bound in GCP nonce ({cert_fp[:16]}...)")

    if nonce_hex and nonce_hex.lower() not in nonces:
        sys.exit(f"[FAIL] caller nonce not present in GCP attestation: {nonce_hex}")
    if nonce_hex:
        print(f"[ok] caller nonce bound ({nonce_hex[:16]}...)")

    if not allow_debug:
        verify_no_gcp_debug(payload)


def verify_aws_cbor(
    blob: bytes,
    cert_der: bytes,
    *,
    expected_pcr0: str | None,
    device_blob_sha: str | None,
) -> None:
    payload, _ = parse_cose_payload(blob)
    verify_cose_signature(blob)

    pcr0 = payload["pcrs"][0].hex()
    if expected_pcr0 and pcr0.lower() != expected_pcr0.strip().lower():
        sys.exit(f"[FAIL] PCR0 mismatch:\n  attestation: {pcr0}\n  expected:    {expected_pcr0}")
    if expected_pcr0:
        print(f"[ok] PCR0 matches {pcr0[:16]}...")

    doc_spki = payload.get("public_key")
    if not doc_spki:
        sys.exit("[FAIL] attestation has no public_key field")
    live_spki = cert_spki(cert_der)
    if doc_spki != live_spki:
        sys.exit(
            "[FAIL] live TLS cert does not match AWS attestation:\n"
            f"  doc spki sha256:  {hashlib.sha256(doc_spki).hexdigest()}\n"
            f"  live spki sha256: {hashlib.sha256(live_spki).hexdigest()}"
        )
    print(f"[ok] live cert SPKI matches AWS attestation ({hashlib.sha256(doc_spki).hexdigest()[:16]}...)")

    user_data = payload.get("user_data") or b""
    cert_fp = hashlib.sha256(cert_der).hexdigest()
    if len(user_data) >= 32 and user_data[:32].hex() != cert_fp:
        sys.exit(
            "[FAIL] AWS attestation user_data cert fingerprint mismatch:\n"
            f"  user_data: {user_data[:32].hex()}\n"
            f"  cert:      {cert_fp}"
        )
    if len(user_data) >= 32:
        print(f"[ok] user_data cert fingerprint matches ({cert_fp[:16]}...)")
    if device_blob_sha and len(user_data) >= 64:
        blob_fp = user_data[32:64].hex()
        if blob_fp.lower() != device_blob_sha.strip().lower():
            sys.exit(f"[FAIL] device-blob mismatch:\n  attestation: {blob_fp}\n  expected:    {device_blob_sha}")
        print(f"[ok] device-blob hash matches {blob_fp[:16]}...")


def read_blob(path: str | None) -> bytes | None:
    if not path:
        return None
    if path == "-":
        return sys.stdin.buffer.read()
    return Path(path).read_bytes()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("blob", nargs="?", help="attestation file path, '-' for stdin, or omit for live sampling")
    parser.add_argument("--api-host", default="api.trustedrouter.com", help="API host to verify")
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument(
        "--connect-ip",
        default=None,
        help="dial this IP directly but keep --api-host as SNI/cert-name/Host "
        "(attest one specific instance behind a shared hostname)",
    )
    parser.add_argument("--samples", type=int, default=1, help="same-TLS-socket live samples to fetch")
    parser.add_argument("--expected-pcr0", default=None, help="hex AWS Nitro PCR0 from the trust page")
    parser.add_argument("--expect-digest", default=None, help="GCP Confidential Space image_digest from the trust page")
    parser.add_argument("--device-blob-sha", default=None, help="hex SHA-256 of canonical device-key blob")
    parser.add_argument("--allow-debug", action="store_true", help="do not fail when GCP dbgstat is enabled")
    args = parser.parse_args()

    blob = read_blob(args.blob)
    if blob is not None and args.samples > 1:
        sys.exit("[FAIL] --samples > 1 requires live mode; omit the blob path")

    if blob is not None:
        cert_der = fetch_live_cert_der(args.api_host, args.port, connect_ip=args.connect_ip)
        if looks_like_jwt(blob):
            verify_gcp_jwt(
                blob,
                cert_der,
                expect_digest=args.expect_digest,
                nonce_hex=None,
                allow_debug=args.allow_debug,
            )
        else:
            verify_aws_cbor(
                blob,
                cert_der,
                expected_pcr0=args.expected_pcr0,
                device_blob_sha=args.device_blob_sha,
            )
        print("\nAttestation verification passed.")
        return 0

    if args.samples < 1:
        sys.exit("[FAIL] --samples must be >= 1")
    for sample in range(1, args.samples + 1):
        nonce_hex = secrets.token_hex(32)
        cert_der, live_blob = fetch_attestation_same_tls_socket(args.api_host, nonce_hex, args.port, connect_ip=args.connect_ip)
        print(f"\nSample {sample}/{args.samples}:")
        if looks_like_jwt(live_blob):
            verify_gcp_jwt(
                live_blob,
                cert_der,
                expect_digest=args.expect_digest,
                nonce_hex=nonce_hex,
                allow_debug=args.allow_debug,
            )
        else:
            verify_aws_cbor(
                live_blob,
                cert_der,
                expected_pcr0=args.expected_pcr0,
                device_blob_sha=args.device_blob_sha,
            )
    print("\nAll sampled attestation bindings passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
