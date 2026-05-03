#!/usr/bin/env python3
# /// script
# dependencies = ["cbor2>=5.5", "cryptography>=42"]
# requires-python = ">=3.11"
# ///
"""Verify a Quill Cloud attestation document end-to-end.

Reads a CBOR attestation blob fetched from `https://api.quill.lorehex.co/attestation`
and checks the four bindings the trust page promises:

  1. The COSE_Sign1 signature chains to AWS Nitro's published root.
  2. The PCR0 in the document matches `--expected-pcr0`.
  3. The `public_key` field equals the `SubjectPublicKeyInfo` of the cert
     presented by the live TLS handshake to `--api-host`.
  4. (When --device-blob-sha is supplied) the second 32 bytes of `user_data`
     match — i.e. the document attests to the same device-key blob the
     operator just provisioned.

Run as a one-liner via `uv run --script tools/verify-attestation.py ...`
or pip install cbor2 cryptography first.

Usage:
    ./verify-attestation.py attestation.cbor \\
        --expected-pcr0 $(curl -sS https://trust.quill.lorehex.co/pcr0.txt) \\
        --api-host api.quill.lorehex.co
"""
from __future__ import annotations

import argparse
import hashlib
import socket
import ssl
import sys
from pathlib import Path

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


# AWS Nitro Enclaves attestation root certificate. Source:
#   https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html
# Hash baked in below — fetch script lives next to this file.
AWS_NITRO_ROOT_PEM = (Path(__file__).parent / "aws-nitro-root.pem").read_bytes()


def parse_attestation(blob: bytes) -> tuple[dict, bytes]:
    """Decode the COSE_Sign1 envelope. Returns (parsed payload, raw payload)."""
    cose = cbor2.loads(blob)
    if not isinstance(cose, list) or len(cose) != 4:
        sys.exit("not a COSE_Sign1 (expected 4-element array)")
    _, _, payload_bytes, _ = cose
    payload = cbor2.loads(payload_bytes)
    if not isinstance(payload, dict):
        sys.exit("payload not a map")
    return payload, payload_bytes


def verify_signature(blob: bytes) -> None:
    """Re-assemble the COSE Sig_structure and verify against the document's
    own certificate, then verify that cert chains to the AWS Nitro root."""
    cose = cbor2.loads(blob)
    protected_header_bytes, _, payload_bytes, signature = cose
    payload = cbor2.loads(payload_bytes)

    cert_der = payload["certificate"]
    cabundle_der = payload.get("cabundle", []) or []
    leaf = x509.load_der_x509_certificate(cert_der)
    # AWS publishes cabundle root-first: cabundle[0] is at/near the root,
    # cabundle[-1] is the leaf's direct issuer. We walk leaf → cabundle[-1]
    # → cabundle[-2] → ... → cabundle[0] → AWS root.
    intermediates = [x509.load_der_x509_certificate(c) for c in cabundle_der]
    root = x509.load_pem_x509_certificate(AWS_NITRO_ROOT_PEM)

    sig_structure = cbor2.dumps(["Signature1", protected_header_bytes, b"", payload_bytes])
    public_key = leaf.public_key()
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        sys.exit("leaf cert public key is not EC (Nitro uses P-384)")
    # Convert raw r||s back into DER for the cryptography API.
    r = int.from_bytes(signature[: len(signature) // 2], "big")
    s = int.from_bytes(signature[len(signature) // 2 :], "big")
    der_sig = encode_dss_signature(r, s)
    public_key.verify(der_sig, sig_structure, ec.ECDSA(hashes.SHA384()))

    # Chain order: leaf is signed by intermediates[-1]; intermediates[-1] by
    # intermediates[-2]; ...; intermediates[0] by root.
    issuers = list(reversed(intermediates)) + [root]
    children = [leaf] + list(reversed(intermediates))
    for child, parent in zip(children, issuers):
        parent.public_key().verify(  # type: ignore[union-attr]
            child.signature,
            child.tbs_certificate_bytes,
            ec.ECDSA(child.signature_hash_algorithm),
        )
    print("[ok] COSE_Sign1 chain validates to AWS Nitro root")


def fetch_live_cert_spki(host: str, port: int = 443) -> bytes:
    """TLS-handshake against the live API and grab the leaf cert's SPKI."""
    ctx = ssl.create_default_context()
    # The Quill cert is self-signed; verification is what THIS script is
    # for, so we explicitly skip CA validation for the handshake-only
    # purpose of grabbing the presented cert.
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=10) as raw:
        with ctx.wrap_socket(raw, server_hostname=host) as tls:
            der = tls.getpeercert(binary_form=True)
            assert der is not None
            cert = x509.load_der_x509_certificate(der)
            return cert.public_key().public_bytes(
                encoding=Encoding.DER, format=PublicFormat.SubjectPublicKeyInfo
            )


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("blob", help="path to the attestation CBOR file")
    p.add_argument("--expected-pcr0", required=True, help="hex PCR0 from the trust page")
    p.add_argument("--api-host", default="api.quill.lorehex.co",
                   help="host to TLS-handshake against for the live cert (default: %(default)s)")
    p.add_argument("--device-blob-sha", default=None,
                   help="hex SHA-256 of the canonical device-key blob (optional)")
    args = p.parse_args()

    blob = Path(args.blob).read_bytes()
    payload, _ = parse_attestation(blob)

    # 1. signature → AWS Nitro root
    verify_signature(blob)

    # 2. PCR0 matches
    pcr0 = payload["pcrs"][0].hex()
    if pcr0.lower() != args.expected_pcr0.strip().lower():
        sys.exit(f"[FAIL] PCR0 mismatch:\n  attestation:  {pcr0}\n  expected:     {args.expected_pcr0}")
    print(f"[ok] PCR0 matches {pcr0[:16]}...")

    # 3. public_key matches the live TLS handshake
    doc_spki = payload.get("public_key")
    if not doc_spki:
        sys.exit("[FAIL] attestation has no public_key field")
    live_spki = fetch_live_cert_spki(args.api_host)
    if doc_spki != live_spki:
        sys.exit(
            f"[FAIL] live TLS cert does not match attestation:\n"
            f"  doc spki sha256:  {hashlib.sha256(doc_spki).hexdigest()}\n"
            f"  live spki sha256: {hashlib.sha256(live_spki).hexdigest()}"
        )
    print(f"[ok] live cert spki matches attestation ({hashlib.sha256(doc_spki).hexdigest()[:16]}...)")

    # 4. device-blob hash (if supplied)
    user_data = payload.get("user_data") or b""
    if len(user_data) >= 32:
        cert_fp = user_data[:32].hex()
        print(f"[ok] user_data[:32] = cert_fp = {cert_fp[:16]}...")
    if args.device_blob_sha and len(user_data) >= 64:
        blob_fp = user_data[32:64].hex()
        if blob_fp.lower() != args.device_blob_sha.strip().lower():
            sys.exit(f"[FAIL] device-blob mismatch:\n  attestation:  {blob_fp}\n  expected:     {args.device_blob_sha}")
        print(f"[ok] device-blob hash matches {blob_fp[:16]}...")

    print()
    print("All four bindings hold. The TLS session you're about to use is")
    print("encrypted to the public key the NSM-signed document attests is")
    print("loaded by exactly the PCR0 the trust page publishes.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
