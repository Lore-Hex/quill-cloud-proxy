#!/usr/bin/env python3
# /// script
# dependencies = ["cbor2>=5.5", "cryptography>=42", "pyOpenSSL>=22.0"]
# requires-python = ">=3.11"
# ///
"""Verify a TrustedRouter/Quill attestation document end-to-end.

Production GCP Confidential Space returns a Google-signed JWT from
`/attestation`; Azure returns a Microsoft-Azure-Attestation-signed JWT; AWS Nitro
returns a COSE/CBOR attestation document. This verifier supports all three and
can sample the live endpoint over the same TLS socket used to fetch the
evidence, which catches cross-SNI certificate substitution bugs and verifies the
RFC 9266 tls-exporter session binding. The two JWT clouds are told apart by
ISSUER, never by shape: an MAA token and a Confidential Space token are both
RS256 JWTs, so a shape guess would send Azure evidence down the GCP rules.

Clients MUST fetch `/attestation` and send sensitive requests over the SAME TLS
connection. The server keeps successful `/attestation` responses alive so the
next request can reuse the attested TLS session; this verifier proves that by
fetching a second attestation over the same socket and checking the same exporter
binding. The exporter binding covers one TLS session; a new connection needs a
fresh attestation token.

SECURITY: the exporter check ALONE is insufficient. A relay can launder the
client's own exporter through the caller-nonce channel. Every verifier MUST also
send a fresh random nonce and require it present; the enclave honors only one
caller nonce, so a relay cannot supply both the random nonce and the client
exporter.

WHAT THE AZURE (MAA) PATH DOES AND DOES NOT PROVE
-------------------------------------------------
This is a real asymmetry against AWS, not a gap that more code closes, so it is
written here rather than smoothed over.

A Nitro attestation is SELF-VERIFYING EVIDENCE. The COSE document carries the
hardware's own signature and its certificate chain, and this verifier checks
that chain against `aws-nitro-root.pem`, a file committed to this repo. We parse
the evidence ourselves; AWS cannot mint a document for a non-enclave without the
root key, and a swapped root would show up in git.

MAA is a CLOUD-OPERATED ATTESTATION SERVICE. The enclave hands Microsoft the raw
SEV-SNP report; Microsoft validates it against AMD's VCEK chain and RE-ATTESTS it
as a JWT. This verifier never sees the SNP report and never sees the AMD chain.
So on Azure we are trusting Microsoft's parsing, Microsoft's policy engine, and
Microsoft's signing key — a trusted third party that has no counterpart on the
AWS path. If MAA mis-parses a report or its signing key is misused, nothing here
would notice. That is inherent to the design: AMD does not publish the report,
Azure does, and there is no way to re-derive the hardware evidence from a JWT.

What we CAN do, and do, is refuse to compound it: the signing instance is pinned
to an operator-named allow-list (--expected-maa-issuer), because
`*.attest.azure.net` is a namespace every Azure tenant can join, not an
authority; and HOST_DATA is pinned (--expected-hostdata), because MAA will
attest any caller's hardware report, so "our instance signed it" does not mean
"it describes our workload". Both are mandatory. With them, an Azure token
proves as much as a Nitro one on every axis except this: the hardware evidence
is attested to us by Microsoft rather than checked by us.

Two smaller, honest gaps: SEV-SNP has no field for the TLS SPKI, so the cert is
bound one way (leaf fingerprint) where Nitro binds it two ways; and MAA tokens
carry no caller-requested audience — the Azure producer's sidecar request has no
audience field, unlike attestation_gcp.go which asks for "quill-cloud" — so
there is no MAA analogue of the GCP_AUDIENCE check, and pretending otherwise
would add a gate real tokens could not satisfy.

Default mode is the strict client/security proof that closes G6: exporter
binding is required and the same-socket keep-alive pin is demonstrated.
`--no-require-exporter-binding` is liveness/identity mode for the DNS
reconciler during rolling deploys: verify digest + cert + fresh nonce + debug
state, but make the exporter optional and skip the same-socket pin follow-up.

Examples:
    # Live GCP production check, including same-connection cert binding.
    ./tools/verify-attestation.py \\
        --api-host api.trustedrouter.com \\
        --expect-digest "$(curl -fsS https://trust.trustedrouter.com/accepted-image-digests-gcp.txt)" \\
        --samples 8

    # Concurrent cross-SNI binding stress test against ONE instance. The
    # --samples check is sequential same-socket, so it cannot expose a global
    # last-cert race (one handshake overwriting another's cert). This hammers a
    # single enclave with interleaved api.trustedrouter.com / api.quillrouter.com
    # connections and asserts each served cert is bound in its OWN token — the
    # only way to catch that substitution class.
    ./tools/verify-attestation.py --binding-stress \\
        --connect-ip 35.193.251.216 \\
        --expect-digest "$(curl -fsS https://trust.trustedrouter.com/accepted-image-digests-gcp.txt)"

    # Offline AWS Nitro CBOR check.
    ./tools/verify-attestation.py attestation.cbor \\
        --expected-pcr0 "$(curl -fsS https://trust.trustedrouter.com/pcr0.txt)" \\
        --api-host api.trustedrouter.com

    # Live Azure check. BOTH Azure pins are mandatory: --expected-maa-issuer
    # names the attestation instance we trust to sign (the namespace is shared
    # with every Azure tenant), and --expected-hostdata pins the SEV-SNP
    # HOST_DATA workload measurement (MAA attests any caller's report).
    ./tools/verify-attestation.py \\
        --api-host api-azure.trustedrouter.com \\
        --expected-maa-issuer "$(curl -fsS https://trust.trustedrouter.com/maa-issuer-azure.txt)" \\
        --expected-hostdata "$(curl -fsS https://trust.trustedrouter.com/hostdata-azure.txt)"
"""
from __future__ import annotations

import argparse
import base64
import concurrent.futures
import hashlib
import ipaddress
import json
import os
import re
import select
import secrets
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import cbor2
from OpenSSL import SSL, crypto
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


# Inlined, not read from a sibling file, so this verifier runs straight from a
# URL with no clone and no packaging:
#
#   uv run https://raw.githubusercontent.com/Lore-Hex/quill-cloud-proxy/main/tools/verify-attestation.py --plane aws
#
# That matters more than the tidiness of a separate file. A verification tool a
# reviewer must first clone, install, and wire up is a tool most reviewers never
# run, and a measurement nobody checks is disclosed rather than published. The
# PEP 723 header above already made this URL-runnable except for this one line.
#
# tools/aws-nitro-root.pem is kept as the reviewable copy and
# tools/test_nitro_root_pin.py fails if the two ever diverge — an inlined root
# of trust that can silently drift from its audited counterpart would be worse
# than the sibling read it replaces.
AWS_NITRO_ROOT_PEM_SHA256 = "6eb9688305e4bbca67f44b59c29a0661ae930f09b5945b5d1d9ae01125c8d6c0"
AWS_NITRO_ROOT_PEM = b"""\
-----BEGIN CERTIFICATE-----
MIICETCCAZagAwIBAgIRAPkxdWgbkK/hHUbMtOTn+FYwCgYIKoZIzj0EAwMwSTEL
MAkGA1UEBhMCVVMxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECwwDQVdTMRswGQYD
VQQDDBJhd3Mubml0cm8tZW5jbGF2ZXMwHhcNMTkxMDI4MTMyODA1WhcNNDkxMDI4
MTQyODA1WjBJMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQL
DANBV1MxGzAZBgNVBAMMEmF3cy5uaXRyby1lbmNsYXZlczB2MBAGByqGSM49AgEG
BSuBBAAiA2IABPwCVOumCMHzaHDimtqQvkY4MpJzbolL//Zy2YlES1BR5TSksfbb
48C8WBoyt7F2Bw7eEtaaP+ohG2bnUs990d0JX28TcPQXCEPZ3BABIeTPYwEoCWZE
h8l5YoQwTcU/9KNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUkCW1DdkF
R+eWw5b6cp3PmanfS5YwDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMDA2kAMGYC
MQCjfy+Rocm9Xue4YnwWmNJVA44fA0P5W2OpYow9OYCVRaEevL8uO1XYru5xtMPW
rfMCMQCi85sWBbJwKKXdS6BptQFuZbT73o/gBh1qUxl/nNr12UO8Yfwr6wPLb+6N
IwLz3/Y=
-----END CERTIFICATE-----"""
GCP_ISSUER = "https://confidentialcomputing.googleapis.com"
GCP_AUDIENCE = "quill-cloud"
# `*.attest.azure.net` is a NAMESPACE, not an authority. Any Azure customer can
# run `az attestation create --name <anything>` and own an instance inside it,
# publishing their own signing certs at {issuer}/certs under a policy THEY
# author. So the suffix is a syntactic guard, never the trust anchor: it is the
# analogue of "the certificate chains to some CA", not of GCP_ISSUER or of the
# Nitro root PEM. The real anchor is the operator-supplied allow-list below —
# see require_trusted_maa_issuer().
MAA_ISSUER_HOST_SUFFIX = ".attest.azure.net"
# Exact MAA instance(s) whose signature we accept. There is no compiled-in
# default: the correct value is deployment-specific (it is whatever
# QUILL_AZURE_MAA_ENDPOINT names for the fleet being verified), and guessing one
# would re-open the very hole this closes. Absent => the MAA path fails closed.
MAA_ISSUER_ENV = "QUILL_EXPECTED_MAA_ISSUER"
MAA_ATTESTATION_TYPE = "sevsnpvm"
# SEV-SNP HOST_DATA is a fixed 32-byte field. A shorter value is not a
# measurement of anything, so length is part of the check, not cosmetics.
MAA_HOSTDATA_BYTES = 32
# Clock skew allowed when checking exp/nbf. MAA tokens are short-lived; this is
# the only freshness signal in offline-blob mode, where there is no live nonce.
MAA_CLOCK_SKEW_SECONDS = 300
_HEX_RE = re.compile(r"\A[0-9a-f]+\Z")
# Field names from runtimeData in enclave-go/internal/attestation/attestation_azure.go,
# in Go struct DECLARATION order — encoding/json emits them in that order and the
# verifier has to reproduce those exact bytes to recheck REPORT_DATA.
MAA_RUNTIME_FIELDS = ("leaf_fp", "device_hash", "channel_binding", "nonce")
# channel_binding and nonce carry `omitempty`; leaf_fp and device_hash do not.
MAA_RUNTIME_OMITEMPTY_FIELDS = ("channel_binding", "nonce")
EXPORTER_LABEL = b"EXPORTER-Channel-Binding"
EXPORTER_LENGTH = 32
_GCP_JWKS: dict[str, Any] | None = None
_MAA_JWKS: dict[str, dict[str, Any]] = {}
_TLS_IO_TIMEOUT_SECONDS = 15.0
_SAME_TLS_SOCKET_TIMEOUT_SECONDS = 40.0


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


def check_pcr0_pin(pcr0: str, expected_pcr0: str | None) -> None:
    """Require PCR0 to be one of the pinned measurements. Unpinned = no check.

    Comma-separated SET, matching --expected-hostdata on the Azure path.

    This used to be an equality check, which made changing PCR0 impossible
    without an outage: a rolling EIF replacement legitimately spans the
    published measurement and the incoming one, and under equality one of the
    two ALWAYS fails. Widening the pin first is what makes the change possible.

    Note the sharp edge that motivated the fix: writing "old,new" against an
    equality check fails BOTH, because neither value equals the literal joined
    string. So attempting a bind window without this turns the whole fleet red
    rather than accepting both measurements — the opposite of the intent.
    """
    if not expected_pcr0:
        return
    allowed = {
        value.strip().lower().removeprefix("0x")
        for value in expected_pcr0.split(",")
        if value.strip()
    }
    if not allowed:
        return
    if pcr0.lower() not in allowed:
        sys.exit(
            "[FAIL] PCR0 mismatch:\n"
            f"  attestation:     {pcr0}\n"
            f"  expected one of: {sorted(allowed)}"
        )
    print(f"[ok] PCR0 matches {pcr0[:16]}...")


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


def _verify_callback(_conn: SSL.Connection, _cert: crypto.X509, _errnum: int, _depth: int, ok: int) -> bool:
    return bool(ok)


def _normalize_dns_name(name: str) -> str:
    labels = name.rstrip(".").split(".")
    return ".".join(
        label if label == "*" else label.encode("idna").decode("ascii")
        for label in labels
    ).lower()


def _dnsname_matches(pattern: str, host: str) -> bool:
    try:
        pattern_norm = _normalize_dns_name(pattern)
    except UnicodeError:
        # The peer controls SAN DNS entries. A malformed IDNA label must be a
        # non-match, not an uncaught traceback that bypasses the verifier's
        # structured hostname-mismatch [FAIL].
        return False
    host_norm = _normalize_dns_name(host)
    if "*" not in pattern_norm:
        return host_norm == pattern_norm

    pattern_labels = pattern_norm.split(".")
    host_labels = host_norm.split(".")
    if pattern_norm.count("*") != 1 or pattern_labels[0] != "*" or len(pattern_labels) < 3:
        return False
    return len(host_labels) == len(pattern_labels) and host_labels[1:] == pattern_labels[1:] and host_labels[0] != ""


def _ip_literal(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    value = host.strip()
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def assert_cert_matches_hostname(cert_der: bytes, host: str) -> None:
    cert = x509.load_der_x509_certificate(cert_der)
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        san = None
    dns_names = san.get_values_for_type(x509.DNSName) if san is not None else []
    ip_addresses = san.get_values_for_type(x509.IPAddress) if san is not None else []
    if not dns_names and not ip_addresses:
        sys.exit(f"[FAIL] TLS certificate has no DNS/IP SubjectAlternativeName for {host}")

    host_ip = _ip_literal(host)
    if host_ip is not None:
        if any(host_ip == candidate for candidate in ip_addresses):
            return
    elif any(_dnsname_matches(pattern, host) for pattern in dns_names):
        return

    san_text = [f"DNS:{name}" for name in dns_names] + [f"IP:{addr}" for addr in ip_addresses]
    sys.exit(
        f"[FAIL] TLS certificate hostname mismatch for {host}: "
        f"no matching SubjectAlternativeName in {san_text}"
    )


def _hex_bytes_len(value: str) -> int:
    try:
        bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError("fresh caller nonce is not valid hex") from exc
    return len(value) // 2


def require_fresh_exporter_binding(
    nonces: list[str],
    *,
    exporter_hex: str,
    nonce_hex: str | None,
    require_exporter: bool = True,
    cloud: str = "GCP",
) -> None:
    """Freshness + channel-binding semantics shared by every JWT-issuing cloud.

    `cloud` only names the cloud in the error text. The rule itself is
    identical for Confidential Space and MAA: the caller's fresh nonce must be
    present, long enough, and distinct from the exporter (so a relay cannot
    launder the client's own exporter through the caller-nonce channel), and
    the exporter must be bound unless we are in liveness mode.
    """
    nonce_set = {value.lower() for value in nonces}
    exporter_hex = exporter_hex.lower()
    if nonce_hex is None:
        raise ValueError("fresh caller nonce is required when checking TLS exporter binding")
    nonce_hex = nonce_hex.lower()
    if _hex_bytes_len(nonce_hex) < 16:
        raise ValueError("fresh caller nonce must be at least 16 random bytes")
    if nonce_hex == exporter_hex:
        raise ValueError("fresh caller nonce must differ from the TLS exporter")
    if nonce_hex not in nonce_set:
        raise ValueError(f"fresh caller nonce not present in {cloud} attestation: {nonce_hex}")
    if require_exporter and exporter_hex not in nonce_set:
        raise ValueError(
            f"TLS exporter channel binding is not bound in {cloud} attestation "
            "(pre-Tier-B enclave or relay could not bind this session):\n"
            f"  exporter: {exporter_hex}\n"
            f"  nonces:   {sorted(nonce_set)}"
        )


def require_gcp_fresh_exporter_binding(
    nonces: list[str],
    *,
    exporter_hex: str,
    nonce_hex: str | None,
    require_exporter: bool = True,
) -> None:
    require_fresh_exporter_binding(
        nonces,
        exporter_hex=exporter_hex,
        nonce_hex=nonce_hex,
        require_exporter=require_exporter,
        cloud="GCP",
    )


def _new_pyopenssl_context(*, ca_trust: bool = True) -> SSL.Context:
    """Build the client TLS context.

    `ca_trust=False` selects the ATTESTED-CERT-ONLY model used by the
    standalone regional enclaves (aws.trustedrouter.com): the enclave
    serves a self-signed cert it minted inside the TEE, and trust comes
    from the attestation document binding that cert's fingerprint — not
    from any CA. Skipping chain validation here does NOT weaken the
    proof, because the cert-to-attestation binding check downstream is
    unconditional: a substituted cert fails that check even though the
    handshake succeeded. What it does drop is hostname/CA identity, so
    this mode must never be the default for CA-issued deployments.
    """
    ctx = SSL.Context(SSL.TLS_CLIENT_METHOD)
    # ADVERTISE 1.2+1.3 LIKE A REAL CLIENT; REQUIRE 1.3 BY ASSERTION.
    #
    # This used to pin the minimum to TLS 1.3, which made OpenSSL send a
    # supported_versions extension containing ONLY 0x0304 — a hello no ordinary
    # browser or SDK ever sends. On 2026-08-07 that turned out to be
    # unroutable to the Azure enclaves: a 1.3-only hello REACHES the server
    # (GetCertificate fires) and no response ever comes back, deterministically,
    # in both regions, while the identical hello advertising 1.2+1.3 completes
    # normally and GCP and AWS accept either. Size is not the cause — the
    # WORKING hello is larger (1557 bytes vs 1484).
    #
    # So this tool could not verify the one deployment it most needed to, for a
    # reason that has nothing to do with the deployment's security.
    #
    # Pinning the floor was never the real requirement anyway. The requirement
    # is that the session actually NEGOTIATES 1.3, because the RFC 9266
    # exporter channel binding this tool checks is TLS 1.3-only. That was
    # previously implicit — nothing asserted it — so deleting the min-version
    # line would have silently downgraded every check. assert_tls13() below
    # makes it explicit and load-bearing.
    #
    # The enclave independently refuses TLS 1.2 (alert 70), so advertising it
    # cannot produce a weaker session; it only makes this hello look like the
    # ones real clients send.
    if hasattr(ctx, "set_min_proto_version") and hasattr(SSL, "TLS1_2_VERSION"):
        ctx.set_min_proto_version(SSL.TLS1_2_VERSION)
    else:
        ctx.set_options(SSL.OP_NO_TLSv1 | SSL.OP_NO_TLSv1_1)
    if ca_trust:
        ctx.set_default_verify_paths()
        ctx.set_verify(SSL.VERIFY_PEER, _verify_callback)
    else:
        ctx.set_verify(SSL.VERIFY_NONE, lambda *_a: True)
    return ctx


def _attestation_request(host: str, nonce_hex: str) -> bytes:
    return (
        f"GET /attestation?nonce={nonce_hex} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Accept: application/jwt, application/cbor, */*\r\n"
        "Connection: keep-alive\r\n"
        "\r\n"
    ).encode("ascii")


def _ssl_call(sock: socket.socket, op, *, timeout: float, what: str):
    """Run a pyOpenSSL socket-BIO operation with timeout-mode socket retries.

    Python sockets created with socket.create_connection(..., timeout=...) are
    non-blocking under the hood. pyOpenSSL does not hide that for socket BIOs:
    handshake/read/write signal "try again when the fd is ready" by raising
    WantReadError or WantWriteError. Retrying through select is the standard
    socket-BIO pattern and keeps a real deadline instead of hanging forever.
    """
    deadline = time.monotonic() + timeout
    while True:
        try:
            return op()
        except SSL.WantReadError:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([sock], [], [], remaining)[0]:
                raise TimeoutError(f"{what}: TLS read timeout")
        except SSL.WantWriteError:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([], [sock], [], remaining)[1]:
                raise TimeoutError(f"{what}: TLS write timeout")


def _tls_timeout_remaining(deadline: float, what: str) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError(f"{what}: TLS operation deadline exceeded")
    return min(_TLS_IO_TIMEOUT_SECONDS, remaining)


def _ssl_send_all(
    sock: socket.socket,
    conn: SSL.Connection,
    data: bytes,
    *,
    deadline: float,
    what: str,
) -> None:
    sent = 0
    while sent < len(data):
        n = _ssl_call(
            sock,
            lambda: conn.send(data[sent:]),
            timeout=_tls_timeout_remaining(deadline, what),
            what=what,
        )
        if n <= 0:
            raise EOFError(f"{what}: TLS send returned {n}")
        sent += n


def _recv_or_fail(
    conn: SSL.Connection,
    raw: socket.socket,
    context: str,
    *,
    deadline: float,
) -> bytes:
    try:
        chunk = _ssl_call(
            raw,
            lambda: conn.recv(65536),
            timeout=_tls_timeout_remaining(deadline, f"{context} recv"),
            what=f"{context} recv",
        )
    except SSL.ZeroReturnError as exc:
        raise EOFError(context) from exc
    if not chunk:
        raise EOFError(context)
    return chunk


def _read_http_response(
    conn: SSL.Connection,
    raw: socket.socket,
    context: str,
    *,
    deadline: float,
) -> tuple[str, dict[str, str], bytes]:
    response = bytearray()
    while b"\r\n\r\n" not in response:
        response.extend(_recv_or_fail(conn, raw, context, deadline=deadline))
    header, sep, rest = bytes(response).partition(b"\r\n\r\n")
    if sep == b"":
        sys.exit(f"[FAIL] {context} HTTP response had no header/body separator")
    lines = header.splitlines()
    if not lines:
        sys.exit(f"[FAIL] {context} HTTP response had no status line")
    status_line = lines[0].decode("latin1", "replace")
    headers: dict[str, str] = {}
    for line in lines[1:]:
        name, colon, value = line.partition(b":")
        if colon:
            headers[name.decode("latin1").strip().lower()] = value.decode("latin1").strip()
    try:
        content_length = int(headers["content-length"])
    except KeyError:
        sys.exit(f"[FAIL] {context} HTTP response had no Content-Length")
    except ValueError:
        sys.exit(f"[FAIL] {context} HTTP response had invalid Content-Length: {headers.get('content-length')!r}")
    if content_length < 0:
        sys.exit(f"[FAIL] {context} HTTP response had negative Content-Length")
    body = bytearray(rest)
    while len(body) < content_length:
        body.extend(_recv_or_fail(conn, raw, context, deadline=deadline))
    return status_line, headers, bytes(body[:content_length])


def _require_attestation_body_binds_exporter(
    blob: bytes,
    exporter: bytes,
    nonce_hex: str,
    label: str,
    *,
    require_exporter: bool = True,
) -> None:
    exporter_hex = exporter.hex().lower()
    nonce_hex = nonce_hex.lower()
    try:
        if looks_like_jwt(blob):
            # Dispatch site 1 of 4. Both clouds issue JWTs; route on the issuer.
            cloud = jwt_attestation_cloud(blob)
            payload = parse_jwt_payload(blob)
            if cloud == "maa":
                fields, _runtime_bytes = maa_runtime_data(payload)
                require_fresh_exporter_binding(
                    maa_binding_values(fields),
                    exporter_hex=exporter_hex,
                    nonce_hex=nonce_hex,
                    require_exporter=require_exporter,
                    cloud="MAA",
                )
                return
            nonces = gcp_nonce_values(payload)
            require_gcp_fresh_exporter_binding(
                nonces,
                exporter_hex=exporter_hex,
                nonce_hex=nonce_hex,
                require_exporter=require_exporter,
            )
            return
        payload, _ = parse_cose_payload(blob)
        user_data = payload.get("user_data") or b""
        if require_exporter:
            if len(user_data) < 96:
                raise ValueError("AWS attestation has no TLS exporter channel binding in user_data")
            bound_exporter = user_data[64:96]
            if bound_exporter != exporter:
                raise ValueError(
                    "AWS attestation exporter mismatch: "
                    f"user_data={bound_exporter.hex()} exporter={exporter_hex}"
                )
        nonce = payload.get("nonce") or b""
        if nonce != bytes.fromhex(nonce_hex):
            raise ValueError(
                "AWS attestation fresh nonce mismatch: "
                f"payload={bytes(nonce).hex() if isinstance(nonce, bytes) else nonce!r} "
                f"expected={nonce_hex}"
            )
    except Exception as exc:
        if isinstance(exc, SystemExit):
            raise
        sys.exit(f"[FAIL] {label} attestation is not bound to this TLS session: {exc}")


def assert_tls13(conn, label: str = "") -> None:
    """The negotiated version MUST be TLS 1.3.

    Not the advertised floor — the negotiated result. The exporter channel
    binding (RFC 9266) that ties the attestation to this exact session exists
    only in 1.3; on a 1.2 session export_keying_material() still returns bytes,
    so a downgraded session would produce a binding that looks fine and proves
    nothing.
    """
    version = conn.get_protocol_version_name()
    where = f" ({label})" if label else ""
    if version != "TLSv1.3":
        sys.exit(
            f"[FAIL] negotiated {version}, need TLSv1.3{where}. The exporter "
            "channel binding this proof depends on does not exist below 1.3."
        )
    print(f"[ok] negotiated TLSv1.3{where}")


def fetch_attestation_same_tls_socket(
    host: str,
    nonce_hex: str,
    port: int = 443,
    connect_ip: str | None = None,
    *,
    require_exporter: bool = True,
    require_pin: bool = True,
    ca_trust: bool = True,
    timeout: float = _SAME_TLS_SOCKET_TIMEOUT_SECONDS,
) -> tuple[bytes, bytes, bytes, str | None, bytes | None]:
    # connect_ip lets a caller (e.g. the DNS reconciler) attest a SPECIFIC
    # instance by IP while still presenting/validating the canonical hostname
    # (SNI + cert SAN + Host header stay `host`). Without it, host is dialed.
    ctx = _new_pyopenssl_context(ca_trust=ca_trust)
    deadline = time.monotonic() + timeout
    raw = socket.create_connection((connect_ip or host, port), timeout=min(10.0, timeout))
    conn = SSL.Connection(ctx, raw)
    try:
        conn.set_tlsext_host_name(host.encode("idna"))
        conn.set_connect_state()
        _ssl_call(
            raw,
            conn.do_handshake,
            timeout=_tls_timeout_remaining(deadline, "handshake"),
            what="handshake",
        )
        assert_tls13(conn, host)
        peer = conn.get_peer_certificate()
        if peer is None:
            sys.exit("[FAIL] TLS handshake returned no peer certificate")
        cert_der = crypto.dump_certificate(crypto.FILETYPE_ASN1, peer)
        assert_cert_matches_hostname(cert_der, host)
        exporter = conn.export_keying_material(EXPORTER_LABEL, EXPORTER_LENGTH)
        _ssl_send_all(
            raw,
            conn,
            _attestation_request(host, nonce_hex),
            deadline=deadline,
            what="attestation request",
        )
        try:
            status_line, _headers, body = _read_http_response(
                conn,
                raw,
                "attestation",
                deadline=deadline,
            )
        except Exception as exc:
            sys.exit(f"[FAIL] attestation socket closed before the first response was fully framed: {exc}")
        if " 200 " not in status_line:
            sys.exit(f"[FAIL] attestation HTTP status was not 200: {status_line}")
        if not body:
            sys.exit("[FAIL] empty attestation body")
        _require_attestation_body_binds_exporter(
            body,
            exporter,
            nonce_hex,
            "first",
            require_exporter=require_exporter,
        )
        if not require_pin:
            return cert_der, exporter, body, None, None

        # G6 pinning is meaningful only if the prompt can follow the evidence on
        # this exact TLS session. A second fresh attestation is an unauthenticated
        # stand-in for that prompt and proves the server did not close after the
        # first response.
        followup_nonce_hex = secrets.token_hex(32)
        try:
            _ssl_send_all(
                raw,
                conn,
                _attestation_request(host, followup_nonce_hex),
                deadline=deadline,
                what="follow-up attestation request",
            )
            followup_status, _followup_headers, followup_body = _read_http_response(
                conn,
                raw,
                "follow-up attestation",
                deadline=deadline,
            )
        except Exception as exc:
            sys.exit(
                "[FAIL] attested TLS socket closed after the first /attestation; "
                f"clients cannot pin a sensitive request to that attestation: {exc}"
            )
        if " 200 " not in followup_status:
            sys.exit(f"[FAIL] follow-up attestation HTTP status was not 200: {followup_status}")
        if not followup_body:
            sys.exit("[FAIL] empty follow-up attestation body")
        followup_exporter = conn.export_keying_material(EXPORTER_LABEL, EXPORTER_LENGTH)
        if followup_exporter != exporter:
            sys.exit("[FAIL] TLS exporter changed on a reused socket")
        _require_attestation_body_binds_exporter(
            followup_body,
            exporter,
            followup_nonce_hex,
            "follow-up",
            require_exporter=require_exporter,
        )
    finally:
        try:
            conn.shutdown()
        except Exception:
            pass
        conn.close()
    return cert_der, exporter, body, followup_nonce_hex, followup_body


def fetch_live_cert_der(
    host: str, port: int = 443, connect_ip: str | None = None, *, ca_trust: bool = True
) -> bytes:
    ctx = ssl.create_default_context()
    if not ca_trust:
        # See _new_pyopenssl_context: attested-cert-only mode. The cert we
        # return here is still checked against the attestation binding.
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
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
    exporter: bytes | None,
    expect_digest: str | None,
    nonce_hex: str | None,
    allow_debug: bool,
    device_blob_sha: str | None = None,
    require_exporter: bool = True,
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
    if expect_digest:
        # --expect-digest may be a comma-separated SET: the published trust
        # digest PLUS the incoming release digest during a rolling deploy (so
        # the fleet, which legitimately spans two digests mid-roll, all
        # verifies). Pass if the attestation matches ANY allowed digest.
        allowed = {d.strip().lower() for d in expect_digest.split(",") if d.strip()}
        if str(digest).lower() not in allowed:
            sys.exit(f"[FAIL] image_digest mismatch:\n  attestation: {digest}\n  expected one of: {sorted(allowed)}")
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

    # attestation_gcp.go puts sha256(deviceBlob) in nonces[1], so an operator
    # who passes --device-blob-sha gets it checked here rather than dropped.
    if device_blob_sha:
        want_device = device_blob_sha.strip().lower()
        if want_device not in nonces:
            sys.exit(
                "[FAIL] device-blob hash is not bound in GCP attestation:\n"
                f"  expected: {want_device}\n"
                f"  nonces:   {nonces}"
            )
        print(f"[ok] device-blob hash bound in GCP nonce ({want_device[:16]}...)")

    if exporter is not None:
        exporter_hex = exporter.hex().lower()
        try:
            require_gcp_fresh_exporter_binding(
                nonces,
                exporter_hex=exporter_hex,
                nonce_hex=nonce_hex,
                require_exporter=require_exporter,
            )
        except ValueError as exc:
            sys.exit(f"[FAIL] {exc}")
        if require_exporter:
            print(f"[ok] TLS exporter channel binding bound in GCP nonce ({exporter_hex[:16]}...)")
        elif exporter_hex in nonces:
            print(f"[ok] optional TLS exporter channel binding present in GCP nonce ({exporter_hex[:16]}...)")
        else:
            print("[ok] TLS exporter channel binding optional in liveness mode")
        print(f"[ok] caller nonce bound ({nonce_hex[:16]}...)")
    elif nonce_hex:
        if nonce_hex.lower() not in nonces:
            sys.exit(f"[FAIL] caller nonce not present in GCP attestation: {nonce_hex}")
        print(f"[ok] caller nonce bound ({nonce_hex[:16]}...)")

    if not allow_debug:
        verify_no_gcp_debug(payload)


def is_maa_issuer(issuer: Any) -> bool:
    """True iff `issuer` is an https URL under *.attest.azure.net.

    Predicate only — used for routing, so it returns False instead of exiting.
    """
    if not isinstance(issuer, str) or not issuer:
        return False
    try:
        parts = urllib.parse.urlsplit(issuer)
    except ValueError:
        return False
    host = (parts.hostname or "").lower()
    if parts.scheme != "https" or not host.endswith(MAA_ISSUER_HOST_SUFFIX):
        return False
    return bool(host[: -len(MAA_ISSUER_HOST_SUFFIX)])


def jwt_attestation_cloud(blob: bytes) -> str:
    """Route a JWT attestation by ISSUER, never by shape.

    An MAA token and a Confidential Space token are both RS256 JWTs, so
    looks_like_jwt() cannot tell them apart: dispatching on shape sends an
    Azure token into the GCP branch, where it dies on the GCP issuer check —
    an unhelpful failure that looks like a broken enclave rather than a
    routing bug. Route on `iss`, and refuse an issuer we do not recognise
    instead of guessing: an unknown issuer is exactly what a forged token
    carries.
    """
    payload = parse_jwt_payload(blob)
    issuer = payload.get("iss")
    if issuer == GCP_ISSUER:
        return "gcp"
    if is_maa_issuer(issuer):
        return "maa"
    sys.exit(
        "[FAIL] unknown JWT attestation issuer — not GCP Confidential Space "
        f"({GCP_ISSUER}) and not Microsoft Azure Attestation "
        f"(https://<instance>{MAA_ISSUER_HOST_SUFFIX}): {issuer!r}"
    )


def normalize_maa_issuer(issuer: str) -> str:
    """Canonical comparison form: lowercase host, no trailing slash.

    Only ever applied to a string that already passed is_maa_issuer(), so the
    scheme is https and the host is non-empty.
    """
    parts = urllib.parse.urlsplit(issuer)
    return f"https://{(parts.hostname or '').lower()}{parts.path.rstrip('/')}"


def maa_issuer_allowlist(expect_issuer: str | None) -> set[str]:
    """The exact MAA instances we trust, from the flag or MAA_ISSUER_ENV.

    Fails closed when empty. This is the MAA analogue of the Nitro root PEM and
    of GCP_ISSUER, and unlike --expected-pcr0 / --expect-digest it cannot be
    optional: those two pin the WORKLOAD while the signing authority stays
    fixed (one AWS root, one Google issuer). MAA has no fixed authority — every
    Azure tenant can stand up an instance under *.attest.azure.net and serve
    its own keys — so with no allow-list the verifier fetches its trust anchor
    from a host the token itself names, and any tenant's token verifies.
    """
    raw = expect_issuer if expect_issuer else os.environ.get(MAA_ISSUER_ENV, "")
    entries = [value.strip() for value in raw.split(",") if value.strip()]
    if not entries:
        sys.exit(
            "[FAIL] no trusted MAA issuer configured, so this token cannot be verified.\n"
            "  Pass --expected-maa-issuer (comma-separated for a multi-region fleet) or set "
            f"{MAA_ISSUER_ENV}, naming the exact attestation instance(s) this fleet attests\n"
            "  against — the same value the enclave's QUILL_AZURE_MAA_ENDPOINT is set to,\n"
            "  e.g. https://<instance>.<region>.attest.azure.net.\n"
            f"  Refusing to fall back to 'any host under *{MAA_ISSUER_HOST_SUFFIX}': that namespace is\n"
            "  open to every Azure tenant, and each one serves its own signing keys under a policy\n"
            "  it wrote, so a token from an ATTACKER-owned instance would verify against the\n"
            "  attacker's own key. Unlike AWS (root PEM in this repo) and GCP (one Google issuer),\n"
            "  Azure has no fixed authority to compile in — it has to be named here."
        )
    allowed: set[str] = set()
    for entry in entries:
        if not is_maa_issuer(entry):
            sys.exit(
                f"[FAIL] --expected-maa-issuer entry is not an https://*{MAA_ISSUER_HOST_SUFFIX} URL: {entry!r}"
            )
        allowed.add(normalize_maa_issuer(entry))
    return allowed


def require_trusted_maa_issuer(issuer: Any, expect_issuer: str | None) -> str:
    """Return `issuer` iff it is one of the exact instances we were told to trust.

    Runs BEFORE any JWKS fetch: the issuer comes out of a token whose signature
    has not been checked, so following it to fetch a key is what makes an
    unpinned issuer fatal rather than merely untidy.
    """
    allowed = maa_issuer_allowlist(expect_issuer)
    if not is_maa_issuer(issuer):
        sys.exit(f"[FAIL] MAA issuer is not an https://*{MAA_ISSUER_HOST_SUFFIX} URL: {issuer!r}")
    issuer = str(issuer)
    if normalize_maa_issuer(issuer) not in allowed:
        sys.exit(
            "[FAIL] MAA issuer is not a trusted attestation instance:\n"
            f"  token issuer:    {issuer}\n"
            f"  trusted one of:  {sorted(allowed)}\n"
            f"  The issuer is syntactically under *{MAA_ISSUER_HOST_SUFFIX}, but that namespace is shared by\n"
            "  every Azure tenant. An instance we did not name serves keys we do not control, under an\n"
            "  attestation policy we did not write, so its claims prove nothing about this fleet."
        )
    return issuer


def maa_issuer_jwks_uri(issuer: str) -> str:
    """Map an MAA issuer to its JWKS URL, refusing any issuer we do not trust.

    MAA publishes its signing certificates at {issuer}/certs — NOT at the OIDC
    well-known path Confidential Space uses.

    The issuer comes out of a token whose signature has NOT been checked yet,
    so it is attacker-controlled input. Following it to an arbitrary URL would
    let a forged token nominate its own JWKS host and "validate" against the
    forger's key, which is the whole ballgame. Pin it to
    https://<instance>.attest.azure.net, with no userinfo, no port, and no
    query, before fetching anything.
    """
    if not is_maa_issuer(issuer):
        sys.exit(f"[FAIL] MAA issuer is not an https://*{MAA_ISSUER_HOST_SUFFIX} URL: {issuer!r}")
    parts = urllib.parse.urlsplit(issuer)
    host = (parts.hostname or "").lower()
    if parts.netloc.lower() != host:
        sys.exit(f"[FAIL] MAA issuer must be a bare https host with no userinfo or port: {issuer!r}")
    if parts.query or parts.fragment:
        sys.exit(f"[FAIL] MAA issuer must not carry a query or fragment: {issuer!r}")
    return f"https://{host}{parts.path.rstrip('/')}/certs"


class _PinnedHostRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Keep a redirected JWKS fetch on the pinned host, over https.

    maa_issuer_jwks_uri() carefully pins scheme, host, userinfo, port and query
    — and the default opener would then follow a 302 from that host to anywhere
    on the internet (HTTPRedirectHandler even permits a downgrade to http),
    handing key selection back to whoever can answer for the issuer. Same-host
    redirects are still allowed, so this cannot break a real MAA endpoint that
    normalises its own URL.
    """

    def __init__(self, host: str) -> None:
        super().__init__()
        self.host = host.lower()

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> urllib.request.Request | None:
        parts = urllib.parse.urlsplit(newurl)
        if parts.scheme != "https" or (parts.hostname or "").lower() != self.host:
            raise urllib.error.HTTPError(
                newurl,
                code,
                f"MAA JWKS redirect leaves the pinned issuer host {self.host}: {newurl!r}",
                headers,
                fp,
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch_maa_jwks(issuer: str) -> dict[str, Any]:
    jwks_uri = maa_issuer_jwks_uri(issuer)
    cached = _MAA_JWKS.get(jwks_uri)
    if cached is not None:
        return cached
    host = (urllib.parse.urlsplit(jwks_uri).hostname or "").lower()
    opener = urllib.request.build_opener(_PinnedHostRedirectHandler(host))
    try:
        with opener.open(jwks_uri, timeout=10) as response:
            jwks = json.load(response)
    except urllib.error.HTTPError as exc:
        sys.exit(f"[FAIL] MAA JWKS fetch failed for {jwks_uri}: {exc}")
    if not isinstance(jwks, dict) or not isinstance(jwks.get("keys"), list):
        sys.exit(f"[FAIL] MAA JWKS response has no keys: {jwks_uri}")
    _MAA_JWKS[jwks_uri] = jwks
    return jwks


def rsa_key_from_maa_jwk(jwk: dict[str, Any]) -> rsa.RSAPublicKey:
    """Extract the RSA public key from an MAA JWKS entry.

    ASSUMED, NOT OBSERVED: MAA's /certs entries are documented to carry the
    signing certificate chain in `x5c` and are not guaranteed to include the
    bare `n`/`e` RSA parameters that Google's JWKS uses. Nothing in the Go
    producer pins this down (it never fetches the JWKS), so both encodings are
    handled and anything else is refused rather than guessed at.
    """
    if jwk.get("kty") != "RSA":
        sys.exit(f"[FAIL] unsupported MAA JWT key type: {jwk.get('kty')!r}")
    if jwk.get("n") and jwk.get("e"):
        return rsa_key_from_jwk(jwk)
    x5c = jwk.get("x5c")
    if isinstance(x5c, list) and x5c and isinstance(x5c[0], str):
        try:
            cert = x509.load_der_x509_certificate(base64.b64decode(x5c[0]))
        except Exception as exc:
            sys.exit(f"[FAIL] MAA JWKS x5c entry is not a parseable certificate: {exc}")
        key = cert.public_key()
        if not isinstance(key, rsa.RSAPublicKey):
            sys.exit("[FAIL] MAA JWKS x5c certificate does not carry an RSA public key")
        return key
    sys.exit("[FAIL] MAA JWKS key has neither RSA n/e parameters nor an x5c chain")


def verify_maa_jwt_signature(blob: bytes, *, expect_issuer: str | None, quiet: bool = False) -> str:
    header = parse_jwt_header(blob)
    if header.get("alg") != "RS256":
        sys.exit(f"[FAIL] unsupported MAA JWT alg: {header.get('alg')!r}")
    kid = header.get("kid")
    if not isinstance(kid, str) or not kid:
        sys.exit("[FAIL] MAA JWT has no kid")
    # Allow-list first: the fetch below goes to a host this unverified token
    # names, so an untrusted issuer must never reach the network.
    issuer = require_trusted_maa_issuer(parse_jwt_payload(blob).get("iss"), expect_issuer)
    jwks = fetch_maa_jwks(issuer)
    key_jwk = next((item for item in jwks["keys"] if isinstance(item, dict) and item.get("kid") == kid), None)
    if key_jwk is None:
        sys.exit(f"[FAIL] MAA JWT kid not found in issuer JWKS: {kid}")
    signing_input, signature_b64 = blob.rsplit(b".", 1)
    try:
        signature = b64url_decode(signature_b64.decode("ascii"))
    except Exception as exc:
        sys.exit(f"[FAIL] MAA JWT signature is not base64url: {exc}")
    try:
        rsa_key_from_maa_jwk(key_jwk).verify(signature, signing_input, padding.PKCS1v15(), hashes.SHA256())
    except SystemExit:
        raise
    except Exception as exc:
        sys.exit(f"[FAIL] MAA JWT signature does not validate against issuer JWKS kid={kid}: {exc!r}")
    if not quiet:
        print(f"[ok] MAA JWT signature validates against {issuer} JWKS kid={kid[:12]}...")
    return issuer


def _decode_base64_any(value: str, what: str) -> bytes:
    text = value.strip()
    padded = text + "=" * (-len(text) % 4)
    try:
        return base64.b64decode(padded, validate=True)
    except Exception:
        pass
    try:
        return base64.urlsafe_b64decode(padded)
    except Exception as exc:
        sys.exit(f"[FAIL] {what} is not valid base64: {exc}")


def canonical_runtime_data_json(fields: dict[str, Any]) -> bytes:
    """Rebuild the exact bytes the SNP report commits to.

    MEASURED against a real SEV-SNP confidential container group (Azure UAE
    North, skr sidecar 2.7) on 2026-08-03. MAA does NOT echo the base64 string
    the enclave sent — it re-serialises runtime_data as a JSON object with keys
    in ALPHABETICAL order, so the sent byte order is destroyed in transit and
    only the sorted form can ever be reconstructed here.

    attestation_azure.go therefore declares its runtimeData fields
    alphabetically so the bytes it hashes already equal this reconstruction.
    Sorting here and not there (or vice versa) means the digest never matches
    and every real token fails — which is exactly what the first draft did,
    with fields in declaration order and SHA-512 over them.

    `omitempty` still applies: absent channel_binding/nonce are dropped rather
    than emitted as "".
    """
    ordered = {
        name: ("" if fields.get(name) is None else str(fields.get(name)))
        for name in sorted(MAA_RUNTIME_FIELDS)
        if not (name in MAA_RUNTIME_OMITEMPTY_FIELDS and fields.get(name) in (None, ""))
    }
    return json.dumps(ordered, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _find_runtime_fields(obj: Any, depth: int = 0) -> dict[str, Any] | None:
    if depth > 6 or not isinstance(obj, dict):
        return None
    if "leaf_fp" in obj and "device_hash" in obj:
        return obj
    for value in obj.values():
        found = _find_runtime_fields(value, depth + 1)
        if found is not None:
            return found
    return None


def maa_runtime_data(payload: dict[str, Any]) -> tuple[dict[str, Any], bytes]:
    """Return (runtime fields, the exact bytes REPORT_DATA should commit to).

    CLAIM SHAPE — ASSUMED, NOT OBSERVED. The Go producer (attestation_azure.go)
    fixes what we SEND: base64 of the compact runtimeData JSON. It says nothing
    about how MAA echoes it back, and there is no live Azure token to look at.
    Azure documents `x-ms-runtime` as a JSON object, but the guest-attestation
    flow is also described as echoing the runtime data as an opaque base64
    string, so BOTH are handled:

      * string  -> base64-decode; those are the producer's exact bytes, so the
                   SHA-512 check is exact.
      * object  -> the claim was parsed by MAA, so the original bytes are gone
                   and we must RE-serialise them with Go's rules
                   (canonical_runtime_data_json). If MAA's parse/echo differs
                   from Go's marshal in any way, the REPORT_DATA check fails
                   closed — a first Azure bring-up should expect to confirm
                   this shape against a real token.

    The object form is searched recursively because MAA is documented to nest
    caller data under a wrapper key (e.g. "client-payload"), and which wrapper
    appears here is likewise unverified.
    """
    candidates = [payload.get("x-ms-runtime"), payload.get("x-ms-runtime-data")]
    # Prefer a string claim wherever it appears: base64 hands back the exact
    # bytes the enclave hashed, so the REPORT_DATA check is a comparison rather
    # than a reconstruction. Only fall back to the object form.
    claim: Any = next((value for value in candidates if isinstance(value, str) and value.strip()), None)
    if claim is None:
        claim = next((value for value in candidates if isinstance(value, dict)), None)
    if isinstance(claim, str) and claim.strip():
        raw = _decode_base64_any(claim, "MAA x-ms-runtime claim")
        try:
            fields = json.loads(raw)
        except Exception as exc:
            sys.exit(f"[FAIL] MAA x-ms-runtime does not base64-decode to JSON: {exc}")
        if not isinstance(fields, dict):
            sys.exit("[FAIL] MAA x-ms-runtime does not decode to a JSON object")
        return fields, raw
    if isinstance(claim, dict):
        fields = _find_runtime_fields(claim)
        if fields is None:
            sys.exit(
                "[FAIL] MAA x-ms-runtime claim carries no leaf_fp/device_hash runtime data; "
                "the token is not bound to this enclave's TLS leaf or device key"
            )
        return fields, canonical_runtime_data_json(fields)
    sys.exit(
        "[FAIL] MAA token has no usable x-ms-runtime claim; without the echoed runtime "
        "data there is nothing tying the hardware report to this TLS session"
    )


def maa_binding_values(fields: dict[str, Any]) -> list[str]:
    """The MAA analogue of gcp_nonce_values(): everything the enclave bound."""
    values: list[str] = []
    for name in ("leaf_fp", "channel_binding", "nonce"):
        value = fields.get(name)
        if isinstance(value, str) and value:
            values.append(value.lower())
    return values


def verify_maa_hostdata(payload: dict[str, Any], expect_hostdata: str | None) -> str:
    """Require a real SEV-SNP HOST_DATA workload measurement.

    This is the whole point of verifying Azure at all, and it is deliberately
    strict enough to REJECT the deployment shape that is easiest to reach.

    On a plain Azure confidential VM (Standard_DC2ads_v5 and friends) the
    SEV-SNP report attests the guest firmware and launch state; HOST_DATA is
    not populated with any measurement of the application. There is no claim
    that says "this box is running quill-enclave@sha256:...". On confidential
    containers (ACI/AKS with confcom) HOST_DATA carries the CCE policy hash,
    which pins the exact permitted container image digests — the true analogue
    of Nitro PCR0 and Confidential Space image_digest.

    So absent, malformed, all-zero, or unpinned HOST_DATA fails, always.
    Accepting any of those would let a region ship attesting strictly weaker
    than AWS and GCP while still printing "verification passed", which is worse
    than having no Azure support at all.
    """
    hostdata = maa_hostdata_value(payload)
    check_maa_hostdata_pin(hostdata, expect_hostdata)
    print(f"[ok] MAA hostdata (SEV-SNP HOST_DATA) {hostdata[:24]}...")
    return hostdata


def maa_hostdata_value(payload: dict[str, Any]) -> str:
    """Normalised 32-byte HOST_DATA hex, or sys.exit. No pin check, no output."""
    raw = payload.get("x-ms-sevsnpvm-hostdata")
    if not isinstance(raw, str) or not raw.strip():
        sys.exit(
            "[FAIL] MAA token has no x-ms-sevsnpvm-hostdata claim: the SEV-SNP report "
            "carries NO measurement of the workload. That is what a PLAIN Azure "
            "confidential VM produces — it attests the guest firmware and launch state, "
            "not the code that is running, so nothing here says which image served this "
            "request. Deploy on confidential containers (ACI/AKS confcom), where "
            "HOST_DATA carries the CCE policy hash pinning the permitted image digests."
        )
    hostdata = raw.strip().lower().removeprefix("0x")
    # bytes.fromhex() silently skips ASCII whitespace, so "00 00 00 01" would
    # parse as 4 bytes and then disagree with the (un-normalised) pin
    # comparison below. Demand a clean even-length hex string instead.
    if not _HEX_RE.match(hostdata) or len(hostdata) % 2:
        sys.exit(f"[FAIL] MAA x-ms-sevsnpvm-hostdata is not hex: {raw!r}")
    hostdata_bytes = bytes.fromhex(hostdata)
    if not any(hostdata_bytes):
        sys.exit(
            "[FAIL] MAA x-ms-sevsnpvm-hostdata is all zero "
            f"({len(hostdata_bytes)} bytes): the guest was launched with no HOST_DATA, "
            "so the hardware report measures no workload. This is a plain confidential "
            "VM, not a confidential container with a CCE policy hash — it cannot prove "
            "which image is running and must not be trusted as an attested enclave."
        )
    if len(hostdata_bytes) != MAA_HOSTDATA_BYTES:
        sys.exit(
            f"[FAIL] MAA x-ms-sevsnpvm-hostdata is {len(hostdata_bytes)} bytes, not "
            f"{MAA_HOSTDATA_BYTES}: SEV-SNP HOST_DATA is a fixed 32-byte field, so a "
            "short value is not a CCE policy hash and measures no workload"
        )
    return hostdata


def check_maa_hostdata_pin(hostdata: str, expect_hostdata: str | None) -> None:
    """Require HOST_DATA to equal a pin we were told to expect. No output.

    Unlike --expected-pcr0 and --expect-digest this is MANDATORY, because on
    Azure it is doing a second job. MAA's attest endpoints accept a hardware
    report from any caller that has one, so pinning the issuer proves only that
    OUR attestation instance signed the claims — not that they describe OUR
    workload. Someone else's confidential container, attested against the same
    instance, produces a genuine token with genuine claims about THEIR image.
    HOST_DATA is the only field that tells the two apart.
    """
    if not expect_hostdata:
        sys.exit(
            "[FAIL] --expected-hostdata is required to verify an Azure attestation.\n"
            "  HOST_DATA is the only claim that identifies WHICH workload ran: it carries the\n"
            "  confidential-container CCE policy hash, the Azure analogue of Nitro PCR0 and\n"
            "  Confidential Space image_digest. Unpinned, this verifier would confirm only that\n"
            "  *some* non-zero measurement exists — and because MAA attests any caller's hardware\n"
            "  report, an unrelated confidential container attesting against the same instance\n"
            "  yields a fully genuine token that would pass. Publish the policy hash on the trust\n"
            "  page and pass it here (comma-separated to span a rolling deploy)."
        )
    # Comma-separated SET, exactly like --expect-digest: during a rolling
    # deploy the fleet legitimately spans the published policy hash and the
    # incoming one, and every instance must still verify.
    allowed = {value.strip().lower().removeprefix("0x") for value in expect_hostdata.split(",") if value.strip()}
    if hostdata not in allowed:
        sys.exit(
            "[FAIL] MAA hostdata mismatch:\n"
            f"  attestation:     {hostdata}\n"
            f"  expected one of: {sorted(allowed)}"
        )


def maa_is_debuggable(payload: dict[str, Any]) -> bool:
    """Parse x-ms-sevsnpvm-is-debuggable, failing closed. No output."""
    value = payload.get("x-ms-sevsnpvm-is-debuggable")
    if value is None:
        sys.exit(
            "[FAIL] MAA token has no x-ms-sevsnpvm-is-debuggable claim; fail closed, "
            "a guest that might be debuggable is not confidential"
        )
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.strip().lower() in {"true", "false"}:
        return value.strip().lower() == "true"
    sys.exit(f"[FAIL] MAA x-ms-sevsnpvm-is-debuggable is not a boolean: {value!r}")


def require_maa_attestation_type(payload: dict[str, Any]) -> None:
    """Require an AMD SEV-SNP guest. No output."""
    attestation_type = payload.get("x-ms-attestation-type")
    if not isinstance(attestation_type, str) or attestation_type.strip().lower() != MAA_ATTESTATION_TYPE:
        sys.exit(
            f"[FAIL] MAA attestation type is not {MAA_ATTESTATION_TYPE!r} "
            f"(this is not an AMD SEV-SNP guest): {attestation_type!r}"
        )


def verify_maa_token_validity_window(payload: dict[str, Any], *, now: float | None = None) -> None:
    """Require a token that is currently valid.

    Live sampling is protected by the caller nonce, but offline-blob mode has
    no nonce and no exporter, so without this an MAA token captured from a
    support bundle months ago re-verifies today for as long as the TLS cert
    lives. MAA always stamps exp; a token without one is not something we can
    reason about, so it fails closed.
    """
    moment = time.time() if now is None else now

    def numeric(name: str) -> float | None:
        value = payload.get(name)
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return None
        return float(value)

    exp = numeric("exp")
    if exp is None:
        sys.exit(
            "[FAIL] MAA token has no numeric exp claim; a token with no expiry cannot be "
            "shown to be fresh, and in offline-blob mode there is no nonce to bound it"
        )
    if moment > exp + MAA_CLOCK_SKEW_SECONDS:
        sys.exit(
            f"[FAIL] MAA token expired {int(moment - exp)}s ago (exp={int(exp)}); a captured "
            "token is a replay, not evidence about the enclave serving this session"
        )
    nbf = numeric("nbf")
    if nbf is not None and moment < nbf - MAA_CLOCK_SKEW_SECONDS:
        sys.exit(f"[FAIL] MAA token is not yet valid (nbf={int(nbf)}, now={int(moment)})")
    print(f"[ok] MAA token is within its validity window ({int(exp - moment)}s to exp)")


def verify_no_maa_debug(payload: dict[str, Any]) -> None:
    if maa_is_debuggable(payload):
        sys.exit(
            "[FAIL] Azure SEV-SNP guest is debuggable (x-ms-sevsnpvm-is-debuggable=true): "
            "the host can inspect guest memory, so nothing in this enclave is confidential"
        )
    print("[ok] MAA guest is not debuggable")


def verify_maa_jwt(
    blob: bytes,
    cert_der: bytes,
    *,
    exporter: bytes | None,
    expect_hostdata: str | None,
    expect_issuer: str | None,
    nonce_hex: str | None,
    allow_debug: bool,
    device_blob_sha: str | None = None,
    require_exporter: bool = True,
) -> None:
    issuer = verify_maa_jwt_signature(blob, expect_issuer=expect_issuer)
    payload = parse_jwt_payload(blob)
    print(f"[ok] MAA issuer is {issuer} (in the trusted set)")

    verify_maa_token_validity_window(payload)

    require_maa_attestation_type(payload)
    print(f"[ok] MAA attestation type is {MAA_ATTESTATION_TYPE}")

    verify_maa_hostdata(payload, expect_hostdata)

    fields, runtime_bytes = maa_runtime_data(payload)

    # The link between the JWT's claims and the hardware report. REPORT_DATA is
    # the only caller-controlled field inside the signed SNP report, so if the
    # echoed runtime data does not hash to it, everything above is a signed
    # assertion about values that were never bound to the hardware.
    report_data = payload.get("x-ms-sevsnpvm-reportdata")
    if not isinstance(report_data, str) or not report_data.strip():
        sys.exit("[FAIL] MAA token has no x-ms-sevsnpvm-reportdata claim")
    claimed_report_data = report_data.strip().lower().removeprefix("0x")
    # MEASURED on real hardware (Azure UAE North, skr sidecar 2.7, 2026-08-03):
    # REPORT_DATA is sha256(runtime_data) followed by 32 ZERO bytes, and the
    # sidecar computes it itself — a report_data supplied in the request is
    # ignored. SEV-SNP's field is 64 bytes wide and sha256 only fills half of
    # it, so the tail padding is part of the format, not slack.
    #
    # The first draft checked sha512 over the whole 64 bytes. It was a
    # defensible reading of the docs and it would have rejected every genuine
    # token, which is the failure mode that looks like "Azure attestation is
    # broken" rather than "our verifier is wrong".
    if len(claimed_report_data) != 128:
        sys.exit(
            "[FAIL] MAA x-ms-sevsnpvm-reportdata is not 64 bytes: "
            f"{len(claimed_report_data)} hex chars"
        )
    claimed_digest, claimed_padding = claimed_report_data[:64], claimed_report_data[64:]
    computed_report_data = hashlib.sha256(runtime_bytes).hexdigest()
    if claimed_digest != computed_report_data:
        sys.exit(
            "[FAIL] MAA REPORT_DATA does not commit to the echoed runtime data:\n"
            f"  sha256(runtime_data):     {computed_report_data}\n"
            f"  x-ms-sevsnpvm-reportdata: {claimed_digest}\n"
            "  the hardware report is not bound to these runtime claims"
        )
    if set(claimed_padding) != {"0"}:
        # Non-zero tail means the layout is not the one measured here. Refuse
        # rather than assume the first 32 bytes still mean what we think.
        sys.exit(
            "[FAIL] MAA REPORT_DATA tail is not zero padding: "
            f"{claimed_padding}\n  expected sha256(runtime_data) || 32 zero bytes"
        )
    print(f"[ok] SEV-SNP REPORT_DATA is sha256(runtime_data)||0*32 ({computed_report_data[:16]}...)")

    leaf_fp = str(fields.get("leaf_fp") or "").strip().lower()
    cert_fp = hashlib.sha256(cert_der).hexdigest().lower()
    if leaf_fp != cert_fp:
        sys.exit(
            "[FAIL] live TLS cert fingerprint is not bound in MAA attestation:\n"
            f"  cert sha256:      {cert_fp}\n"
            f"  runtime leaf_fp:  {leaf_fp or '(absent)'}"
        )
    print(f"[ok] live TLS cert fingerprint bound in MAA runtime data ({cert_fp[:16]}...)")

    # device_hash is one of the two non-omitempty producer fields and is inside
    # the REPORT_DATA pre-image, so it is free to check. Dropping the operator's
    # --device-blob-sha silently would tell them they pinned the device-key blob
    # when nothing compared it.
    if device_blob_sha:
        want_device = device_blob_sha.strip().lower()
        got_device = str(fields.get("device_hash") or "").strip().lower()
        if got_device != want_device:
            sys.exit(
                "[FAIL] device-blob mismatch in MAA runtime data:\n"
                f"  attestation: {got_device or '(absent)'}\n"
                f"  expected:    {want_device}"
            )
        print(f"[ok] device-blob hash bound in MAA runtime data ({got_device[:16]}...)")

    binding_values = maa_binding_values(fields)
    channel_binding = str(fields.get("channel_binding") or "").strip().lower()
    runtime_nonce = str(fields.get("nonce") or "").strip().lower()

    if exporter is not None:
        exporter_hex = exporter.hex().lower()
        try:
            require_fresh_exporter_binding(
                binding_values,
                exporter_hex=exporter_hex,
                nonce_hex=nonce_hex,
                require_exporter=require_exporter,
                cloud="MAA",
            )
        except ValueError as exc:
            sys.exit(f"[FAIL] {exc}")
        # A GCP token flattens everything into one nonce array, so membership is
        # all that can be checked there. MAA runtime data has NAMED fields, so
        # additionally pin each value to the field meant to carry it: a token
        # that merely mentions the exporter somewhere has not bound it as the
        # channel binding.
        if channel_binding:
            if channel_binding != exporter_hex:
                sys.exit(
                    "[FAIL] MAA channel_binding does not match the live TLS exporter:\n"
                    f"  channel_binding: {channel_binding}\n"
                    f"  exporter:        {exporter_hex}"
                )
            print(f"[ok] TLS exporter channel binding bound in MAA runtime data ({exporter_hex[:16]}...)")
        elif require_exporter:
            sys.exit("[FAIL] MAA runtime data has no channel_binding; this session is not bound")
        else:
            print("[ok] TLS exporter channel binding optional in liveness mode")

    if nonce_hex is not None:
        if runtime_nonce != nonce_hex.lower():
            sys.exit(
                "[FAIL] caller nonce not present in MAA attestation:\n"
                f"  expected: {nonce_hex.lower()}\n"
                f"  runtime:  {runtime_nonce or '(absent)'}"
            )
        print(f"[ok] caller nonce bound ({nonce_hex[:16]}...)")

    if not allow_debug:
        verify_no_maa_debug(payload)
    else:
        print("[warn] --allow-debug: skipping the MAA is-debuggable gate")


def verify_aws_cbor(
    blob: bytes,
    cert_der: bytes,
    *,
    exporter: bytes | None,
    expected_pcr0: str | None,
    device_blob_sha: str | None,
) -> None:
    payload, _ = parse_cose_payload(blob)
    verify_cose_signature(blob)

    pcr0 = payload["pcrs"][0].hex()
    check_pcr0_pin(pcr0, expected_pcr0)

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
    if exporter is not None:
        if len(user_data) < 96:
            sys.exit("[FAIL] AWS attestation has no TLS exporter channel binding in user_data")
        bound_exporter = user_data[64:96]
        if bound_exporter != exporter:
            sys.exit(
                "[FAIL] TLS exporter channel binding is not bound in AWS attestation:\n"
                f"  user_data: {bound_exporter.hex()}\n"
                f"  exporter:  {exporter.hex()}"
            )
        print(f"[ok] TLS exporter channel binding bound in AWS user_data ({exporter.hex()[:16]}...)")


def read_blob(path: str | None) -> bytes | None:
    if not path:
        return None
    if path == "-":
        return sys.stdin.buffer.read()
    return Path(path).read_bytes()


def _probe_binding(
    host: str,
    port: int,
    connect_ip: str | None,
    require_exporter: bool = True,
    *,
    expect_issuer: str | None = None,
    expect_hostdata: str | None = None,
) -> dict[str, Any]:
    """One TLS connection: capture the served leaf cert AND fetch /attestation on
    the SAME socket, then report whether that cert is bound in the token's GCP
    nonce. A 500/handshake error is recorded as `error` (the Confidential Space
    launcher's token socket can saturate under load) — NOT a binding mismatch."""
    nonce_hex = secrets.token_hex(16)
    try:
        cert_der, exporter, blob, _followup_nonce_hex, _followup_blob = fetch_attestation_same_tls_socket(
            host,
            nonce_hex,
            port,
            connect_ip=connect_ip,
            require_exporter=require_exporter,
            require_pin=require_exporter,
        )
    except (SystemExit, Exception) as exc:  # fetch_* sys.exit()s on non-200
        return {"host": host, "error": str(exc) or repr(exc)}
    served_fp = hashlib.sha256(cert_der).hexdigest().lower()
    if not looks_like_jwt(blob):
        return {"host": host, "error": "non-JWT attestation (binding-stress is JWT-only)"}
    # Dispatch site 2 of 4. Routing on shape here would score every MAA token as
    # a binding MISMATCH (GCP nonce claims are simply absent from an MAA token),
    # i.e. report a relay/substitution race that is not there.
    cloud = jwt_attestation_cloud(blob)
    payload = parse_jwt_payload(blob)
    if cloud == "maa":
        fields, _runtime_bytes = maa_runtime_data(payload)
        nonces = maa_binding_values(fields)
        dbg = [str(payload.get("x-ms-sevsnpvm-is-debuggable"))]
        # Every fail-closed MAA gate runs HERE too. Reading claims straight out
        # of an unverified payload and then printing a measurement verdict is
        # how a plain confidential VM — no HOST_DATA at all — used to score a
        # clean run in this mode: an absent claim produced no observation, and
        # "nothing observed" was silently treated as "nothing to object to".
        # Signature included, since the JWKS is cached after the first probe.
        try:
            verify_maa_jwt_signature(blob, expect_issuer=expect_issuer, quiet=True)
            require_maa_attestation_type(payload)
            if maa_is_debuggable(payload):
                sys.exit("[FAIL] Azure SEV-SNP guest is debuggable")
            digest = maa_hostdata_value(payload)
            check_maa_hostdata_pin(digest, expect_hostdata)
        except SystemExit as exc:
            # Report the binding columns truthfully even though a claim gate is
            # what failed: "exporter_bound=False" next to a signature error
            # would send the reader hunting for a relay that is not there.
            return {
                "host": host, "cloud": cloud, "served_fp": served_fp,
                "exporter": exporter.hex().lower(), "nonce": nonce_hex.lower(),
                "cert_bound": served_fp in nonces,
                "exporter_bound": exporter.hex().lower() in nonces,
                "nonce_bound": nonce_hex.lower() in nonces, "bound": False,
                "binding_error": str(exc), "dbgstat": dbg, "digest": None,
            }
    else:
        nonces = gcp_nonce_values(payload)
        dbg = [str(v) for k, v in walk_values(payload) if k.lower() == "dbgstat"]
        digest = first_claim(payload, "image_digest", "submods.container.image_digest")
    exporter_hex = exporter.hex().lower()
    cert_bound = served_fp in nonces
    exporter_bound = exporter_hex in nonces
    nonce_bound = nonce_hex.lower() in nonces
    binding_error = ""
    try:
        require_fresh_exporter_binding(
            nonces,
            exporter_hex=exporter_hex,
            nonce_hex=nonce_hex,
            require_exporter=require_exporter,
            cloud=cloud.upper(),
        )
        fresh_exporter_bound = True
    except ValueError as exc:
        fresh_exporter_bound = False
        binding_error = str(exc)
    return {
        "host": host,
        "cloud": cloud,
        "served_fp": served_fp,
        "exporter": exporter_hex,
        "nonce": nonce_hex.lower(),
        "cert_bound": cert_bound,
        "exporter_bound": exporter_bound,
        "nonce_bound": nonce_bound,
        "bound": cert_bound and fresh_exporter_bound,
        "binding_error": binding_error,
        "dbgstat": dbg,
        "digest": digest,
    }


def binding_stress(
    connect_ip: str | None, hosts: list[str], concurrency: int, rounds: int,
    port: int, expect_digest: str | None, require_exporter: bool = True,
    expect_hostdata: str | None = None, expect_issuer: str | None = None,
) -> int:
    """Adversarial concurrent cross-SNI binding check against a single instance.

    Fires `concurrency` simultaneous connections per round, `rounds` rounds, with
    the SNI interleaved across `hosts`. Asserts every served cert is bound in its
    own attestation token, and the verifier's fresh nonce is also echoed. A
    process-global last-cert race (one handshake
    overwriting another's cert) surfaces here as mismatches; the sequential
    --samples check cannot see it. Returns 0 iff no mismatches."""
    target = connect_ip or hosts[0]
    print(f"[binding-stress] {concurrency}x{rounds} concurrent probes -> {target}; "
          f"interleaved SNIs={hosts}")
    results: list[dict[str, Any]] = []
    for _ in range(rounds):
        with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as ex:
            futs = [ex.submit(_probe_binding, hosts[i % len(hosts)], port, connect_ip, require_exporter,
                              expect_issuer=expect_issuer, expect_hostdata=expect_hostdata)
                    for i in range(concurrency)]
            for fut in concurrent.futures.as_completed(futs):
                results.append(fut.result())

    by_host: dict[str, dict[str, int]] = {}
    fps: dict[str, set[str]] = {}
    mismatches: list[dict[str, Any]] = []
    dbg: set[str] = set()
    # Keyed by cloud: a GCP image_digest and an Azure HOST_DATA policy hash are
    # both "the workload measurement", but they are checked against different
    # expectations, so they must not be pooled.
    measurements: dict[str, set[str]] = {}
    # How many probes of each cloud actually completed, so "no measurement
    # observed" can be told apart from "no probe of that cloud ran".
    probes_by_cloud: dict[str, int] = {}
    errors = 0
    for r in results:
        if r.get("error"):
            errors += 1
            continue
        probes_by_cloud[str(r.get("cloud", "gcp"))] = probes_by_cloud.get(str(r.get("cloud", "gcp")), 0) + 1
        h = r["host"]
        slot = by_host.setdefault(h, {"n": 0, "bound": 0})
        slot["n"] += 1
        if r["bound"]:
            slot["bound"] += 1
        else:
            mismatches.append(r)
        fps.setdefault(h, set()).add(r["served_fp"][:16])
        dbg.update(r.get("dbgstat", []))
        if r.get("digest"):
            measurements.setdefault(str(r.get("cloud", "gcp")), set()).add(str(r["digest"]))

    bound_ok = sum(s["bound"] for s in by_host.values())
    for h in sorted(by_host):
        s = by_host[h]
        print(f"[binding-stress]   SNI {h:28s} {s['bound']}/{s['n']} cert+exporter+nonce bound  "
              f"served-fp={sorted(fps.get(h, []))}")
    print(f"[binding-stress]   distinct served certs: "
          f"{sorted({f for s in fps.values() for f in s})}")
    print(f"[binding-stress]   dbgstat seen: {sorted(dbg) or '(none)'}; "
          f"errors/500s: {errors}; successful bound checks: {bound_ok}")

    # Report per-probe failures FIRST. A probe that fails an MAA gate (bad
    # signature, debuggable guest, absent HOST_DATA) reports no measurement AND
    # counts as a mismatch; leading with the aggregate would print "carried no
    # hostdata" over the specific reason recorded in binding_error.
    if mismatches:
        print(f"[FAIL] {len(mismatches)} channel-binding/attestation MISMATCH(es) under concurrency — "
              "a served cert/exporter was NOT bound in its own token (relay or substitution race "
              "present), or a token failed a fail-closed attestation gate")
        for m in mismatches[:8]:
            print(
                f"  host={m['host']} served_fp={m['served_fp'][:16]} "
                f"cert_bound={m['cert_bound']} exporter_bound={m['exporter_bound']} "
                f"nonce_bound={m['nonce_bound']} error={m.get('binding_error', '')}"
            )
        return 1

    for cloud, expected, label in (
        ("gcp", expect_digest, "image_digest"),
        ("maa", expect_hostdata, "hostdata"),
    ):
        observed = measurements.get(cloud, set())
        probes = probes_by_cloud.get(cloud, 0)
        if not expected:
            continue
        if probes and not observed:
            # A pin was supplied and every probe of that cloud came back with no
            # measurement at all. Skipping here is what let the deployment shape
            # this verifier exists to reject pass its own deploy gate.
            print(f"[FAIL] {probes} {cloud} probe(s) carried NO {label} to check "
                  f"against the expected set {sorted({d.strip().lower() for d in expected.split(',') if d.strip()})}")
            return 1
        if not observed:
            continue
        allowed = {d.strip().lower() for d in expected.split(",") if d.strip()}
        bad = {d for d in observed if d.lower() not in allowed}
        if bad:
            print(f"[FAIL] {label}(s) not in expected set: {sorted(bad)} "
                  f"(expected one of {sorted(allowed)})")
            return 1
        print(f"[ok] all observed {label}s in expected set ({sorted(observed)})")

    if bound_ok == 0:
        print("[WARN] every probe errored (token socket saturated?) — no binding "
              "confirmed; retry with a lower --binding-stress-concurrency")
        return 2
    if len(by_host) < 2:
        print("[WARN] only one SNI produced successful probes; cross-SNI substitution "
              "not fully exercised this run (retry or lower concurrency)")
    print(f"[ok] no binding mismatches across {bound_ok} concurrent mixed-SNI probes")
    return 0


def reject_inapplicable_measurement_pins(cloud: str, args: argparse.Namespace) -> None:
    """Refuse to run when the operator pinned a measurement this cloud cannot carry.

    Each cloud names its workload measurement differently, and the flags are not
    interchangeable. Silently dropping the one that does not apply is the worst
    outcome: the operator asked for a pin, saw "verification passed", and got no
    pin at all. Say so instead — a reconciler pointed at the wrong cloud should
    stop, not publish an IP on an unpinned token.
    """
    flags = {
        "aws": ("--expected-pcr0", args.expected_pcr0),
        "gcp": ("--expect-digest", args.expect_digest),
        "maa": ("--expected-hostdata", args.expected_hostdata),
    }
    for other, (flag, value) in flags.items():
        if other != cloud and value:
            mine = flags[cloud][0]
            sys.exit(
                f"[FAIL] {flag} was supplied, but this attestation came from {cloud.upper()}.\n"
                f"  {flag} pins the {other.upper()} workload measurement and means nothing here; "
                f"ignoring it would\n  report a pinned verification that never happened. Use {mine} "
                f"for {cloud.upper()}."
            )


def build_parser() -> argparse.ArgumentParser:
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
    parser.add_argument(
        "--expected-hostdata",
        default=None,
        help="hex Azure SEV-SNP HOST_DATA from the trust page — the confidential-container "
        "CCE policy hash, i.e. the Azure analogue of PCR0/image_digest; comma-separated to "
        "accept any of a set during a rolling deploy. HOST_DATA must be present and non-zero "
        "even without this flag: a plain confidential VM populates no workload measurement "
        "and is rejected by construction. REQUIRED on the Azure path — see --expected-maa-issuer.",
    )
    parser.add_argument(
        "--expected-maa-issuer",
        default=None,
        help="REQUIRED to verify Azure: the exact Microsoft Azure Attestation instance(s) this "
        f"fleet attests against, e.g. https://<instance>.<region>{MAA_ISSUER_HOST_SUFFIX} (the enclave's "
        "QUILL_AZURE_MAA_ENDPOINT); comma-separated for a multi-region fleet. May also be set via "
        f"{MAA_ISSUER_ENV}. There is no default: *{MAA_ISSUER_HOST_SUFFIX} is a namespace open to every "
        "Azure tenant, each serving its own signing keys, so without this the verifier would fetch "
        "its trust anchor from whatever host the unverified token names.",
    )
    parser.add_argument("--expect-digest", default=None, help="GCP Confidential Space image_digest(s); comma-separated to accept any of a set (e.g. published trust digest + incoming release during a rollout)")
    parser.add_argument("--device-blob-sha", default=None, help="hex SHA-256 of canonical device-key blob")
    parser.add_argument(
        "--allow-debug",
        action="store_true",
        help="do not fail on a debug-enabled guest. Covers BOTH the GCP dbgstat gate and the Azure "
        "x-ms-sevsnpvm-is-debuggable gate, so on Azure it accepts a guest whose memory the host can "
        "read — i.e. an enclave that is not confidential. Diagnostics only.",
    )
    parser.add_argument(
        "--no-require-exporter-binding",
        dest="require_exporter_binding",
        action="store_false",
        default=True,
        help="liveness/identity mode for DNS reconciliation: require digest, cert, fresh nonce, and dbgstat checks, but make the TLS exporter optional and skip the same-socket pin follow-up",
    )
    parser.add_argument(
        "--attested-cert-only",
        dest="ca_trust",
        action="store_false",
        default=True,
        help="the endpoint serves a SELF-SIGNED cert minted inside the TEE "
             "(standalone regional enclaves, e.g. aws.trustedrouter.com): skip CA "
             "chain/hostname validation, but still require the attestation to bind "
             "the presented cert. Trust comes from the attestation, not a CA.",
    )
    parser.add_argument("--binding-stress", action="store_true",
                        help="concurrent cross-SNI binding stress test against ONE instance "
                             "(use with --connect-ip); asserts each served cert is bound in its "
                             "own token. Catches a global last-cert race the sequential --samples "
                             "check cannot.")
    parser.add_argument("--binding-stress-hosts",
                        default="api.trustedrouter.com,api.quillrouter.com",
                        help="comma-separated SNIs to interleave in --binding-stress")
    parser.add_argument("--binding-stress-concurrency", type=int, default=12)
    parser.add_argument("--binding-stress-rounds", type=int, default=4)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    require_exporter = args.require_exporter_binding

    if args.binding_stress:
        hosts = [h.strip() for h in args.binding_stress_hosts.split(",") if h.strip()]
        if not hosts:
            sys.exit("[FAIL] --binding-stress-hosts produced no hosts")
        return binding_stress(args.connect_ip, hosts, args.binding_stress_concurrency,
                              args.binding_stress_rounds, args.port, args.expect_digest,
                              require_exporter=require_exporter,
                              expect_hostdata=args.expected_hostdata,
                              expect_issuer=args.expected_maa_issuer)

    blob = read_blob(args.blob)
    if blob is not None and args.samples > 1:
        sys.exit("[FAIL] --samples > 1 requires live mode; omit the blob path")

    if blob is not None:
        cert_der = fetch_live_cert_der(
            args.api_host, args.port, connect_ip=args.connect_ip, ca_trust=args.ca_trust
        )
        if looks_like_jwt(blob):
            # Dispatch site 3 of 4 (offline blob).
            if jwt_attestation_cloud(blob) == "maa":
                reject_inapplicable_measurement_pins("maa", args)
                verify_maa_jwt(
                    blob,
                    cert_der,
                    exporter=None,
                    expect_hostdata=args.expected_hostdata,
                    expect_issuer=args.expected_maa_issuer,
                    nonce_hex=None,
                    allow_debug=args.allow_debug,
                    device_blob_sha=args.device_blob_sha,
                    require_exporter=require_exporter,
                )
            else:
                reject_inapplicable_measurement_pins("gcp", args)
                verify_gcp_jwt(
                    blob,
                    cert_der,
                    exporter=None,
                    expect_digest=args.expect_digest,
                    nonce_hex=None,
                    allow_debug=args.allow_debug,
                    device_blob_sha=args.device_blob_sha,
                    require_exporter=require_exporter,
                )
        else:
            reject_inapplicable_measurement_pins("aws", args)
            verify_aws_cbor(
                blob,
                cert_der,
                exporter=None,
                expected_pcr0=args.expected_pcr0,
                device_blob_sha=args.device_blob_sha,
            )
        print("\nAttestation verification passed.")
        return 0

    if args.samples < 1:
        sys.exit("[FAIL] --samples must be >= 1")
    for sample in range(1, args.samples + 1):
        nonce_hex = secrets.token_hex(32)
        cert_der, exporter, live_blob, followup_nonce_hex, followup_blob = fetch_attestation_same_tls_socket(
            args.api_host,
            nonce_hex,
            args.port,
            connect_ip=args.connect_ip,
            require_exporter=require_exporter,
            require_pin=require_exporter,
            ca_trust=args.ca_trust,
        )
        print(f"\nSample {sample}/{args.samples}:")
        if looks_like_jwt(live_blob):
            # Dispatch site 4 of 4 (live sampling). The follow-up token comes
            # off the same socket and the same enclave, so it routes the same
            # way; routing it independently would be a second shape guess.
            if jwt_attestation_cloud(live_blob) == "maa":
                reject_inapplicable_measurement_pins("maa", args)
                verify_maa_jwt(
                    live_blob,
                    cert_der,
                    exporter=exporter,
                    expect_hostdata=args.expected_hostdata,
                    expect_issuer=args.expected_maa_issuer,
                    nonce_hex=nonce_hex,
                    allow_debug=args.allow_debug,
                    device_blob_sha=args.device_blob_sha,
                    require_exporter=require_exporter,
                )
                if require_exporter:
                    verify_maa_jwt(
                        followup_blob,
                        cert_der,
                        exporter=exporter,
                        expect_hostdata=args.expected_hostdata,
                        expect_issuer=args.expected_maa_issuer,
                        nonce_hex=followup_nonce_hex,
                        allow_debug=args.allow_debug,
                        device_blob_sha=args.device_blob_sha,
                        require_exporter=require_exporter,
                    )
            else:
                reject_inapplicable_measurement_pins("gcp", args)
                verify_gcp_jwt(
                    live_blob,
                    cert_der,
                    exporter=exporter,
                    expect_digest=args.expect_digest,
                    nonce_hex=nonce_hex,
                    allow_debug=args.allow_debug,
                    device_blob_sha=args.device_blob_sha,
                    require_exporter=require_exporter,
                )
                if require_exporter:
                    verify_gcp_jwt(
                        followup_blob,
                        cert_der,
                        exporter=exporter,
                        expect_digest=args.expect_digest,
                        nonce_hex=followup_nonce_hex,
                        allow_debug=args.allow_debug,
                        device_blob_sha=args.device_blob_sha,
                        require_exporter=require_exporter,
                    )
        else:
            reject_inapplicable_measurement_pins("aws", args)
            verify_aws_cbor(
                live_blob,
                cert_der,
                exporter=exporter if require_exporter else None,
                expected_pcr0=args.expected_pcr0,
                device_blob_sha=args.device_blob_sha,
            )
            if require_exporter:
                verify_aws_cbor(
                    followup_blob,
                    cert_der,
                    exporter=exporter,
                    expected_pcr0=args.expected_pcr0,
                    device_blob_sha=args.device_blob_sha,
                )
        if require_exporter:
            print("[ok] follow-up /attestation stayed on the attested TLS socket")
    if require_exporter:
        print("\nAll sampled attestation bindings passed.")
    else:
        print("\nAll sampled liveness attestations passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
