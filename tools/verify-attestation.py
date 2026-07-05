#!/usr/bin/env python3
# /// script
# dependencies = ["cbor2>=5.5", "cryptography>=42", "pyOpenSSL>=22.0"]
# requires-python = ">=3.11"
# ///
"""Verify a TrustedRouter/Quill attestation document end-to-end.

Production GCP Confidential Space returns a Google-signed JWT from
`/attestation`; AWS Nitro returns a COSE/CBOR attestation document. This verifier
supports both formats and can sample the live endpoint over the same TLS socket
used to fetch the evidence, which catches cross-SNI certificate substitution
bugs and verifies the RFC 9266 tls-exporter session binding.

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

Examples:
    # Live GCP production check, including same-connection cert binding.
    ./tools/verify-attestation.py \\
        --api-host api.trustedrouter.com \\
        --expect-digest "$(curl -fsS https://trust.trustedrouter.com/image-digest-gcp.txt)" \\
        --samples 8

    # Concurrent cross-SNI binding stress test against ONE instance. The
    # --samples check is sequential same-socket, so it cannot expose a global
    # last-cert race (one handshake overwriting another's cert). This hammers a
    # single enclave with interleaved api.trustedrouter.com / api.quillrouter.com
    # connections and asserts each served cert is bound in its OWN token — the
    # only way to catch that substitution class.
    ./tools/verify-attestation.py --binding-stress \\
        --connect-ip 35.193.251.216 \\
        --expect-digest "$(curl -fsS https://trust.trustedrouter.com/image-digest-gcp.txt)"

    # Offline AWS Nitro CBOR check.
    ./tools/verify-attestation.py attestation.cbor \\
        --expected-pcr0 "$(curl -fsS https://trust.trustedrouter.com/pcr0.txt)" \\
        --api-host api.trustedrouter.com
"""
from __future__ import annotations

import argparse
import base64
import concurrent.futures
import hashlib
import ipaddress
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
from OpenSSL import SSL, crypto
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


AWS_NITRO_ROOT_PEM = (Path(__file__).parent / "aws-nitro-root.pem").read_bytes()
GCP_ISSUER = "https://confidentialcomputing.googleapis.com"
GCP_AUDIENCE = "quill-cloud"
EXPORTER_LABEL = b"EXPORTER-Channel-Binding"
EXPORTER_LENGTH = 32
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


def require_gcp_fresh_exporter_binding(nonces: list[str], *, exporter_hex: str, nonce_hex: str | None) -> None:
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
        raise ValueError(f"fresh caller nonce not present in GCP attestation: {nonce_hex}")
    if exporter_hex not in nonce_set:
        raise ValueError(
            "TLS exporter channel binding is not bound in GCP attestation "
            "(pre-Tier-B enclave or relay could not bind this session):\n"
            f"  exporter: {exporter_hex}\n"
            f"  nonces:   {sorted(nonce_set)}"
        )


def _new_pyopenssl_context() -> SSL.Context:
    ctx = SSL.Context(SSL.TLS_CLIENT_METHOD)
    if hasattr(ctx, "set_min_proto_version") and hasattr(SSL, "TLS1_3_VERSION"):
        ctx.set_min_proto_version(SSL.TLS1_3_VERSION)
    else:
        ctx.set_options(
            SSL.OP_NO_TLSv1
            | SSL.OP_NO_TLSv1_1
            | SSL.OP_NO_TLSv1_2
        )
    ctx.set_default_verify_paths()
    ctx.set_verify(SSL.VERIFY_PEER, _verify_callback)
    return ctx


def _attestation_request(host: str, nonce_hex: str) -> bytes:
    return (
        f"GET /attestation?nonce={nonce_hex} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Accept: application/jwt, application/cbor, */*\r\n"
        "Connection: keep-alive\r\n"
        "\r\n"
    ).encode("ascii")


def _recv_or_fail(conn: SSL.Connection, context: str) -> bytes:
    try:
        chunk = conn.recv(65536)
    except SSL.ZeroReturnError as exc:
        raise EOFError(context) from exc
    if not chunk:
        raise EOFError(context)
    return chunk


def _read_http_response(conn: SSL.Connection, context: str) -> tuple[str, dict[str, str], bytes]:
    response = bytearray()
    while b"\r\n\r\n" not in response:
        response.extend(_recv_or_fail(conn, context))
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
        body.extend(_recv_or_fail(conn, context))
    return status_line, headers, bytes(body[:content_length])


def _require_attestation_body_binds_exporter(blob: bytes, exporter: bytes, nonce_hex: str, label: str) -> None:
    exporter_hex = exporter.hex().lower()
    nonce_hex = nonce_hex.lower()
    try:
        if looks_like_jwt(blob):
            nonces = gcp_nonce_values(parse_jwt_payload(blob))
            require_gcp_fresh_exporter_binding(nonces, exporter_hex=exporter_hex, nonce_hex=nonce_hex)
            return
        payload, _ = parse_cose_payload(blob)
        user_data = payload.get("user_data") or b""
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


def fetch_attestation_same_tls_socket(
    host: str, nonce_hex: str, port: int = 443, connect_ip: str | None = None
) -> tuple[bytes, bytes, bytes, str, bytes]:
    # connect_ip lets a caller (e.g. the DNS reconciler) attest a SPECIFIC
    # instance by IP while still presenting/validating the canonical hostname
    # (SNI + cert SAN + Host header stay `host`). Without it, host is dialed.
    ctx = _new_pyopenssl_context()
    raw = socket.create_connection((connect_ip or host, port), timeout=10)
    conn = SSL.Connection(ctx, raw)
    try:
        conn.set_tlsext_host_name(host.encode("idna"))
        conn.set_connect_state()
        conn.do_handshake()
        peer = conn.get_peer_certificate()
        if peer is None:
            sys.exit("[FAIL] TLS handshake returned no peer certificate")
        cert_der = crypto.dump_certificate(crypto.FILETYPE_ASN1, peer)
        assert_cert_matches_hostname(cert_der, host)
        exporter = conn.export_keying_material(EXPORTER_LABEL, EXPORTER_LENGTH)
        conn.sendall(_attestation_request(host, nonce_hex))
        try:
            status_line, _headers, body = _read_http_response(conn, "attestation")
        except Exception as exc:
            sys.exit(f"[FAIL] attestation socket closed before the first response was fully framed: {exc}")
        if " 200 " not in status_line:
            sys.exit(f"[FAIL] attestation HTTP status was not 200: {status_line}")
        if not body:
            sys.exit("[FAIL] empty attestation body")
        _require_attestation_body_binds_exporter(body, exporter, nonce_hex, "first")

        # G6 pinning is meaningful only if the prompt can follow the evidence on
        # this exact TLS session. A second fresh attestation is an unauthenticated
        # stand-in for that prompt and proves the server did not close after the
        # first response.
        followup_nonce_hex = secrets.token_hex(32)
        try:
            conn.sendall(_attestation_request(host, followup_nonce_hex))
            followup_status, _followup_headers, followup_body = _read_http_response(
                conn, "follow-up attestation"
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
            followup_body, exporter, followup_nonce_hex, "follow-up"
        )
    finally:
        try:
            conn.shutdown()
        except Exception:
            pass
        conn.close()
    return cert_der, exporter, body, followup_nonce_hex, followup_body


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
    exporter: bytes | None,
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

    if exporter is not None:
        exporter_hex = exporter.hex().lower()
        try:
            require_gcp_fresh_exporter_binding(nonces, exporter_hex=exporter_hex, nonce_hex=nonce_hex)
        except ValueError as exc:
            sys.exit(f"[FAIL] {exc}")
        print(f"[ok] TLS exporter channel binding bound in GCP nonce ({exporter_hex[:16]}...)")
        print(f"[ok] caller nonce bound ({nonce_hex[:16]}...)")
    elif nonce_hex:
        if nonce_hex.lower() not in nonces:
            sys.exit(f"[FAIL] caller nonce not present in GCP attestation: {nonce_hex}")
        print(f"[ok] caller nonce bound ({nonce_hex[:16]}...)")

    if not allow_debug:
        verify_no_gcp_debug(payload)


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


def _probe_binding(host: str, port: int, connect_ip: str | None) -> dict[str, Any]:
    """One TLS connection: capture the served leaf cert AND fetch /attestation on
    the SAME socket, then report whether that cert is bound in the token's GCP
    nonce. A 500/handshake error is recorded as `error` (the Confidential Space
    launcher's token socket can saturate under load) — NOT a binding mismatch."""
    nonce_hex = secrets.token_hex(16)
    try:
        cert_der, exporter, blob, _followup_nonce_hex, _followup_blob = fetch_attestation_same_tls_socket(
            host, nonce_hex, port, connect_ip=connect_ip
        )
    except (SystemExit, Exception) as exc:  # fetch_* sys.exit()s on non-200
        return {"host": host, "error": str(exc) or repr(exc)}
    served_fp = hashlib.sha256(cert_der).hexdigest().lower()
    if not looks_like_jwt(blob):
        return {"host": host, "error": "non-JWT attestation (binding-stress is GCP-only)"}
    payload = parse_jwt_payload(blob)
    nonces = gcp_nonce_values(payload)
    exporter_hex = exporter.hex().lower()
    cert_bound = served_fp in nonces
    exporter_bound = exporter_hex in nonces
    nonce_bound = nonce_hex.lower() in nonces
    binding_error = ""
    try:
        require_gcp_fresh_exporter_binding(nonces, exporter_hex=exporter_hex, nonce_hex=nonce_hex)
        fresh_exporter_bound = True
    except ValueError as exc:
        fresh_exporter_bound = False
        binding_error = str(exc)
    dbg = [str(v) for k, v in walk_values(payload) if k.lower() == "dbgstat"]
    digest = first_claim(payload, "image_digest", "submods.container.image_digest")
    return {
        "host": host,
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
    port: int, expect_digest: str | None,
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
            futs = [ex.submit(_probe_binding, hosts[i % len(hosts)], port, connect_ip)
                    for i in range(concurrency)]
            for fut in concurrent.futures.as_completed(futs):
                results.append(fut.result())

    by_host: dict[str, dict[str, int]] = {}
    fps: dict[str, set[str]] = {}
    mismatches: list[dict[str, Any]] = []
    dbg: set[str] = set()
    digests: set[str] = set()
    errors = 0
    for r in results:
        if r.get("error"):
            errors += 1
            continue
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
            digests.add(str(r["digest"]))

    bound_ok = sum(s["bound"] for s in by_host.values())
    for h in sorted(by_host):
        s = by_host[h]
        print(f"[binding-stress]   SNI {h:28s} {s['bound']}/{s['n']} cert+exporter+nonce bound  "
              f"served-fp={sorted(fps.get(h, []))}")
    print(f"[binding-stress]   distinct served certs: "
          f"{sorted({f for s in fps.values() for f in s})}")
    print(f"[binding-stress]   dbgstat seen: {sorted(dbg) or '(none)'}; "
          f"errors/500s: {errors}; successful bound checks: {bound_ok}")

    if expect_digest:
        allowed = {d.strip().lower() for d in expect_digest.split(",") if d.strip()}
        bad = {d for d in digests if d.lower() not in allowed}
        if bad:
            print(f"[FAIL] image_digest(s) not in expected set: {sorted(bad)} "
                  f"(expected one of {sorted(allowed)})")
            return 1
        if digests:
            print(f"[ok] all observed image_digests in expected set ({sorted(digests)})")

    if mismatches:
        print(f"[FAIL] {len(mismatches)} channel-binding MISMATCH(es) under concurrency — "
              "a served cert/exporter was NOT bound in its own token (relay or substitution race present)")
        for m in mismatches[:8]:
            print(
                f"  host={m['host']} served_fp={m['served_fp'][:16]} "
                f"cert_bound={m['cert_bound']} exporter_bound={m['exporter_bound']} "
                f"nonce_bound={m['nonce_bound']} error={m.get('binding_error', '')}"
            )
        return 1
    if bound_ok == 0:
        print("[WARN] every probe errored (token socket saturated?) — no binding "
              "confirmed; retry with a lower --binding-stress-concurrency")
        return 2
    if len(by_host) < 2:
        print("[WARN] only one SNI produced successful probes; cross-SNI substitution "
              "not fully exercised this run (retry or lower concurrency)")
    print(f"[ok] no binding mismatches across {bound_ok} concurrent mixed-SNI probes")
    return 0


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
    parser.add_argument("--expect-digest", default=None, help="GCP Confidential Space image_digest(s); comma-separated to accept any of a set (e.g. published trust digest + incoming release during a rollout)")
    parser.add_argument("--device-blob-sha", default=None, help="hex SHA-256 of canonical device-key blob")
    parser.add_argument("--allow-debug", action="store_true", help="do not fail when GCP dbgstat is enabled")
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
    args = parser.parse_args()

    if args.binding_stress:
        hosts = [h.strip() for h in args.binding_stress_hosts.split(",") if h.strip()]
        if not hosts:
            sys.exit("[FAIL] --binding-stress-hosts produced no hosts")
        return binding_stress(args.connect_ip, hosts, args.binding_stress_concurrency,
                              args.binding_stress_rounds, args.port, args.expect_digest)

    blob = read_blob(args.blob)
    if blob is not None and args.samples > 1:
        sys.exit("[FAIL] --samples > 1 requires live mode; omit the blob path")

    if blob is not None:
        cert_der = fetch_live_cert_der(args.api_host, args.port, connect_ip=args.connect_ip)
        if looks_like_jwt(blob):
            verify_gcp_jwt(
                blob,
                cert_der,
                exporter=None,
                expect_digest=args.expect_digest,
                nonce_hex=None,
                allow_debug=args.allow_debug,
            )
        else:
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
            args.api_host, nonce_hex, args.port, connect_ip=args.connect_ip
        )
        print(f"\nSample {sample}/{args.samples}:")
        if looks_like_jwt(live_blob):
            verify_gcp_jwt(
                live_blob,
                cert_der,
                exporter=exporter,
                expect_digest=args.expect_digest,
                nonce_hex=nonce_hex,
                allow_debug=args.allow_debug,
            )
            verify_gcp_jwt(
                followup_blob,
                cert_der,
                exporter=exporter,
                expect_digest=args.expect_digest,
                nonce_hex=followup_nonce_hex,
                allow_debug=args.allow_debug,
            )
        else:
            verify_aws_cbor(
                live_blob,
                cert_der,
                exporter=exporter,
                expected_pcr0=args.expected_pcr0,
                device_blob_sha=args.device_blob_sha,
            )
            verify_aws_cbor(
                followup_blob,
                cert_der,
                exporter=exporter,
                expected_pcr0=args.expected_pcr0,
                device_blob_sha=args.device_blob_sha,
            )
        print("[ok] follow-up /attestation stayed on the attested TLS socket")
    print("\nAll sampled attestation bindings passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
