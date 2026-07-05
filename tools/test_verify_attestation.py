#!/usr/bin/env python3
from __future__ import annotations

import base64
import datetime
import hashlib
import importlib.util
import ipaddress
import json
import os
import sys
import types
import unittest
from pathlib import Path


REAL_CRYPTOGRAPHY = True


def cryptography_works() -> bool:
    try:
        import cryptography.x509  # noqa: F401
    except Exception:
        return False
    return True


def install_cryptography_stub() -> None:
    cryptography = types.ModuleType("cryptography")
    x509 = types.ModuleType("cryptography.x509")
    hazmat = types.ModuleType("cryptography.hazmat")
    primitives = types.ModuleType("cryptography.hazmat.primitives")
    hashes = types.ModuleType("cryptography.hazmat.primitives.hashes")
    asymmetric = types.ModuleType("cryptography.hazmat.primitives.asymmetric")
    ec = types.ModuleType("cryptography.hazmat.primitives.asymmetric.ec")
    padding = types.ModuleType("cryptography.hazmat.primitives.asymmetric.padding")
    rsa = types.ModuleType("cryptography.hazmat.primitives.asymmetric.rsa")
    utils = types.ModuleType("cryptography.hazmat.primitives.asymmetric.utils")
    serialization = types.ModuleType("cryptography.hazmat.primitives.serialization")

    class ExtensionNotFound(Exception):
        pass

    class EllipticCurvePublicKey:
        pass

    class RSAPublicKey:
        pass

    def unavailable(*_args, **_kwargs):
        raise RuntimeError("cryptography backend is unavailable in this unit-test environment")

    x509.ExtensionNotFound = ExtensionNotFound
    x509.SubjectAlternativeName = object
    x509.DNSName = object
    x509.IPAddress = object
    x509.load_der_x509_certificate = unavailable
    x509.load_pem_x509_certificate = unavailable
    hashes.SHA256 = object
    hashes.SHA384 = object
    ec.EllipticCurvePublicKey = EllipticCurvePublicKey
    ec.ECDSA = unavailable
    padding.PKCS1v15 = unavailable
    rsa.RSAPublicKey = RSAPublicKey
    rsa.RSAPublicNumbers = unavailable
    utils.encode_dss_signature = unavailable
    serialization.Encoding = types.SimpleNamespace(DER="DER")
    serialization.PublicFormat = types.SimpleNamespace(SubjectPublicKeyInfo="SubjectPublicKeyInfo")

    cryptography.x509 = x509
    cryptography.hazmat = hazmat
    hazmat.primitives = primitives
    primitives.hashes = hashes
    primitives.asymmetric = asymmetric
    primitives.serialization = serialization
    asymmetric.ec = ec
    asymmetric.padding = padding
    asymmetric.rsa = rsa
    asymmetric.utils = utils

    sys.modules["cryptography"] = cryptography
    sys.modules["cryptography.x509"] = x509
    sys.modules["cryptography.hazmat"] = hazmat
    sys.modules["cryptography.hazmat.primitives"] = primitives
    sys.modules["cryptography.hazmat.primitives.hashes"] = hashes
    sys.modules["cryptography.hazmat.primitives.asymmetric"] = asymmetric
    sys.modules["cryptography.hazmat.primitives.asymmetric.ec"] = ec
    sys.modules["cryptography.hazmat.primitives.asymmetric.padding"] = padding
    sys.modules["cryptography.hazmat.primitives.asymmetric.rsa"] = rsa
    sys.modules["cryptography.hazmat.primitives.asymmetric.utils"] = utils
    sys.modules["cryptography.hazmat.primitives.serialization"] = serialization


def install_optional_import_stubs() -> None:
    global REAL_CRYPTOGRAPHY
    if importlib.util.find_spec("cbor2") is None:
        cbor2 = types.ModuleType("cbor2")

        def missing_cbor2(*_args, **_kwargs):
            raise RuntimeError("cbor2 is unavailable in this unit-test environment")

        cbor2.loads = missing_cbor2
        cbor2.dumps = missing_cbor2
        sys.modules["cbor2"] = cbor2

    if importlib.util.find_spec("OpenSSL") is None:
        openssl = types.ModuleType("OpenSSL")
        openssl.SSL = types.SimpleNamespace()
        openssl.crypto = types.SimpleNamespace()
        sys.modules["OpenSSL"] = openssl

    REAL_CRYPTOGRAPHY = cryptography_works()
    if not REAL_CRYPTOGRAPHY:
        install_cryptography_stub()


def load_verifier():
    install_optional_import_stubs()
    path = Path(__file__).with_name("verify-attestation.py")
    spec = importlib.util.spec_from_file_location("verify_attestation", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


try:
    VERIFIER = load_verifier()
    LOAD_ERROR = None
except ModuleNotFoundError as exc:
    VERIFIER = None
    LOAD_ERROR = exc


def make_cert_der(dns_names: list[str], ip_addresses: list[str]) -> bytes:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.UTC)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "unused.example")])
    san_values = [x509.DNSName(name) for name in dns_names]
    san_values.extend(x509.IPAddress(ipaddress.ip_address(value)) for value in ip_addresses)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName(san_values), critical=False)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


class VerifierTestCase(unittest.TestCase):
    def setUp(self) -> None:
        if VERIFIER is None:
            self.skipTest(f"verifier dependencies unavailable: {LOAD_ERROR}")


class HostnameVerificationTests(VerifierTestCase):
    def setUp(self) -> None:
        super().setUp()
        if not REAL_CRYPTOGRAPHY:
            if os.environ.get("TR_REQUIRE_CRYPTO") == "1":
                self.fail("TR_REQUIRE_CRYPTO=1 but cryptography backend is unavailable")
            self.skipTest("cryptography backend unavailable for certificate-generation test")

    def test_subject_alt_name_matches_dns_wildcard_and_ip(self) -> None:
        cert_der = make_cert_der(["api.example.com", "*.example.net"], ["127.0.0.1"])

        VERIFIER.assert_cert_matches_hostname(cert_der, "api.example.com")
        VERIFIER.assert_cert_matches_hostname(cert_der, "blue.example.net")
        VERIFIER.assert_cert_matches_hostname(cert_der, "127.0.0.1")

    def test_subject_alt_name_rejects_non_matching_host(self) -> None:
        cert_der = make_cert_der(["api.example.com", "*.example.net"], ["127.0.0.1"])

        with self.assertRaises(SystemExit) as raised:
            VERIFIER.assert_cert_matches_hostname(cert_der, "deep.blue.example.net")
        self.assertIn("hostname mismatch", str(raised.exception))

    def test_subject_alt_name_invalid_idna_patterns_are_clean_mismatches(self) -> None:
        for dns_name in [".example.com", f"{'a' * 64}.example.com"]:
            with self.subTest(dns_name=dns_name):
                cert_der = make_cert_der([dns_name], [])

                with self.assertRaises(SystemExit) as raised:
                    VERIFIER.assert_cert_matches_hostname(cert_der, "api.example.com")
                self.assertIn("[FAIL] TLS certificate hostname mismatch", str(raised.exception))


class GCPNonceBindingTests(VerifierTestCase):
    def test_relay_laundered_exporter_without_fresh_nonce_is_rejected(self) -> None:
        client_exporter = "11" * 32
        proxy_exporter = "22" * 32
        verifier_nonce = "33" * 32
        decoded_payload = {"eat_nonce": [proxy_exporter, client_exporter]}
        nonces = VERIFIER.gcp_nonce_values(decoded_payload)

        with self.assertRaises(ValueError) as raised:
            VERIFIER.require_gcp_fresh_exporter_binding(
                nonces,
                exporter_hex=client_exporter,
                nonce_hex=verifier_nonce,
            )
        self.assertIn("fresh caller nonce not present", str(raised.exception))

    def test_exporter_and_distinct_fresh_nonce_are_accepted(self) -> None:
        exporter = "aa" * 32
        verifier_nonce = "bb" * 32
        decoded_payload = {"eat_nonce": [exporter, verifier_nonce]}
        nonces = VERIFIER.gcp_nonce_values(decoded_payload)

        VERIFIER.require_gcp_fresh_exporter_binding(
            nonces,
            exporter_hex=exporter,
            nonce_hex=verifier_nonce,
        )


def jwt_for_payload(payload: dict) -> bytes:
    def b64url_json(value: dict) -> str:
        raw = json.dumps(value, separators=(",", ":")).encode("utf-8")
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

    return f"{b64url_json({'alg': 'RS256', 'kid': 'offline-test'})}.{b64url_json(payload)}.sig".encode("ascii")


class GCPLivenessModeTests(VerifierTestCase):
    def setUp(self) -> None:
        super().setUp()
        self._orig_verify_signature = VERIFIER.verify_gcp_jwt_signature
        VERIFIER.verify_gcp_jwt_signature = lambda _blob: None
        self.cert_der = b"offline leaf cert"
        self.cert_fp = hashlib.sha256(self.cert_der).hexdigest()
        self.exporter = bytes.fromhex("aa" * 32)
        self.nonce_hex = "bb" * 32
        self.digest = "sha256:offline-good"

    def tearDown(self) -> None:
        if VERIFIER is not None:
            VERIFIER.verify_gcp_jwt_signature = self._orig_verify_signature
        super().tearDown()

    def payload(self, *, nonces: list[str] | None = None, digest: str | None = None) -> dict:
        return {
            "iss": VERIFIER.GCP_ISSUER,
            "aud": [VERIFIER.GCP_AUDIENCE],
            "image_digest": digest or self.digest,
            "eat_nonce": nonces if nonces is not None else [self.cert_fp, self.nonce_hex],
        }

    def verify(self, payload: dict, *, require_exporter: bool) -> None:
        VERIFIER.verify_gcp_jwt(
            jwt_for_payload(payload),
            self.cert_der,
            exporter=self.exporter,
            expect_digest=self.digest,
            nonce_hex=self.nonce_hex,
            allow_debug=False,
            require_exporter=require_exporter,
        )

    def test_liveness_accepts_old_style_token_without_exporter(self) -> None:
        self.verify(self.payload(), require_exporter=False)

    def test_strict_rejects_old_style_token_without_exporter(self) -> None:
        with self.assertRaises(SystemExit) as raised:
            self.verify(self.payload(), require_exporter=True)
        self.assertIn("TLS exporter channel binding is not bound", str(raised.exception))

    def test_liveness_rejects_missing_fresh_nonce(self) -> None:
        with self.assertRaises(SystemExit) as raised:
            self.verify(self.payload(nonces=[self.cert_fp]), require_exporter=False)
        self.assertIn("fresh caller nonce not present", str(raised.exception))

    def test_liveness_rejects_wrong_digest(self) -> None:
        with self.assertRaises(SystemExit) as raised:
            self.verify(self.payload(digest="sha256:wrong"), require_exporter=False)
        self.assertIn("image_digest mismatch", str(raised.exception))

    def test_liveness_rejects_unbound_cert(self) -> None:
        with self.assertRaises(SystemExit) as raised:
            self.verify(self.payload(nonces=["00" * 32, self.nonce_hex]), require_exporter=False)
        self.assertIn("live TLS cert fingerprint is not bound", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
