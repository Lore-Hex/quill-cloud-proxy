#!/usr/bin/env python3
"""Strict-verification tests for the Microsoft Azure Attestation (MAA) path.

Every failure mode below is a test that the verifier FAILS CLOSED. That is the
point of the file: an Azure attestation that is accepted when it should not be
is worse than no Azure support at all, because it turns "attested" from a claim
into a decoration. So each test asserts SystemExit, and the happy-path test
exists mainly to prove the failure tests are failing for the reason claimed and
not because the fixture is broken.

The token is signed with a locally generated RSA key and the issuer's JWKS is
stubbed, so nothing here touches the network (an autouse fixture makes a real
fetch an outright test failure).
"""
from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import pathlib
import sys
import time
import types
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def _module_available(name: str) -> bool:
    """True if `name` is importable OR already stubbed into sys.modules.

    find_spec() alone is not enough: test_verify_attestation.py installs its own
    bare ModuleType stubs, and a ModuleType has `__spec__ = None`, which makes
    find_spec raise ValueError rather than report the module. Whichever test
    module pytest imports first must not break the other.
    """
    if name in sys.modules:
        return True
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError):
        return False


def _stub_module(name: str) -> types.ModuleType:
    module = types.ModuleType(name)
    # Give the stub a real spec so a find_spec() elsewhere sees "available"
    # instead of raising ValueError on a None __spec__.
    module.__spec__ = importlib.util.spec_from_loader(name, loader=None)
    return module


def _install_optional_import_stubs() -> None:
    """Stub the imports only the AWS Nitro / live-TLS paths need.

    verify-attestation.py imports cbor2 and pyOpenSSL at module scope. Neither
    is reachable from these offline MAA tests, so stub them when absent instead
    of making the MAA suite depend on them. This only ADDS to sys.modules and
    never removes anything, so it cannot poison a module another test imported.
    """
    if not _module_available("cbor2"):
        cbor2 = _stub_module("cbor2")

        def _no_cbor2(*_args: object, **_kwargs: object) -> object:
            raise RuntimeError("cbor2 is unavailable in this unit-test environment")

        cbor2.loads = _no_cbor2  # type: ignore[attr-defined]
        cbor2.dumps = _no_cbor2  # type: ignore[attr-defined]
        sys.modules["cbor2"] = cbor2
    if not _module_available("OpenSSL"):
        openssl = _stub_module("OpenSSL")
        openssl.SSL = types.SimpleNamespace()  # type: ignore[attr-defined]
        openssl.crypto = types.SimpleNamespace()  # type: ignore[attr-defined]
        sys.modules["OpenSSL"] = openssl


def _load_verifier() -> types.ModuleType:
    _install_optional_import_stubs()
    path = Path(__file__).with_name("verify-attestation.py")
    spec = importlib.util.spec_from_file_location("verify_attestation_under_test", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


VERIFIER = _load_verifier()

ISSUER = "https://quillenclave.uaen.attest.azure.net"
KID = "maa-test-signing-key"
CERT_DER = b"offline azure enclave leaf certificate DER"
CERT_FP = hashlib.sha256(CERT_DER).hexdigest()
DEVICE_HASH = hashlib.sha256(b"canonical device key blob").hexdigest()
EXPORTER = bytes.fromhex("a1" * 32)
NONCE_HEX = "b2" * 32
HOSTDATA = "c3" * 32

SIGNING_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
FORGER_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_uint(value: int) -> str:
    return _b64url(value.to_bytes((value.bit_length() + 7) // 8, "big"))


def jwks_for(key: rsa.RSAPrivateKey, kid: str = KID) -> dict[str, object]:
    numbers = key.public_key().public_numbers()
    return {"keys": [{"kty": "RSA", "kid": kid, "n": _b64url_uint(numbers.n), "e": _b64url_uint(numbers.e)}]}


def sign_jwt(
    payload: dict[str, object],
    *,
    key: rsa.RSAPrivateKey | None = None,
    kid: str = KID,
    alg: str = "RS256",
) -> bytes:
    header = _b64url(json.dumps({"alg": alg, "kid": kid, "typ": "JWT"}, separators=(",", ":")).encode())
    body = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header}.{body}".encode("ascii")
    signature = (key or SIGNING_KEY).sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return f"{header}.{body}.{_b64url(signature)}".encode("ascii")


def runtime_fields(**overrides: str) -> dict[str, str]:
    """The runtimeData struct attestation_azure.go marshals into REPORT_DATA."""
    fields = {
        "leaf_fp": CERT_FP,
        "device_hash": DEVICE_HASH,
        "channel_binding": EXPORTER.hex(),
        "nonce": NONCE_HEX,
    }
    fields.update(overrides)
    return fields


def maa_payload(
    *,
    fields: dict[str, str] | None = None,
    runtime_style: str = "string",
    drop: tuple[str, ...] = (),
    **overrides: object,
) -> dict[str, object]:
    """A token that passes every check, so each test can spoil exactly one thing."""
    fields = runtime_fields() if fields is None else fields
    runtime_bytes = VERIFIER.canonical_runtime_data_json(fields)
    runtime_claim: object
    if runtime_style == "string":
        runtime_claim = base64.b64encode(runtime_bytes).decode("ascii")
    else:
        # MAA is documented to nest caller data under a wrapper key. Which
        # wrapper the guest-attestation flow uses is unverified, so the
        # verifier searches for the fields and this exercises that.
        runtime_claim = {"client-payload": fields}
    now = int(time.time())
    payload: dict[str, object] = {
        "iss": ISSUER,
        "iat": now - 30,
        "nbf": now - 30,
        "exp": now + 3600,
        "x-ms-attestation-type": "sevsnpvm",
        "x-ms-sevsnpvm-is-debuggable": False,
        "x-ms-sevsnpvm-hostdata": HOSTDATA,
        "x-ms-sevsnpvm-reportdata": hashlib.sha256(runtime_bytes).hexdigest() + "00" * 32,
        "x-ms-runtime": runtime_claim,
    }
    payload.update(overrides)
    for key in drop:
        payload.pop(key, None)
    return payload


def run_verify(
    payload: dict[str, object],
    *,
    key: rsa.RSAPrivateKey | None = None,
    kid: str = KID,
    alg: str = "RS256",
    cert_der: bytes = CERT_DER,
    exporter: bytes | None = EXPORTER,
    expect_hostdata: str | None = HOSTDATA,
    expect_issuer: str | None = ISSUER,
    nonce_hex: str | None = NONCE_HEX,
    allow_debug: bool = False,
    device_blob_sha: str | None = None,
    require_exporter: bool = True,
) -> None:
    # expect_hostdata and expect_issuer default to the correct values because
    # both are MANDATORY on the MAA path: a test that spoils one other thing
    # must not also trip the missing-pin gates and pass for the wrong reason.
    VERIFIER.verify_maa_jwt(
        sign_jwt(payload, key=key, kid=kid, alg=alg),
        cert_der,
        exporter=exporter,
        expect_hostdata=expect_hostdata,
        expect_issuer=expect_issuer,
        nonce_hex=nonce_hex,
        allow_debug=allow_debug,
        device_blob_sha=device_blob_sha,
        require_exporter=require_exporter,
    )


@pytest.fixture(autouse=True)
def stub_jwks(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Serve the local signing key as the issuer's JWKS, and ban real fetches."""
    fetched: list[str] = []

    def fake_fetch(issuer: str) -> dict[str, object]:
        # Run the real issuer pinning even though the fetch itself is stubbed,
        # so a regression that lets a forged issuer through still shows up.
        VERIFIER.maa_issuer_jwks_uri(issuer)
        fetched.append(issuer)
        return jwks_for(SIGNING_KEY)

    def no_network(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("test attempted a live network fetch")

    monkeypatch.setattr(VERIFIER, "fetch_maa_jwks", fake_fetch)
    monkeypatch.setattr(VERIFIER.urllib.request, "urlopen", no_network)
    monkeypatch.setattr(VERIFIER, "_MAA_JWKS", {})
    return fetched


# --------------------------------------------------------------------------
# Happy path
# --------------------------------------------------------------------------


def test_happy_path_base64_runtime_claim(stub_jwks: list[str]) -> None:
    run_verify(maa_payload(), expect_hostdata=HOSTDATA)
    assert stub_jwks == [ISSUER]


def test_happy_path_nested_object_runtime_claim() -> None:
    run_verify(maa_payload(runtime_style="object"), expect_hostdata=HOSTDATA)


def test_happy_path_accepts_any_hostdata_in_a_rolling_deploy_set() -> None:
    run_verify(maa_payload(), expect_hostdata=f"{'d4' * 32},{HOSTDATA}")


def test_happy_path_liveness_mode_without_exporter() -> None:
    fields = runtime_fields()
    fields.pop("channel_binding")
    run_verify(maa_payload(fields=fields), require_exporter=False)


# --------------------------------------------------------------------------
# Issuer routing and signature
# --------------------------------------------------------------------------


def test_routes_gcp_and_maa_by_issuer_not_by_shape() -> None:
    assert VERIFIER.jwt_attestation_cloud(sign_jwt(maa_payload())) == "maa"
    assert VERIFIER.jwt_attestation_cloud(sign_jwt({"iss": VERIFIER.GCP_ISSUER})) == "gcp"


def test_unknown_issuer_is_named_and_refused() -> None:
    with pytest.raises(SystemExit) as raised:
        VERIFIER.jwt_attestation_cloud(sign_jwt({"iss": "https://attestation.example.com"}))
    assert "unknown JWT attestation issuer" in str(raised.value)
    assert "https://attestation.example.com" in str(raised.value)


@pytest.mark.parametrize(
    "issuer",
    [
        "https://confidentialcomputing.googleapis.com",
        "https://evil.example.com",
        # Suffix-looking but a different registrable domain.
        "https://quillenclave.attest.azure.net.evil.example.com",
        # Bare parent domain: no instance label.
        "https://attest.azure.net",
        # Leading-dot host: endswith() the suffix, but the instance label is
        # empty. Distinct from the bare-domain case above and easy to leave
        # unguarded.
        "https://.attest.azure.net",
        # Plaintext: a JWKS fetch over http is trivially substitutable.
        "http://quillenclave.uaen.attest.azure.net",
        "",
    ],
)
def test_wrong_issuer_is_rejected(issuer: str) -> None:
    with pytest.raises(SystemExit) as raised:
        run_verify(maa_payload(iss=issuer))
    assert "MAA issuer is not" in str(raised.value)


def test_forged_issuer_never_reaches_a_jwks_fetch(stub_jwks: list[str]) -> None:
    with pytest.raises(SystemExit):
        run_verify(maa_payload(iss="https://forger.example.com"))
    assert stub_jwks == [], "verifier fetched a JWKS from an unpinned issuer host"


@pytest.mark.parametrize(
    "issuer",
    [
        "https://someone@quillenclave.uaen.attest.azure.net",
        "https://quillenclave.uaen.attest.azure.net:8443",
        "https://quillenclave.uaen.attest.azure.net?x=1",
    ],
)
def test_issuer_with_userinfo_port_or_query_is_rejected(issuer: str) -> None:
    with pytest.raises(SystemExit):
        VERIFIER.maa_issuer_jwks_uri(issuer)


def test_jwks_uri_is_the_maa_certs_path_not_the_oidc_well_known_path() -> None:
    assert VERIFIER.maa_issuer_jwks_uri(ISSUER) == f"{ISSUER}/certs"


def test_bad_signature_is_rejected() -> None:
    with pytest.raises(SystemExit) as raised:
        run_verify(maa_payload(), key=FORGER_KEY)
    assert "signature does not validate" in str(raised.value)


def test_unknown_kid_is_rejected() -> None:
    with pytest.raises(SystemExit) as raised:
        run_verify(maa_payload(), kid="not-in-the-jwks")
    assert "kid not found" in str(raised.value)


def test_non_rs256_alg_is_rejected() -> None:
    with pytest.raises(SystemExit) as raised:
        run_verify(maa_payload(), alg="none")
    assert "unsupported MAA JWT alg" in str(raised.value)


def test_x5c_only_jwks_entry_is_usable(monkeypatch: pytest.MonkeyPatch) -> None:
    """MAA publishes signing certs; n/e may be absent. Both must work."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.x509.oid import NameOID

    now = datetime.datetime.now(datetime.UTC)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "maa-test")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(SIGNING_KEY.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(SIGNING_KEY, hashes.SHA256())
    )
    x5c = base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode("ascii")
    monkeypatch.setattr(
        VERIFIER,
        "fetch_maa_jwks",
        lambda _issuer: {"keys": [{"kty": "RSA", "kid": KID, "x5c": [x5c]}]},
    )
    run_verify(maa_payload(), expect_hostdata=HOSTDATA)


# --------------------------------------------------------------------------
# Hardware claims
# --------------------------------------------------------------------------


@pytest.mark.parametrize("attestation_type", ["sgx", "tdxvm", "", None, 1])
def test_attestation_type_must_be_sevsnpvm(attestation_type: object) -> None:
    payload = maa_payload()
    if attestation_type is None:
        payload.pop("x-ms-attestation-type")
    else:
        payload["x-ms-attestation-type"] = attestation_type
    with pytest.raises(SystemExit) as raised:
        run_verify(payload)
    assert "attestation type is not 'sevsnpvm'" in str(raised.value)


@pytest.mark.parametrize("debuggable", [True, "true", "TRUE"])
def test_debuggable_guest_is_rejected(debuggable: object) -> None:
    with pytest.raises(SystemExit) as raised:
        run_verify(maa_payload(**{"x-ms-sevsnpvm-is-debuggable": debuggable}))
    assert "debuggable" in str(raised.value)


def test_absent_is_debuggable_claim_fails_closed() -> None:
    with pytest.raises(SystemExit) as raised:
        run_verify(maa_payload(drop=("x-ms-sevsnpvm-is-debuggable",)))
    assert "no x-ms-sevsnpvm-is-debuggable claim" in str(raised.value)


def test_allow_debug_opts_out_of_the_debug_gate_only() -> None:
    run_verify(maa_payload(**{"x-ms-sevsnpvm-is-debuggable": True}), allow_debug=True)


def test_hostdata_absent_is_rejected_as_a_plain_confidential_vm() -> None:
    with pytest.raises(SystemExit) as raised:
        run_verify(maa_payload(drop=("x-ms-sevsnpvm-hostdata",)))
    message = str(raised.value)
    assert "no x-ms-sevsnpvm-hostdata claim" in message
    # The message has to explain WHY, or the next person "fixes" it by
    # deploying a plain CVM and passing --expected-hostdata 00...
    assert "PLAIN Azure" in message and "confidential containers" in message


@pytest.mark.parametrize("zeros", ["00" * 32, "00" * 16, "00"])
def test_hostdata_all_zero_is_rejected(zeros: str) -> None:
    with pytest.raises(SystemExit) as raised:
        run_verify(maa_payload(**{"x-ms-sevsnpvm-hostdata": zeros}))
    assert "hostdata is all zero" in str(raised.value)


def test_hostdata_mismatch_is_rejected() -> None:
    with pytest.raises(SystemExit) as raised:
        run_verify(maa_payload(), expect_hostdata="d4" * 32)
    assert "hostdata mismatch" in str(raised.value)


def test_hostdata_non_hex_is_rejected() -> None:
    with pytest.raises(SystemExit) as raised:
        run_verify(maa_payload(**{"x-ms-sevsnpvm-hostdata": "not-hex"}))
    assert "hostdata is not hex" in str(raised.value)


def test_hostdata_match_is_case_insensitive() -> None:
    run_verify(maa_payload(**{"x-ms-sevsnpvm-hostdata": HOSTDATA.upper()}), expect_hostdata=HOSTDATA)


# --------------------------------------------------------------------------
# The report-data link: claims vs the hardware report
# --------------------------------------------------------------------------


def test_reportdata_not_matching_sha256_of_runtime_data_is_rejected() -> None:
    with pytest.raises(SystemExit) as raised:
        run_verify(
            maa_payload(**{"x-ms-sevsnpvm-reportdata": hashlib.sha256(b"some other bytes").hexdigest() + "00" * 32})
        )
    assert "REPORT_DATA does not commit to the echoed runtime data" in str(raised.value)


def test_reportdata_absent_is_rejected() -> None:
    with pytest.raises(SystemExit) as raised:
        run_verify(maa_payload(drop=("x-ms-sevsnpvm-reportdata",)))
    assert "no x-ms-sevsnpvm-reportdata claim" in str(raised.value)


def test_tampered_runtime_data_breaks_the_reportdata_link() -> None:
    """Swapping in a different leaf_fp without re-deriving REPORT_DATA must fail.

    This is the check that stops an attacker from editing the echoed runtime
    data: the hardware report commits to the original bytes.
    """
    payload = maa_payload()
    tampered = runtime_fields(leaf_fp=hashlib.sha256(b"attacker cert").hexdigest())
    payload["x-ms-runtime"] = base64.b64encode(
        VERIFIER.canonical_runtime_data_json(tampered)
    ).decode("ascii")
    with pytest.raises(SystemExit) as raised:
        run_verify(payload)
    assert "REPORT_DATA does not commit" in str(raised.value)


def test_runtime_claim_absent_is_rejected() -> None:
    with pytest.raises(SystemExit) as raised:
        run_verify(maa_payload(drop=("x-ms-runtime",)))
    assert "no usable x-ms-runtime claim" in str(raised.value)


def test_runtime_object_without_runtime_fields_is_rejected() -> None:
    with pytest.raises(SystemExit) as raised:
        run_verify(maa_payload(**{"x-ms-runtime": {"keys": [{"kid": "unrelated"}]}}))
    assert "carries no leaf_fp/device_hash runtime data" in str(raised.value)


def test_canonical_runtime_json_is_sorted_no_spaces_and_drops_omitempty() -> None:
    """SORTED keys, no spaces, empty omitempty fields dropped.

    Sorted, not Go declaration order. MAA re-serialises runtime_data with keys
    alphabetised, so the bytes the enclave sent cannot be recovered from the
    token and only the sorted form is reconstructible. attestation_azure.go now
    declares its struct fields alphabetically to match, so both sides hash
    identical bytes. Measured on real SEV-SNP hardware 2026-08-03; the earlier
    declaration-order spelling would have failed every genuine token.
    """
    assert VERIFIER.canonical_runtime_data_json(runtime_fields()) == (
        b'{"channel_binding":"' + EXPORTER.hex().encode()
        + b'","device_hash":"' + DEVICE_HASH.encode()
        + b'","leaf_fp":"' + CERT_FP.encode()
        + b'","nonce":"' + NONCE_HEX.encode() + b'"}'
    )
    assert VERIFIER.canonical_runtime_data_json({"leaf_fp": "aa", "device_hash": "bb"}) == (
        b'{"device_hash":"bb","leaf_fp":"aa"}'
    )


# --------------------------------------------------------------------------
# Session binding
# --------------------------------------------------------------------------


def test_leaf_fp_not_matching_the_live_cert_is_rejected() -> None:
    fields = runtime_fields(leaf_fp=hashlib.sha256(b"a different cert").hexdigest())
    with pytest.raises(SystemExit) as raised:
        run_verify(maa_payload(fields=fields))
    assert "live TLS cert fingerprint is not bound" in str(raised.value)


def test_leaf_fp_absent_is_rejected() -> None:
    fields = runtime_fields()
    fields.pop("leaf_fp")
    with pytest.raises(SystemExit) as raised:
        run_verify(maa_payload(fields=fields))
    assert "live TLS cert fingerprint is not bound" in str(raised.value)


def test_channel_binding_mismatch_is_rejected() -> None:
    fields = runtime_fields(channel_binding="ee" * 32)
    with pytest.raises(SystemExit) as raised:
        run_verify(maa_payload(fields=fields))
    assert "TLS exporter channel binding is not bound" in str(raised.value)


def test_channel_binding_mismatch_is_rejected_even_in_liveness_mode() -> None:
    """Liveness mode makes the binding OPTIONAL, never wrong-but-accepted."""
    fields = runtime_fields(channel_binding="ee" * 32)
    with pytest.raises(SystemExit) as raised:
        run_verify(maa_payload(fields=fields), require_exporter=False)
    assert "channel_binding does not match the live TLS exporter" in str(raised.value)


def test_channel_binding_absent_is_rejected_in_strict_mode() -> None:
    fields = runtime_fields()
    fields.pop("channel_binding")
    with pytest.raises(SystemExit) as raised:
        run_verify(maa_payload(fields=fields))
    assert "TLS exporter channel binding is not bound" in str(raised.value)


def test_nonce_mismatch_is_rejected() -> None:
    fields = runtime_fields(nonce="ff" * 32)
    with pytest.raises(SystemExit) as raised:
        run_verify(maa_payload(fields=fields))
    assert "fresh caller nonce not present" in str(raised.value)


def test_nonce_absent_is_rejected() -> None:
    fields = runtime_fields()
    fields.pop("nonce")
    with pytest.raises(SystemExit) as raised:
        run_verify(maa_payload(fields=fields))
    assert "fresh caller nonce not present" in str(raised.value)


def test_relay_laundered_exporter_as_the_caller_nonce_is_rejected() -> None:
    """The nonce must be independent of the exporter, as on the GCP path."""
    fields = runtime_fields(nonce=EXPORTER.hex())
    with pytest.raises(SystemExit) as raised:
        run_verify(maa_payload(fields=fields), nonce_hex=EXPORTER.hex())
    assert "must differ from the TLS exporter" in str(raised.value)


def test_short_caller_nonce_is_rejected() -> None:
    short = "ab" * 8
    fields = runtime_fields(nonce=short)
    with pytest.raises(SystemExit) as raised:
        run_verify(maa_payload(fields=fields), nonce_hex=short)
    assert "at least 16 random bytes" in str(raised.value)


def test_same_socket_binding_check_routes_maa_tokens() -> None:
    """Dispatch site 1: the same-TLS-socket body check must not use GCP rules."""
    VERIFIER._require_attestation_body_binds_exporter(
        sign_jwt(maa_payload()), EXPORTER, NONCE_HEX, "first"
    )
    with pytest.raises(SystemExit) as raised:
        VERIFIER._require_attestation_body_binds_exporter(
            sign_jwt(maa_payload(fields=runtime_fields(nonce="ff" * 32))),
            EXPORTER,
            NONCE_HEX,
            "first",
        )
    assert "not bound to this TLS session" in str(raised.value)


# --------------------------------------------------------------------------
# The trust anchor: WHICH attestation instance signed
#
# `*.attest.azure.net` is a namespace, not an authority — `az attestation
# create` puts any Azure tenant inside it, serving their own signing keys at
# {issuer}/certs under a policy they wrote. Suffix-matching it is the moral
# equivalent of accepting "chains to some CA". These tests are the ones that
# fail against a verifier which trusts the suffix alone.
# --------------------------------------------------------------------------

ATTACKER_ISSUER = "https://attackerprovider.uaenorth.attest.azure.net"


def test_token_from_another_azure_tenants_instance_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The headline attack: nothing is forged, and it must still fail.

    An attacker runs their own Azure confidential container, creates their own
    attestation instance, and submits runtime data naming OUR live cert, OUR
    exporter and OUR fresh nonce (all four fields are caller-supplied to the
    sidecar per attestation_azure.go). Every claim is genuine — signature,
    sevsnpvm, is-debuggable=false, a non-zero hostdata, a REPORT_DATA that
    really is sha512(runtime_data). The only thing wrong is WHO signed it.
    """
    monkeypatch.setattr(VERIFIER, "fetch_maa_jwks", lambda _issuer: jwks_for(FORGER_KEY))
    with pytest.raises(SystemExit) as raised:
        run_verify(
            maa_payload(iss=ATTACKER_ISSUER, **{"x-ms-sevsnpvm-hostdata": "de" * 32}),
            key=FORGER_KEY,
            expect_hostdata="de" * 32,
        )
    message = str(raised.value)
    assert "not a trusted attestation instance" in message
    assert ATTACKER_ISSUER in message


def test_untrusted_instance_never_reaches_a_jwks_fetch(stub_jwks: list[str]) -> None:
    """The fetch goes to a host the unverified token names, so it must not happen."""
    with pytest.raises(SystemExit):
        run_verify(maa_payload(iss=ATTACKER_ISSUER))
    assert stub_jwks == [], "verifier fetched a JWKS from an untrusted Azure instance"


def test_no_issuer_pin_configured_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(VERIFIER.MAA_ISSUER_ENV, raising=False)
    with pytest.raises(SystemExit) as raised:
        run_verify(maa_payload(), expect_issuer=None)
    message = str(raised.value)
    assert "no trusted MAA issuer configured" in message
    # The message must explain why there is no default, or the next person adds one.
    assert "open to every Azure tenant" in message


def test_issuer_pin_may_come_from_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(VERIFIER.MAA_ISSUER_ENV, ISSUER)
    run_verify(maa_payload(), expect_issuer=None)


def test_issuer_pin_accepts_a_multi_region_set() -> None:
    run_verify(maa_payload(), expect_issuer=f"https://other.eus.attest.azure.net,{ISSUER}")


def test_issuer_pin_is_exact_not_a_substring_match() -> None:
    """A neighbouring instance name must not satisfy the pin."""
    lookalike = "https://xxquillenclave.uaen.attest.azure.net"
    with pytest.raises(SystemExit) as raised:
        run_verify(maa_payload(iss=lookalike))
    assert "not a trusted attestation instance" in str(raised.value)


def test_issuer_pin_tolerates_a_trailing_slash() -> None:
    run_verify(maa_payload(), expect_issuer=f"{ISSUER}/")


def test_an_out_of_domain_issuer_pin_is_refused() -> None:
    """A bad pin must fail loudly, not silently widen the trust set."""
    with pytest.raises(SystemExit) as raised:
        run_verify(maa_payload(), expect_issuer="https://attacker.example.com")
    assert "--expected-maa-issuer entry is not" in str(raised.value)


def test_jwks_redirect_off_the_pinned_host_is_refused() -> None:
    """Pinning the JWKS URL is pointless if a 302 can move the fetch."""
    handler = VERIFIER._PinnedHostRedirectHandler("quillenclave.uaen.attest.azure.net")
    for target in (
        "https://attacker.example.com/certs",
        "http://quillenclave.uaen.attest.azure.net/certs",
    ):
        with pytest.raises(VERIFIER.urllib.error.HTTPError):
            handler.redirect_request(None, None, 302, "Found", {}, target)


# --------------------------------------------------------------------------
# Token validity window
# --------------------------------------------------------------------------


def test_expired_token_is_rejected() -> None:
    """Offline-blob mode has no nonce and no exporter, so exp is the only
    freshness signal — without it a token from a months-old support bundle
    re-verifies today."""
    now = int(time.time())
    with pytest.raises(SystemExit) as raised:
        run_verify(maa_payload(iat=now - 400000, nbf=now - 400000, exp=now - 86400))
    assert "expired" in str(raised.value)


def test_token_without_exp_is_rejected() -> None:
    with pytest.raises(SystemExit) as raised:
        run_verify(maa_payload(drop=("exp",)))
    assert "no numeric exp claim" in str(raised.value)


def test_not_yet_valid_token_is_rejected() -> None:
    now = int(time.time())
    with pytest.raises(SystemExit) as raised:
        run_verify(maa_payload(nbf=now + 86400, exp=now + 172800))
    assert "not yet valid" in str(raised.value)


def test_small_clock_skew_is_tolerated() -> None:
    """A verifier a minute fast must not report the fleet as unattested."""
    now = int(time.time())
    run_verify(maa_payload(exp=now - 60))


# --------------------------------------------------------------------------
# HOST_DATA shape and the mandatory pin
# --------------------------------------------------------------------------


def test_hostdata_pin_is_mandatory() -> None:
    """Unpinned, hostdata proves only that SOME non-zero value exists — and MAA
    attests any caller's report, so an unrelated container passes."""
    with pytest.raises(SystemExit) as raised:
        run_verify(maa_payload(), expect_hostdata=None)
    message = str(raised.value)
    assert "--expected-hostdata is required" in message
    assert "CCE policy hash" in message


@pytest.mark.parametrize("hostdata", ["c3 c3", "c3\tc3", "c3\nc3", " ".join(["c3"] * 32)])
def test_hostdata_with_embedded_whitespace_is_rejected(hostdata: str) -> None:
    """bytes.fromhex() silently skips whitespace, so this used to parse — and
    then the pin comparison ran against the un-normalised string, so the two
    checks disagreed about what the value even was."""
    with pytest.raises(SystemExit) as raised:
        run_verify(maa_payload(**{"x-ms-sevsnpvm-hostdata": hostdata}))
    assert "is not hex" in str(raised.value)


@pytest.mark.parametrize("hostdata", ["01", "0001", "c3" * 31, "c3" * 33, "c3" * 64])
def test_hostdata_must_be_exactly_32_bytes(hostdata: str) -> None:
    """HOST_DATA is a fixed 32-byte field; a 1-byte non-zero value satisfied the
    old 'is it non-zero' gate and was reported as a workload measurement."""
    with pytest.raises(SystemExit) as raised:
        run_verify(maa_payload(**{"x-ms-sevsnpvm-hostdata": hostdata}), expect_hostdata=hostdata)
    assert "not 32" in str(raised.value)


def test_hostdata_odd_length_hex_is_rejected() -> None:
    with pytest.raises(SystemExit) as raised:
        run_verify(maa_payload(**{"x-ms-sevsnpvm-hostdata": "c" + "c3" * 31}))
    assert "is not hex" in str(raised.value)


# --------------------------------------------------------------------------
# Operator-supplied pins must never be silently dropped
# --------------------------------------------------------------------------


def test_device_blob_sha_mismatch_is_rejected() -> None:
    """device_hash is in the REPORT_DATA pre-image, so --device-blob-sha is free
    to check; accepting the flag and never comparing it tells the operator they
    pinned the device key when nothing did."""
    with pytest.raises(SystemExit) as raised:
        run_verify(maa_payload(), device_blob_sha="11" * 32)
    assert "device-blob mismatch" in str(raised.value)


def test_device_blob_sha_match_is_accepted() -> None:
    run_verify(maa_payload(), device_blob_sha=DEVICE_HASH.upper())


def _run_gcp_verify(nonces: list[str], **kwargs: object) -> None:
    """verify_gcp_jwt with the signature stubbed; only the claim rules are under test."""
    payload = {
        "iss": VERIFIER.GCP_ISSUER, "aud": VERIFIER.GCP_AUDIENCE,
        "eat_nonce": nonces, "image_digest": "sha256:abc",
    }
    VERIFIER.verify_gcp_jwt(
        sign_jwt(payload), CERT_DER,
        exporter=EXPORTER, expect_digest=None, nonce_hex=NONCE_HEX,
        allow_debug=False, **kwargs,  # type: ignore[arg-type]
    )


def test_gcp_device_blob_sha_mismatch_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    """attestation_gcp.go puts sha256(deviceBlob) in nonces[1]; the flag was
    accepted and never compared there either."""
    monkeypatch.setattr(VERIFIER, "verify_gcp_jwt_signature", lambda _blob: None)
    nonces = [CERT_FP, DEVICE_HASH, EXPORTER.hex(), NONCE_HEX]
    with pytest.raises(SystemExit) as raised:
        _run_gcp_verify(nonces, device_blob_sha="11" * 32)
    assert "device-blob hash is not bound" in str(raised.value)


def test_gcp_device_blob_sha_match_is_accepted(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(VERIFIER, "verify_gcp_jwt_signature", lambda _blob: None)
    nonces = [CERT_FP, DEVICE_HASH, EXPORTER.hex(), NONCE_HEX]
    _run_gcp_verify(nonces, device_blob_sha=DEVICE_HASH.upper())


@pytest.mark.parametrize(
    ("cloud", "flag", "value"),
    [
        ("maa", "expect_digest", "sha256:abc"),
        ("maa", "expected_pcr0", "ab" * 48),
        ("gcp", "expected_hostdata", "c3" * 32),
        ("aws", "expected_hostdata", "c3" * 32),
    ],
)
def test_a_measurement_pin_for_another_cloud_is_refused(cloud: str, flag: str, value: str) -> None:
    """reconcile-enclave-dns.py hardcodes --expect-digest. Pointed at Azure, the
    pin used to evaporate and the run still passed, so an IP could be published
    on the strength of an unpinned token."""
    import argparse

    args = argparse.Namespace(expected_pcr0=None, expect_digest=None, expected_hostdata=None)
    setattr(args, flag, value)
    with pytest.raises(SystemExit) as raised:
        VERIFIER.reject_inapplicable_measurement_pins(cloud, args)
    assert "was supplied, but this attestation came from" in str(raised.value)


def test_applicable_pins_are_not_refused() -> None:
    import argparse

    VERIFIER.reject_inapplicable_measurement_pins(
        "maa",
        argparse.Namespace(expected_pcr0=None, expect_digest=None, expected_hostdata="c3" * 32),
    )


def _flag_help(flag: str) -> str:
    for action in VERIFIER.build_parser()._actions:
        if flag in action.option_strings:
            return action.help or ""
    raise AssertionError(f"{flag} is not a flag")


def test_allow_debug_help_text_names_the_azure_gate() -> None:
    """--allow-debug silently covers the Azure is-debuggable gate too. An
    operator who enables it for a Confidential Space reason and later points the
    same command at Azure must be able to see that from --help, rather than
    reading 'do not fail when GCP dbgstat is enabled' and assuming it is inert."""
    help_text = _flag_help("--allow-debug")
    assert "x-ms-sevsnpvm-is-debuggable" in help_text
    assert "Azure" in help_text


def test_the_issuer_pin_flag_exists_and_says_why_it_is_required() -> None:
    help_text = _flag_help("--expected-maa-issuer")
    assert "REQUIRED" in help_text
    assert "namespace" in help_text


# --------------------------------------------------------------------------
# --binding-stress must enforce the same gates it reports on
# --------------------------------------------------------------------------


def _stub_stress_transport(
    monkeypatch: pytest.MonkeyPatch,
    *,
    payload_overrides: dict[str, object] | None = None,
    drop: tuple[str, ...] = (),
) -> None:
    """Make _probe_binding's TLS fetch return a real, correctly bound MAA token.

    Everything about the token is honest except whatever the caller spoils, so a
    failure can only come from the gate under test.
    """

    def fake_fetch(
        host: str,
        nonce_hex: str,
        port: int = 443,
        connect_ip: str | None = None,
        **_kwargs: object,
    ) -> tuple[bytes, bytes, bytes, str | None, bytes | None]:
        cert_der = f"cert-for-{host}".encode()
        fields = {
            "leaf_fp": hashlib.sha256(cert_der).hexdigest(),
            "device_hash": DEVICE_HASH,
            "channel_binding": EXPORTER.hex(),
            "nonce": nonce_hex,
        }
        blob = sign_jwt(maa_payload(fields=fields, drop=drop, **(payload_overrides or {})))
        return cert_der, EXPORTER, blob, None, None

    monkeypatch.setattr(VERIFIER, "fetch_attestation_same_tls_socket", fake_fetch)
    monkeypatch.setattr(VERIFIER, "fetch_maa_jwks", lambda _issuer: jwks_for(SIGNING_KEY))


STRESS_HOSTS = ["api-azure.trustedrouter.com", "api.quillrouter.com"]


def _stress(**kwargs: object) -> int:
    defaults: dict[str, object] = {
        "connect_ip": None, "hosts": STRESS_HOSTS, "concurrency": 2, "rounds": 1,
        "port": 443, "expect_digest": None, "expect_hostdata": HOSTDATA,
        "expect_issuer": ISSUER,
    }
    defaults.update(kwargs)
    return VERIFIER.binding_stress(**defaults)  # type: ignore[arg-type]


def test_binding_stress_passes_on_a_healthy_azure_fleet(monkeypatch: pytest.MonkeyPatch) -> None:
    """Control, so the failure tests below are known to fail for their stated reason."""
    _stub_stress_transport(monkeypatch)
    assert _stress() == 0


def test_binding_stress_fails_a_plain_cvm_with_no_hostdata(monkeypatch: pytest.MonkeyPatch) -> None:
    """THE regression: a plain Azure confidential VM emits no HOST_DATA claim, so
    nothing was observed, so the pin was skipped and the deploy gate went green
    on exactly the deployment this module exists to reject."""
    _stub_stress_transport(monkeypatch, drop=("x-ms-sevsnpvm-hostdata",))
    assert _stress() == 1


def test_binding_stress_fails_all_zero_hostdata_without_a_pin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub_stress_transport(monkeypatch, payload_overrides={"x-ms-sevsnpvm-hostdata": "00" * 32})
    assert _stress(expect_hostdata=None) == 1


def test_binding_stress_fails_a_debuggable_guest(monkeypatch: pytest.MonkeyPatch) -> None:
    """dbgstat was printed and never asserted, so a guest whose memory the host
    can read passed this mode."""
    _stub_stress_transport(monkeypatch, payload_overrides={"x-ms-sevsnpvm-is-debuggable": True})
    assert _stress() == 1


def test_binding_stress_fails_a_wrong_attestation_type(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_stress_transport(monkeypatch, payload_overrides={"x-ms-attestation-type": "tdxvm"})
    assert _stress() == 1


def test_binding_stress_verifies_signatures(monkeypatch: pytest.MonkeyPatch) -> None:
    """This mode used to read claims straight out of an unauthenticated payload
    and then print a measurement verdict on them."""
    _stub_stress_transport(monkeypatch)
    monkeypatch.setattr(VERIFIER, "fetch_maa_jwks", lambda _issuer: jwks_for(FORGER_KEY))
    assert _stress() == 1


def test_binding_stress_fails_an_untrusted_issuer(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_stress_transport(monkeypatch)
    assert _stress(expect_issuer="https://someone-else.eus.attest.azure.net") == 1


def test_binding_stress_fails_a_hostdata_outside_the_pinned_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub_stress_transport(monkeypatch)
    assert _stress(expect_hostdata="d4" * 32) == 1


def _stub_probe(monkeypatch: pytest.MonkeyPatch, cloud: str, digest: object) -> None:
    """A probe that passes every binding check but reports no measurement.

    Isolates the AGGREGATION rule from the per-probe gates: those two are
    independent layers, and a test that only exercises the probe gates would
    let the aggregation regress unnoticed.
    """

    def probe(host: str, *_args: object, **_kwargs: object) -> dict[str, object]:
        return {
            "host": host, "cloud": cloud, "served_fp": hashlib.sha256(host.encode()).hexdigest(),
            "exporter": EXPORTER.hex(), "nonce": NONCE_HEX, "cert_bound": True,
            "exporter_bound": True, "nonce_bound": True, "bound": True,
            "binding_error": "", "dbgstat": ["False"], "digest": digest,
        }

    monkeypatch.setattr(VERIFIER, "_probe_binding", probe)


@pytest.mark.parametrize("cloud", ["maa", "gcp"])
def test_binding_stress_fails_when_a_pin_is_set_but_no_probe_reports_a_measurement(
    monkeypatch: pytest.MonkeyPatch, cloud: str,
) -> None:
    """`if not expected or not observed: continue` treated 'no measurement at
    all' as 'nothing to object to', so the pin was skipped exactly when the
    fleet failed to produce one."""
    _stub_probe(monkeypatch, cloud, None)
    pin = {"maa": {"expect_hostdata": HOSTDATA, "expect_digest": None},
           "gcp": {"expect_digest": "sha256:abc", "expect_hostdata": None}}[cloud]
    assert _stress(**pin) == 1


@pytest.mark.parametrize("cloud", ["maa", "gcp"])
def test_binding_stress_passes_when_the_reported_measurement_matches(
    monkeypatch: pytest.MonkeyPatch, cloud: str,
) -> None:
    """Control for the test above: the same probe WITH a measurement passes."""
    value = {"maa": HOSTDATA, "gcp": "sha256:abc"}[cloud]
    _stub_probe(monkeypatch, cloud, value)
    pin = {"maa": {"expect_hostdata": value, "expect_digest": None},
           "gcp": {"expect_digest": value, "expect_hostdata": None}}[cloud]
    assert _stress(**pin) == 0


# --------------------------------------------------------------------------
# End-to-end through main(), so the argparse wiring is covered too
#
# The unit tests call verify_maa_jwt directly, which cannot catch a pin that
# main() parses but never forwards — the exact shape of the --device-blob-sha
# defect (flag accepted, argument dropped, run passes).
# --------------------------------------------------------------------------


def _run_cli(tmp_path: Path, argv: list[str], monkeypatch: pytest.MonkeyPatch,
             payload: dict[str, object] | None = None) -> int:
    blob_path = tmp_path / "azure.jwt"
    blob_path.write_bytes(sign_jwt(payload if payload is not None else maa_payload()))
    monkeypatch.setattr(VERIFIER, "fetch_live_cert_der", lambda *_a, **_k: CERT_DER)
    monkeypatch.setattr(VERIFIER, "fetch_maa_jwks", lambda _issuer: jwks_for(SIGNING_KEY))
    monkeypatch.setattr(
        VERIFIER.sys, "argv",
        ["verify-attestation.py", str(blob_path), "--api-host", "api-azure.trustedrouter.com", *argv],
    )
    return VERIFIER.main()


def test_cli_offline_blob_passes_with_both_pins(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert _run_cli(tmp_path, [
        "--expected-maa-issuer", ISSUER,
        "--expected-hostdata", HOSTDATA,
    ], monkeypatch) == 0


def test_cli_forwards_device_blob_sha(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A pin parsed but not forwarded is worse than one not offered."""
    with pytest.raises(SystemExit) as raised:
        _run_cli(tmp_path, [
            "--expected-maa-issuer", ISSUER,
            "--expected-hostdata", HOSTDATA,
            "--device-blob-sha", "11" * 32,
        ], monkeypatch)
    assert "device-blob mismatch" in str(raised.value)


def test_cli_requires_the_issuer_pin(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(VERIFIER.MAA_ISSUER_ENV, raising=False)
    with pytest.raises(SystemExit) as raised:
        _run_cli(tmp_path, ["--expected-hostdata", HOSTDATA], monkeypatch)
    assert "no trusted MAA issuer configured" in str(raised.value)


def test_cli_requires_the_hostdata_pin(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(SystemExit) as raised:
        _run_cli(tmp_path, ["--expected-maa-issuer", ISSUER], monkeypatch)
    assert "--expected-hostdata is required" in str(raised.value)


def test_cli_refuses_a_gcp_pin_against_an_azure_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """reconcile-enclave-dns.py hardcodes --expect-digest; pointed at Azure it
    must stop rather than publish an IP on an unpinned token."""
    with pytest.raises(SystemExit) as raised:
        _run_cli(tmp_path, [
            "--expected-maa-issuer", ISSUER,
            "--expected-hostdata", HOSTDATA,
            "--expect-digest", "sha256:abc",
        ], monkeypatch)
    assert "--expect-digest was supplied" in str(raised.value)


# --------------------------------------------------------------------------
# The AWS Nitro path must stay reachable
# --------------------------------------------------------------------------


def test_cose_documents_are_not_captured_by_jwt_routing() -> None:
    """A Nitro COSE_Sign1 document still takes the AWS branch.

    Routing changed only INSIDE `if looks_like_jwt(blob)`. CBOR documents start
    with a major-type-4 array header (0x84), never ASCII 'e', so they cannot be
    pulled into the JWT branch by the new issuer dispatch.
    """
    assert VERIFIER.looks_like_jwt(b"\x84\x44\xa1\x01\x38\x22") is False
    assert VERIFIER.looks_like_jwt(sign_jwt(maa_payload())) is True


# ---------------------------------------------------------------------------
# Real-hardware fixture.
#
# Every shape below was ASSUMED when this verifier was first written, and three
# of the assumptions were wrong. The token in tools/fixtures/ came off a real
# AMD SEV-SNP confidential container group in Azure UAE North on 2026-08-03
# (skr sidecar 2.7), signed by a real MAA instance. It exists so the corrections
# cannot silently regress into the plausible-but-wrong versions.
# ---------------------------------------------------------------------------

_FIXTURE_DIR = pathlib.Path(__file__).parent / "fixtures"
_REAL_TOKEN = (_FIXTURE_DIR / "maa_real_sevsnp_token.jwt").read_text().strip()
_REAL_ISSUER = "https://trquilluaen.uaen.attest.azure.net"
_REAL_HOSTDATA = "994b542047b4d5ed6163b7b54e56e0d642624d1e7179b1df43b9fe761c25a987"
# The probe bound leaf_fp = sha256(b"probe-leaf-der"), so this is the cert.
_REAL_CERT_DER = b"probe-leaf-der"
_REAL_EXPORTER = bytes.fromhex("aa" * 32)
_REAL_NONCE_HEX = "bb" * 16


def _va():
    return _load_verifier()


def _real_payload():
    return _va().parse_jwt_payload(_REAL_TOKEN.encode())


class TestRealHardwareToken:
    def test_hostdata_is_the_cce_policy_hash(self):
        """HOST_DATA carries the confidential-container policy hash.

        This is the whole reason Azure can attest at the same strength as
        Nitro PCR0 and Confidential Space image_digest. It was also observed
        to CHANGE when the container command changed, so it measures this
        workload rather than just the base image.
        """
        assert _real_payload()["x-ms-sevsnpvm-hostdata"] == _REAL_HOSTDATA

    def test_hostdata_is_not_all_zero(self):
        """A plain CVM yields all-zero HOST_DATA. Confidential containers do not."""
        raw = _real_payload()["x-ms-sevsnpvm-hostdata"]
        assert any(bytes.fromhex(raw))

    def test_report_data_is_sha256_of_runtime_then_zero_padding(self):
        """NOT sha512, and only half the 64-byte field is the digest.

        The first draft checked sha512 across all 64 bytes; it would have
        rejected this genuine token, which reads as "Azure attestation is
        broken" rather than "our verifier is wrong".
        """
        va = _va()
        payload = _real_payload()
        _fields, runtime_bytes = va.maa_runtime_data(payload)
        claimed = payload["x-ms-sevsnpvm-reportdata"].lower()
        assert len(claimed) == 128
        assert claimed[:64] == hashlib.sha256(runtime_bytes).hexdigest()
        assert set(claimed[64:]) == {"0"}

    def test_runtime_claim_is_an_object_with_sorted_keys(self):
        """MAA re-serialises runtime_data; the sent byte order does not survive.

        This is why attestation_azure.go declares its struct fields
        alphabetically — so the bytes it hashes already equal what is
        reconstructed here.
        """
        rd = _real_payload()["x-ms-runtime"]
        assert isinstance(rd, dict)
        assert list(rd.keys()) == sorted(rd.keys())

    def test_full_verification_passes_against_the_real_token(self, monkeypatch):
        """The end-to-end chain, on hardware-produced evidence."""
        va = _va()
        jwks = json.loads((_FIXTURE_DIR / "maa_real_jwks.json").read_text())
        monkeypatch.setattr(va, "fetch_maa_jwks", lambda _uri: jwks)
        # The fixture token expires; freeze the clock inside its window.
        monkeypatch.setattr(va.time, "time", lambda: _real_payload()["iat"] + 60)
        va.verify_maa_jwt(
            _REAL_TOKEN.encode(),
            _REAL_CERT_DER,
            exporter=_REAL_EXPORTER,
            expect_hostdata=_REAL_HOSTDATA,
            expect_issuer=_REAL_ISSUER,
            nonce_hex=_REAL_NONCE_HEX,
            allow_debug=False,
            require_exporter=True,
        )

    def test_real_token_is_rejected_for_a_different_hostdata(self, monkeypatch):
        """The workload pin must actually bite on real evidence too."""
        va = _va()
        jwks = json.loads((_FIXTURE_DIR / "maa_real_jwks.json").read_text())
        monkeypatch.setattr(va, "fetch_maa_jwks", lambda _uri: jwks)
        monkeypatch.setattr(va.time, "time", lambda: _real_payload()["iat"] + 60)
        with pytest.raises(SystemExit):
            va.verify_maa_jwt(
                _REAL_TOKEN.encode(),
                _REAL_CERT_DER,
                exporter=_REAL_EXPORTER,
                expect_hostdata="ff" * 32,
                expect_issuer=_REAL_ISSUER,
                nonce_hex=_REAL_NONCE_HEX,
                allow_debug=False,
                require_exporter=True,
            )
