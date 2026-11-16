"""Read enclave-owned bootstrap evidence on the same verified Nitro TLS socket."""

from __future__ import annotations

import argparse
import contextlib
import importlib.util
import json
import re
import secrets
import socket
import time
from pathlib import Path
from typing import Any

from tools import aws_eif_manifest

HOST = "api-aws.trustedrouter.com"


def verifier() -> Any:
    spec = importlib.util.spec_from_file_location(
        "aws_bootstrap_attestation_verifier", Path(__file__).with_name("verify-attestation.py")
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("attestation verifier unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def validate_health(body: bytes, policy: str, version: int) -> dict[str, Any]:
    if not 0 < len(body) <= 16 << 10:
        raise ValueError("health response size")
    result = json.loads(body, object_pairs_hook=aws_eif_manifest._unique_object)
    if not isinstance(result, dict) or result.get("status") != "ok":
        raise ValueError("enclave is not healthy")
    evidence = result.get("aws_bootstrap")
    if not isinstance(evidence, dict) or set(evidence) != {"policy", "mode", "bundle_version"}:
        raise ValueError("attested bootstrap evidence missing")
    if evidence["mode"] != "attested" or evidence["policy"] != policy:
        raise ValueError("enclave bootstrap mode/policy mismatch")
    if type(evidence["bundle_version"]) is not int or evidence["bundle_version"] != version:
        raise ValueError("enclave bootstrap version mismatch")
    return evidence


def probe(*, pcr0: str, instance: str, port: int, policy: str, version: int) -> dict[str, Any]:
    if re.fullmatch(r"[0-9a-f]{96}", pcr0) is None or pcr0 == "0" * 96:
        raise ValueError("non-debug CI measurement required")
    if re.fullmatch(r"i-(?:[0-9a-f]{8}|[0-9a-f]{17})", instance) is None:
        raise ValueError("explicit candidate instance required")
    if not 1 <= port <= 65535 or policy not in {"transition", "strict"} or type(version) is not int or not 1 <= version <= (1 << 53) - 1:
        raise ValueError("invalid bootstrap expectation")
    verify = verifier()
    # Trust comes from the Nitro chain and its binding to this exact TLS leaf
    # and session, not the host's CA configuration or a second HTTP connection.
    ctx = verify._new_pyopenssl_context(ca_trust=False)
    nonce = secrets.token_hex(32)
    deadline = time.monotonic() + 30
    with contextlib.closing(socket.create_connection(("127.0.0.1", port), timeout=10)) as raw:
        conn = verify.SSL.Connection(ctx, raw)
        try:
            conn.set_tlsext_host_name(HOST.encode("ascii"))
            conn.set_connect_state()
            verify._ssl_call(raw, conn.do_handshake, timeout=10, what="bootstrap probe handshake")
            verify.assert_tls13(conn, HOST)
            cert = conn.get_peer_certificate()
            if cert is None:
                raise ValueError("missing enclave TLS certificate")
            cert_der = verify.crypto.dump_certificate(verify.crypto.FILETYPE_ASN1, cert)
            verify.assert_cert_matches_hostname(cert_der, HOST)
            exporter = conn.export_keying_material(verify.EXPORTER_LABEL, verify.EXPORTER_LENGTH)
            verify._ssl_send_all(raw, conn, verify._attestation_request(HOST, nonce), deadline=deadline, what="attestation")
            status, _, body = verify._read_http_response(conn, raw, "attestation", deadline=deadline)
            if status.split(" ", 2)[1:2] != ["200"]:
                raise ValueError("attestation HTTP failure")
            verify._require_attestation_body_binds_exporter(body, exporter, nonce, "bootstrap probe", require_exporter=True)
            verify.verify_aws_cbor(body, cert_der, exporter=exporter, expected_pcr0=pcr0, device_blob_sha=None)
            payload, _ = verify.parse_cose_payload(body)
            module_id = payload.get("module_id")
            if not isinstance(module_id, str) or re.fullmatch(re.escape(instance) + r"-enc[0-9a-f]+", module_id) is None:
                raise ValueError("attestation is not from the expected instance")
            verify._ssl_send_all(
                raw, conn, f"GET /health HTTP/1.1\r\nHost: {HOST}\r\nConnection: close\r\n\r\n".encode("ascii"),
                deadline=deadline, what="bootstrap health",
            )
            status, _, body = verify._read_http_response(conn, raw, "bootstrap health", deadline=deadline)
            if status.split(" ", 2)[1:2] != ["200"]:
                raise ValueError("bootstrap health HTTP failure")
            evidence = validate_health(body, policy, version)
            return {"instance": instance, "module_id": module_id, "pcr0": pcr0, "bootstrap": evidence}
        finally:
            with contextlib.suppress(Exception):
                conn.shutdown()
            conn.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--signature", required=True, type=Path)
    parser.add_argument("--expected-source", required=True)
    parser.add_argument("--instance", required=True)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--policy", required=True, choices=("transition", "strict"))
    parser.add_argument("--version", required=True, type=int)
    args = parser.parse_args()
    artifact = aws_eif_manifest.verify(args.manifest, args.signature, expected_source=args.expected_source)
    result = probe(pcr0=artifact["measurements"]["PCR0"], instance=args.instance, port=args.port, policy=args.policy, version=args.version)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
