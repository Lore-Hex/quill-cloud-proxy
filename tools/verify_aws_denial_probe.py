"""Authenticate public evidence from the isolated, non-serving KMS denial probe."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import time
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_der_public_key

from tools import aws_bootstrap_probe, aws_eif_manifest

PROTOCOL = b"trustedrouter.aws-bootstrap.denial-probe.v1"


def verify(body: bytes, *, instance: str, nonce: bytes, measurements: dict[str, str],
           accepted: list[str], debug: bool, now: float | None = None) -> dict[str, Any]:
    if re.fullmatch(r"i-(?:[0-9a-f]{8}|[0-9a-f]{17})", instance) is None or len(nonce) != 32:
        raise ValueError("explicit instance and fresh 32-byte challenge required")
    if not accepted or len(accepted) > 16 or any(re.fullmatch(r"[0-9a-f]{96}", p) is None or p == "0" * 96 for p in accepted):
        raise ValueError("explicit non-debug production admission required")
    expected: dict[int, bytes] = {}
    for index in (0, 1, 2):
        value = measurements.get(f"PCR{index}")
        if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{96}", value) is None or value == "0" * 96:
            raise ValueError("record the test EIF measurements before boot")
        expected[index] = bytes(48) if debug else bytes.fromhex(value)
    if measurements["PCR0"] in accepted:
        raise ValueError("never use an admitted image for this denial probe")
    if not 0 < len(body) <= 32 << 10:
        raise ValueError("probe evidence size")
    record = json.loads(body, object_pairs_hook=aws_eif_manifest._unique_object)
    if not isinstance(record, dict) or set(record) != {"attestation_document", "public_key", "nonce", "protocol"}:
        raise ValueError("probe evidence fields")
    if record["protocol"] != PROTOCOL.decode("ascii"):
        raise ValueError("probe protocol mismatch")
    try:
        document = base64.b64decode(record["attestation_document"], validate=True)
        public_der = base64.b64decode(record["public_key"], validate=True)
        challenge = base64.b64decode(record["nonce"], validate=True)
    except (ValueError, TypeError) as exc:
        raise ValueError("probe evidence encoding") from exc
    if not 0 < len(document) <= 16 << 10 or not 0 < len(public_der) <= 1024 or challenge != nonce:
        raise ValueError("probe evidence bounds or challenge")
    public = load_der_public_key(public_der)
    if not isinstance(public, rsa.RSAPublicKey) or public.key_size != 2048 or public.public_numbers().e != 65537:
        raise ValueError("probe must bind a 2048-bit RSA recipient")
    verifier = aws_bootstrap_probe.verifier()
    verifier.verify_cose_signature(document)
    payload, _ = verifier.parse_cose_payload(document)
    module = payload.get("module_id")
    if not isinstance(module, str) or re.fullmatch(re.escape(instance) + r"-enc[0-9a-f]+", module) is None:
        raise ValueError("wrong probe instance")
    if payload.get("nonce") != nonce or payload.get("public_key") != public_der or payload.get("user_data") != PROTOCOL:
        raise ValueError("signed probe binding mismatch")
    stamp = payload.get("timestamp")
    current = time.time() if now is None else now
    if type(stamp) is not int or not -30 <= current - stamp / 1000 <= 120:
        raise ValueError("probe evidence is not fresh")
    pcrs = payload.get("pcrs")
    if not isinstance(pcrs, dict) or any(pcrs.get(index) != value for index, value in expected.items()):
        raise ValueError("probe measurement mismatch")
    return {
        "instance": instance, "module_id": module, "mode": "debug" if debug else "unpublished",
        "pcr0": expected[0].hex(), "timestamp_ms": stamp,
        "public_key_sha256": hashlib.sha256(public_der).hexdigest(),
        "document_sha256": hashlib.sha256(document).hexdigest(),
        "scope": "authenticated test evidence only; not a KMS denial result",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--measurements", type=Path, required=True)
    parser.add_argument("--instance", required=True)
    parser.add_argument("--nonce", required=True)
    parser.add_argument("--accepted-pcr0", action="append", required=True)
    parser.add_argument("--mode", choices=("debug", "unpublished"), required=True)
    args = parser.parse_args()
    measurements = json.loads(aws_eif_manifest._read_bytes(args.measurements, 16 << 10))
    result = verify(
        aws_eif_manifest._read_bytes(args.evidence, 32 << 10), instance=args.instance,
        nonce=bytes.fromhex(args.nonce), measurements=measurements["Measurements"],
        accepted=args.accepted_pcr0, debug=args.mode == "debug",
    )
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
