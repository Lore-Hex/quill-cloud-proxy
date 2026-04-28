from __future__ import annotations

import json

import pytest

from quill_enclave.attest import AttestationError, parse_device_blob


def _hex(s: str) -> str:
    import hashlib

    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def test_parse_two_devices() -> None:
    blob = json.dumps(
        [
            {"key_hash": _hex("a"), "owner": "alice@x", "device_id": "q-001"},
            {"key_hash": _hex("b"), "owner": "bob@x", "device_id": "q-002"},
        ]
    ).encode("utf-8")
    out = parse_device_blob(blob)
    assert len(out) == 2
    assert all(isinstance(k, bytes) and len(k) == 32 for k in out)


def test_parse_invalid_json() -> None:
    with pytest.raises(AttestationError):
        parse_device_blob(b"not json {{")


def test_parse_must_be_array() -> None:
    with pytest.raises(AttestationError):
        parse_device_blob(b'{"foo":"bar"}')


def test_parse_rejects_short_hash() -> None:
    with pytest.raises(AttestationError):
        parse_device_blob(
            json.dumps([{"key_hash": "abc", "owner": "x", "device_id": "y"}]).encode()
        )


def test_parse_rejects_non_hex_hash() -> None:
    with pytest.raises(AttestationError):
        parse_device_blob(
            json.dumps([{"key_hash": "Z" * 64, "owner": "x", "device_id": "y"}]).encode()
        )
