from __future__ import annotations

import hashlib

from quill_enclave.auth import DeviceRegistry
from quill_enclave.types import DeviceConfig


def _hash(s: str) -> bytes:
    return hashlib.sha256(s.encode("utf-8")).digest()


def test_lookup_hits() -> None:
    bearer = "secret-bearer"
    cfg: DeviceConfig = {
        "key_hash": _hash(bearer).hex(),
        "owner": "alice@example.com",
        "device_id": "q-002",
    }
    reg = DeviceRegistry({_hash(bearer): cfg})
    assert reg.lookup(bearer) == cfg


def test_lookup_misses() -> None:
    cfg: DeviceConfig = {
        "key_hash": _hash("real").hex(),
        "owner": "alice",
        "device_id": "q-002",
    }
    reg = DeviceRegistry({_hash("real"): cfg})
    assert reg.lookup("wrong") is None


def test_replace_swaps_atomically() -> None:
    cfg1: DeviceConfig = {"key_hash": _hash("a").hex(), "owner": "a", "device_id": "q-001"}
    cfg2: DeviceConfig = {"key_hash": _hash("b").hex(), "owner": "b", "device_id": "q-002"}
    reg = DeviceRegistry({_hash("a"): cfg1})
    assert reg.lookup("a") is cfg1
    assert reg.lookup("b") is None
    reg.replace({_hash("b"): cfg2})
    assert reg.lookup("a") is None
    assert reg.lookup("b") is cfg2
