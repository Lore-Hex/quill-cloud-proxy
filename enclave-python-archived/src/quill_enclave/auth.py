"""Bearer-hash → DeviceConfig lookup.

The device list is a frozen `dict[bytes, DeviceConfig]` loaded once at
enclave boot from the KMS-attested-decrypt of the sealed blob (see
`attest.py`). It's then swapped atomically by `refresh_device_list()` when
the parent reports a new blob etag (every 60s polling).

No I/O in this module. The map is in-memory only.
"""

from __future__ import annotations

import hashlib
import hmac
import threading

from quill_enclave.types import DeviceConfig


class DeviceRegistry:
    """Thread-safe holder of the active device map. Swap-on-write."""

    def __init__(self, devices: dict[bytes, DeviceConfig]) -> None:
        self._lock = threading.RLock()
        self._devices: dict[bytes, DeviceConfig] = devices

    def lookup(self, bearer: str) -> DeviceConfig | None:
        """Hash the bearer, return the device config if known, else None.

        Uses a constant-time compare loop to avoid timing-side-channel
        leakage of which prefix matched (mostly theatre at this scale, but
        free).
        """
        digest = _hash_bearer(bearer)
        with self._lock:
            for stored_hash, cfg in self._devices.items():
                if hmac.compare_digest(digest, stored_hash):
                    return cfg
        return None

    def replace(self, devices: dict[bytes, DeviceConfig]) -> None:
        """Atomically swap the device map (called when the sealed blob updates)."""
        with self._lock:
            self._devices = devices

    def device_ids(self) -> list[str]:
        with self._lock:
            return [cfg["device_id"] for cfg in self._devices.values()]


def _hash_bearer(bearer: str) -> bytes:
    return hashlib.sha256(bearer.encode("utf-8")).digest()
