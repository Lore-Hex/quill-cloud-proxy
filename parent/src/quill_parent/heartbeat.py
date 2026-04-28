"""Hourly heartbeat: emits exactly one log line per hour with the total
request count across all devices. No per-device data, no per-request data.

This is the ONLY application log line the parent ever emits in steady
state. The CI test asserts this is the only call to `log.info` with
counter-shaped fields.
"""

from __future__ import annotations

import asyncio
import threading
from typing import Any

from quill_parent.logging import get_logger

log = get_logger(__name__)


class Heartbeat:
    """Thread-safe accumulator. Increment on every request; flush once per interval."""

    def __init__(self, interval_seconds: int) -> None:
        self._lock = threading.Lock()
        self._interval = interval_seconds
        self._requests = 0
        self._errors = 0

    def record(self, *, ok: bool) -> None:
        with self._lock:
            self._requests += 1
            if not ok:
                self._errors += 1

    def _drain(self) -> tuple[int, int]:
        with self._lock:
            req, err = self._requests, self._errors
            self._requests = 0
            self._errors = 0
            return req, err

    async def run(self) -> None:
        while True:
            await asyncio.sleep(self._interval)
            req, err = self._drain()
            # Aggregate-only. No device id, no key hash, no per-request anything.
            log.info("quill.heartbeat", requests=req, errors=err)


def emit_startup(version: str, git_commit: str) -> None:
    """One-shot startup line. Aggregate-only metadata."""
    extra: dict[str, Any] = {"version": version, "git_commit": git_commit}
    log.info("quill.startup", **extra)
