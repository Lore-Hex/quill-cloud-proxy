"""Vsock relay: parent → enclave → parent.

The parent reconstructs a minimal HTTP request (POST /v1/chat/completions
with the original body and bearer), sends it over a vsock connection to
the enclave, and streams back the chunked response bytes verbatim. The
parent does NOT decode the request body or the response body; it's purely
a protocol bridge.

Why not a custom binary protocol? Because the enclave's HTTP parser is
already small and well-scoped, and reusing it means one less surface to
audit for "is this protocol parser zero-leak."
"""

from __future__ import annotations

import asyncio
import socket
from collections.abc import AsyncIterator

from quill_parent.config import Settings
from quill_parent.heartbeat import Heartbeat


def _build_http_request(body: bytes, bearer: str) -> bytes:
    """Wrap (body, bearer) in a minimal HTTP/1.1 POST. Bytes only — no inspection."""
    head = (
        f"POST /v1/chat/completions HTTP/1.1\r\n"
        f"Host: enclave\r\n"
        f"Authorization: {bearer}\r\n"
        f"Content-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode("ascii", errors="replace")
    return head + body


async def _connect_enclave(settings: Settings) -> socket.socket:
    """Open a connection to the enclave's vsock listener.

    In production: AF_VSOCK to (CID_ANY=enclave-cid, port).
    In dev: AF_UNIX to /tmp/quill-enclave-<port>.sock so a laptop can run
    the same path without a Nitro host.
    """
    if settings.use_dev_transport:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        await asyncio.get_event_loop().sock_connect(
            s, f"/tmp/quill-enclave-{settings.enclave_relay_port}.sock"
        )
        return s
    # AF_VSOCK / VMADDR_CID_ANY pairing — Linux-only, Nitro-only.
    af_vsock = 40
    s = socket.socket(af_vsock, socket.SOCK_STREAM)
    # The enclave's CID is known from the nitro-cli describe-enclaves call,
    # injected via env at deploy time. For V1 we assume CID 16 (the default
    # for a single enclave on the host); document in the deployment README.
    enclave_cid = 16
    await asyncio.get_event_loop().sock_connect(s, (enclave_cid, settings.enclave_relay_port))
    return s


async def relay_to_enclave(
    *, body: bytes, bearer: str, settings: Settings, heartbeat: Heartbeat
) -> AsyncIterator[bytes]:
    """Send the HTTP-wrapped request, stream the response, never inspect bytes."""
    sock = await _connect_enclave(settings)
    sock.setblocking(False)
    loop = asyncio.get_event_loop()
    try:
        await loop.sock_sendall(sock, _build_http_request(body, bearer))
        # Read until the connection closes. Skip the response status line +
        # headers in a single linear pass without any field-level parsing
        # beyond `\r\n\r\n` boundary.
        head_buf = bytearray()
        while b"\r\n\r\n" not in head_buf:
            chunk = await loop.sock_recv(sock, 4096)
            if not chunk:
                heartbeat.record(ok=False)
                return
            head_buf.extend(chunk)
        _, _, leftover = bytes(head_buf).partition(b"\r\n\r\n")
        if leftover:
            yield leftover
        while True:
            chunk = await loop.sock_recv(sock, 4096)
            if not chunk:
                break
            yield chunk
        heartbeat.record(ok=True)
    finally:
        try:
            sock.close()
        except OSError:
            # nothing to do; socket is best-effort closed
            return
