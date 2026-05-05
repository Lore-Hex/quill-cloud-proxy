"""Vsock relay: parent → enclave → parent.

The parent reconstructs a minimal HTTP request with the original route path,
body, and bearer, sends it over a vsock connection to
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
from typing import NamedTuple

from quill_parent.config import Settings
from quill_parent.heartbeat import Heartbeat


def _build_http_request(body: bytes, bearer: str, route_path: str) -> bytes:
    """Wrap (body, bearer) in a minimal HTTP/1.1 POST. Bytes only — no inspection."""
    head = (
        f"POST {route_path} HTTP/1.1\r\n"
        f"Host: enclave\r\n"
        f"Authorization: {bearer}\r\n"
        f"Content-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode("ascii", errors="replace")
    return head + body


class RelayResponse(NamedTuple):
    status_code: int
    content_type: str
    chunks: AsyncIterator[bytes]


async def _single_chunk(body: bytes) -> AsyncIterator[bytes]:
    yield body


def _parse_status_code(head: bytes) -> int:
    status_line = head.split(b"\r\n", 1)[0]
    parts = status_line.split()
    if len(parts) < 2:
        return 502
    try:
        return int(parts[1])
    except ValueError:
        return 502


def _parse_content_type(head: bytes) -> str:
    for raw in head.split(b"\r\n")[1:]:
        name, sep, value = raw.partition(b":")
        if sep and name.lower() == b"content-type":
            parsed = value.strip().decode("ascii", errors="replace")
            return parsed or "application/json"
    return "application/json"


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
    *, body: bytes, bearer: str, settings: Settings, heartbeat: Heartbeat, route_path: str
) -> AsyncIterator[bytes]:
    """Send the HTTP-wrapped request, stream the response, never inspect bytes."""
    response = await relay_to_enclave_response(
        body=body, bearer=bearer, settings=settings, heartbeat=heartbeat, route_path=route_path
    )
    async for chunk in response.chunks:
        yield chunk


async def relay_to_enclave_response(
    *, body: bytes, bearer: str, settings: Settings, heartbeat: Heartbeat, route_path: str
) -> RelayResponse:
    """Open the enclave relay and return its HTTP status plus body stream.

    This still treats request/response bodies as opaque bytes. The parent only
    parses the enclave's HTTP status line and header boundary so client-visible
    failures do not get flattened into 200 responses.
    """
    sock = await _connect_enclave(settings)
    sock.setblocking(False)
    loop = asyncio.get_event_loop()
    try:
        await loop.sock_sendall(sock, _build_http_request(body, bearer, route_path))
        # Read until the connection closes. Skip the response status line +
        # headers in a single linear pass without any field-level parsing
        # beyond `\r\n\r\n` boundary.
        head_buf = bytearray()
        while b"\r\n\r\n" not in head_buf:
            chunk = await loop.sock_recv(sock, 4096)
            if not chunk:
                heartbeat.record(ok=False)
                sock.close()
                return RelayResponse(
                    502,
                    "application/json",
                    _single_chunk(
                        b'{"error":{"status":502,"message":"enclave closed before headers"}}'
                    ),
                )
            head_buf.extend(chunk)
        head, _, leftover = bytes(head_buf).partition(b"\r\n\r\n")
        status_code = _parse_status_code(head)
        content_type = _parse_content_type(head)

        async def iter_body() -> AsyncIterator[bytes]:
            try:
                if leftover:
                    yield leftover
                while True:
                    chunk = await loop.sock_recv(sock, 4096)
                    if not chunk:
                        break
                    yield chunk
                heartbeat.record(ok=status_code < 500)
            finally:
                try:
                    sock.close()
                except OSError:
                    return

        return RelayResponse(status_code, content_type, iter_body())
    except Exception:
        sock.close()
        raise
