"""Raw TCP pump from the NLB to the enclave's vsock listener.

This module accepts a raw TCP connection from the NLB and pumps bytes
bidirectionally to the enclave over vsock: no parsing, no header rewrite,
no auth check. The enclave terminates TLS on its side; everything in
between is opaque ciphertext.

Where it sits:
  client ──TLS bytes──► NLB :443 (TCP passthrough)
                          ─► parent:8444 (this module)
                              ─► vsock :8001 to enclave (TLS terminator)

The FastAPI listener (main.py) keeps running for /admin/usage, /trust,
/health only; it has no inference routes and does not see prompt content.

Set QUILL_TCP_PUMP=true on the parent to start this listener. Production
prompt traffic must point at this TCP pump so TLS terminates inside the
enclave.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import socket
from typing import Final

from quill_parent.config import Settings
from quill_parent.logging import get_logger

log = get_logger(__name__)

# Separate from the FastAPI admin/trust listener. This port receives only
# raw TLS bytes destined for the enclave.
TCP_PUMP_PORT: Final[int] = 8444
AF_VSOCK: Final[int] = 40
ENCLAVE_CID: Final[int] = 16


async def _open_vsock_pair(
    settings: Settings,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Open a connection to the enclave and return both halves of the
    asyncio stream. AF_UNIX in dev (laptop), AF_VSOCK in production."""
    if settings.use_dev_transport:
        return await asyncio.open_unix_connection(
            f"/tmp/quill-enclave-{settings.enclave_relay_port}.sock"
        )
    raw = socket.socket(AF_VSOCK, socket.SOCK_STREAM)
    raw.setblocking(False)
    await asyncio.get_event_loop().sock_connect(raw, (ENCLAVE_CID, settings.enclave_relay_port))
    return await asyncio.open_connection(sock=raw)


async def _pump(src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> None:
    """Copy bytes from src to dst until EOF. No buffering, no inspection."""
    try:
        while True:
            chunk = await src.read(16 * 1024)
            if not chunk:
                break
            dst.write(chunk)
            await dst.drain()
    except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError):
        # Both directions surface the same way; nothing to log per-conn
        # because the parent never sees per-request payload data.
        pass
    finally:
        with contextlib.suppress(OSError, RuntimeError):
            dst.write_eof()


async def _handle_client(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    settings: Settings,
) -> None:
    try:
        enclave_reader, enclave_writer = await _open_vsock_pair(settings)
    except Exception as exc:
        log.exception("tcp_pump.connect_enclave_failed", err=type(exc).__name__)
        client_writer.close()
        return

    try:
        c2e = asyncio.create_task(_pump(client_reader, enclave_writer))
        e2c = asyncio.create_task(_pump(enclave_reader, client_writer))
        _, pending = await asyncio.wait({c2e, e2c}, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
    finally:
        for w in (client_writer, enclave_writer):
            with contextlib.suppress(OSError, RuntimeError):
                w.close()


async def serve_forever(settings: Settings) -> None:
    """Bind 0.0.0.0:TCP_PUMP_PORT and serve raw connections.

    The NLB is fronting this listener; its security group + private subnet
    placement is what scopes who can reach it. No auth check here — every
    connection gets pumped, and the enclave's TLS handshake is the first
    gate. Mis-pointed clients fail TLS and disconnect at the enclave.
    """
    server = await asyncio.start_server(
        lambda r, w: _handle_client(r, w, settings),
        host="0.0.0.0",
        port=TCP_PUMP_PORT,
    )
    log.info("tcp_pump.listening", port=TCP_PUMP_PORT)
    async with server:
        await server.serve_forever()


def is_enabled() -> bool:
    """Whether to run the production inference TCP pump."""
    return os.environ.get("QUILL_TCP_PUMP", "false").lower() == "true"
