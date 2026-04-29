"""Enclave entrypoint.

Listens on a vsock port for inbound HTTP from the parent's TLS-terminating
relay. Parses the OpenAI request, hashes the bearer, looks up the device,
calls Bedrock via the parent's outbound vsock relay, streams the response
back.

NO logging. NO disk writes. NO network except vsock.

The CI test `tests/test_no_io.py` AST-walks every file under `quill_enclave`
and fails if any forbidden identifier appears (print/log/open/sys.stdout/
sys.stderr/etc.).

Only invoked from `python -m quill_enclave.main` inside the EIF; tests
import individual functions and invoke them directly.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import socket
from collections.abc import AsyncIterator
from typing import cast

from quill_enclave.adapter import (
    AdapterError,
    new_request_id,
    to_anthropic_request,
    transform_stream,
)
from quill_enclave.attest import get_provider, parse_device_blob
from quill_enclave.auth import DeviceRegistry
from quill_enclave.bedrock import get_client, map_model
from quill_enclave.transport import PORT_PARENT_RELAY, listen_inbound
from quill_enclave.types import OpenAIChatRequest

DEFAULT_MODEL = "claude-opus-4-7"
DEFAULT_MAX_TOKENS = 4096


async def boot() -> DeviceRegistry:
    """Load the sealed device blob via attested KMS decrypt."""
    provider = get_provider()
    doc = provider.attestation_document()
    # The parent fetches the ciphertext from S3 and hands it to the enclave;
    # for V1 boot, we have a vsock RPC to the parent for that. In test mode
    # the mock provider returns plaintext directly when QUILL_MOCK_BLOB_PATH
    # is set.
    plaintext = provider.kms_decrypt(b"", doc)
    devices = parse_device_blob(plaintext)
    return DeviceRegistry(devices)


async def handle_chat(
    body: bytes,
    bearer: str,
    registry: DeviceRegistry,
) -> tuple[int, AsyncIterator[bytes]]:
    """Process one /v1/chat/completions request. Returns (status, body_iter)."""
    device = registry.lookup(bearer)
    if device is None:
        return 401, _single_chunk(_error_json(401, "Invalid API key"))

    try:
        raw = json.loads(body)
    except json.JSONDecodeError as exc:
        return 400, _single_chunk(_error_json(400, f"invalid JSON: {exc}"))

    if not isinstance(raw, dict):
        return 400, _single_chunk(_error_json(400, "request body must be a JSON object"))
    # The TypedDict shape is loose (total=False), so the cast is safe at this
    # boundary; to_anthropic_request validates required fields itself.
    req = cast("OpenAIChatRequest", raw)

    try:
        anthro_req = to_anthropic_request(
            req, default_model=DEFAULT_MODEL, default_max_tokens=DEFAULT_MAX_TOKENS
        )
    except AdapterError as exc:
        return exc.status_code, _single_chunk(_error_json(exc.status_code, exc.message))

    # Translate the human-friendly model to the Bedrock model ID.
    try:
        anthro_req["model"] = map_model(anthro_req["model"])
    except ValueError as exc:
        return 400, _single_chunk(_error_json(400, str(exc)))

    request_id = new_request_id()
    client = get_client()
    sse_bytes = client.invoke_streaming(anthro_req)
    out_stream = transform_stream(
        sse_bytes, request_id=request_id, model=req.get("model", DEFAULT_MODEL)
    )

    # NB: we deliberately do NOT increment counters here. The parent does
    # that after the stream terminates, so the enclave never holds counter
    # state. (Counters are still aggregate, but keeping them in the parent
    # keeps the enclave purely stateless w.r.t. accounting.)
    return 200, out_stream


def _error_json(status: int, message: str) -> bytes:
    payload = {"error": {"status": status, "message": message}}
    return json.dumps(payload).encode("utf-8")


async def _single_chunk(body: bytes) -> AsyncIterator[bytes]:
    yield body


async def serve(registry: DeviceRegistry) -> None:
    """Accept connections on the inbound vsock port and dispatch."""
    listener = listen_inbound(PORT_PARENT_RELAY)
    listener.setblocking(False)
    loop = asyncio.get_event_loop()
    # Hold strong refs so tasks aren't GC'd mid-flight (RUF006).
    tasks: set[asyncio.Task[None]] = set()
    while True:
        client_sock, _addr = await loop.sock_accept(listener)
        client_sock.setblocking(False)
        task = asyncio.create_task(_serve_one(client_sock, registry))
        tasks.add(task)
        task.add_done_callback(tasks.discard)


async def _serve_one(client: socket.socket, registry: DeviceRegistry) -> None:
    try:
        bearer, body = await _read_request(client)
        status, body_iter = await handle_chat(body, bearer, registry)
        await _write_response(client, status, body_iter)
    finally:
        with contextlib.suppress(OSError):
            client.close()


async def _read_request(client: socket.socket) -> tuple[str, bytes]:
    """Read the full HTTP request from the client socket. Returns (bearer, body).

    Minimal HTTP parser: looks for the headers/body split, finds
    `Authorization: Bearer ...` and uses Content-Length to read the body.
    Streaming-vs-non-streaming is handled by the OpenAI request body, not
    transfer-encoding here.
    """
    loop = asyncio.get_event_loop()
    buf = bytearray()
    while b"\r\n\r\n" not in buf:
        chunk = await loop.sock_recv(client, 4096)
        if not chunk:
            return "", b""
        buf.extend(chunk)

    head, _, rest = bytes(buf).partition(b"\r\n\r\n")
    headers = {}
    for line in head.split(b"\r\n")[1:]:
        if b": " in line:
            k, _, v = line.partition(b": ")
            headers[k.decode("ascii", errors="replace").lower()] = v.decode(
                "utf-8", errors="replace"
            )

    content_length = int(headers.get("content-length", "0") or "0")
    body = bytearray(rest)
    while len(body) < content_length:
        chunk = await loop.sock_recv(client, 4096)
        if not chunk:
            break
        body.extend(chunk)

    auth = headers.get("authorization", "")
    bearer = auth[7:] if auth.lower().startswith("bearer ") else ""
    return bearer, bytes(body)


async def _write_response(
    client: socket.socket, status: int, body_iter: AsyncIterator[bytes]
) -> None:
    loop = asyncio.get_event_loop()
    status_text = {200: "OK", 400: "Bad Request", 401: "Unauthorized"}.get(status, "Error")
    head = (
        f"HTTP/1.1 {status} {status_text}\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Content-Type: text/event-stream\r\n"
        "Cache-Control: no-cache\r\n"
        "X-Accel-Buffering: no\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii")
    await loop.sock_sendall(client, head)
    async for chunk in body_iter:
        if not chunk:
            continue
        framed = f"{len(chunk):x}\r\n".encode("ascii") + chunk + b"\r\n"
        await loop.sock_sendall(client, framed)
    await loop.sock_sendall(client, b"0\r\n\r\n")


async def amain() -> None:
    registry = await boot()
    await serve(registry)


def main() -> None:
    asyncio.run(amain())


if __name__ == "__main__":
    main()
