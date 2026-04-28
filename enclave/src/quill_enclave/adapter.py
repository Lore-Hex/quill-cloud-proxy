"""OpenAI Chat Completions ↔ Anthropic Messages adapter.

Same translation as `quill-device/src/quill_device/adapters/openai_chat.py`.
Bedrock's `InvokeModelWithResponseStream` returns events whose body is
**identical** to native Anthropic SSE event payloads, just wrapped in a
`{"chunk": {"bytes": <base64>}}` envelope. So we unwrap once in
`bedrock.py`, then this module's transform is reused verbatim.

No I/O in this module. Pure translation.
"""

from __future__ import annotations

import json
import time
import uuid
from collections.abc import AsyncIterator
from typing import Final

from quill_enclave.types import (
    AnthropicMessage,
    AnthropicMessagesRequest,
    OpenAIChatChunk,
    OpenAIChatChunkChoice,
    OpenAIChatChunkDelta,
    OpenAIChatMessage,
    OpenAIChatRequest,
)

_DONE_LINE: Final[bytes] = b"data: [DONE]\n\n"


class AdapterError(Exception):
    """Raised when an inbound OpenAI request can't be translated to Anthropic."""

    def __init__(self, status_code: int, message: str) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.message = message


def to_anthropic_request(
    req: OpenAIChatRequest,
    *,
    default_model: str,
    default_max_tokens: int,
) -> AnthropicMessagesRequest:
    messages_field = req.get("messages")
    if not messages_field:
        raise AdapterError(400, "messages must contain at least one entry")

    system_parts: list[str] = []
    out_messages: list[AnthropicMessage] = []
    for msg in messages_field:
        role = msg.get("role")
        content = msg.get("content")
        if content is None:
            continue
        if role == "system":
            system_parts.append(content)
            continue
        if role not in ("user", "assistant"):
            raise AdapterError(400, f"unsupported role: {role!r}")
        out_messages.append(AnthropicMessage(role=role, content=content))

    if not out_messages:
        raise AdapterError(400, "messages must contain a user/assistant turn")

    out: AnthropicMessagesRequest = {
        "model": req.get("model", default_model),
        "messages": out_messages,
        "max_tokens": int(req.get("max_tokens", default_max_tokens)),
        "stream": bool(req.get("stream", False)),
        # Bedrock requires this on the body, not the envelope.
        "anthropic_version": "bedrock-2023-05-31",
    }
    if system_parts:
        out["system"] = "\n\n".join(system_parts)
    if "temperature" in req:
        out["temperature"] = float(req["temperature"])
    if "top_p" in req:
        out["top_p"] = float(req["top_p"])
    if "stop" in req:
        stop = req["stop"]
        out["stop_sequences"] = [stop] if isinstance(stop, str) else list(stop)
    return out


# ---- streaming transform ----------------------------------------------------


async def _parse_anthropic_events(
    raw: AsyncIterator[bytes],
) -> AsyncIterator[tuple[str, dict[str, object]]]:
    """Yield (event_name, parsed_json) tuples from Anthropic-style SSE bytes.

    Anthropic's streaming format (matches what Bedrock unwraps to):
        event: <name>
        data: {<json>}\n\n
    """
    buffer: bytes = b""
    async for chunk in raw:
        buffer += chunk
        while b"\n\n" in buffer:
            block, _, buffer = buffer.partition(b"\n\n")
            event_name = ""
            data_lines: list[str] = []
            for line in block.split(b"\n"):
                if line.startswith(b"event: "):
                    event_name = line[7:].decode("utf-8", errors="replace").strip()
                elif line.startswith(b"data: "):
                    data_lines.append(line[6:].decode("utf-8", errors="replace"))
            if not data_lines:
                continue
            try:
                parsed = json.loads("\n".join(data_lines))
            except json.JSONDecodeError:
                continue
            if isinstance(parsed, dict):
                yield event_name, parsed


def _make_chunk(
    *,
    request_id: str,
    created: int,
    model: str,
    delta: OpenAIChatChunkDelta,
    finish_reason: str | None,
) -> bytes:
    chunk: OpenAIChatChunk = {
        "id": request_id,
        "object": "chat.completion.chunk",
        "created": created,
        "model": model,
        "choices": [
            OpenAIChatChunkChoice(index=0, delta=delta, finish_reason=finish_reason),
        ],
    }
    return f"data: {json.dumps(chunk, separators=(',', ':'))}\n\n".encode()


def _map_stop_reason(anthropic_reason: str) -> str:
    return {
        "end_turn": "stop",
        "stop_sequence": "stop",
        "max_tokens": "length",
        "tool_use": "tool_calls",
    }.get(anthropic_reason, "stop")


async def transform_stream(
    anthropic_sse: AsyncIterator[bytes],
    *,
    request_id: str,
    model: str,
) -> AsyncIterator[bytes]:
    created = int(time.time())
    finish_reason: str = "stop"
    role_sent = False
    async for event_name, data in _parse_anthropic_events(anthropic_sse):
        if event_name == "content_block_delta":
            delta_field = data.get("delta")
            if not isinstance(delta_field, dict):
                continue
            if delta_field.get("type") != "text_delta":
                continue
            text = delta_field.get("text")
            if not isinstance(text, str) or not text:
                continue
            if not role_sent:
                yield _make_chunk(
                    request_id=request_id,
                    created=created,
                    model=model,
                    delta={"role": "assistant", "content": ""},
                    finish_reason=None,
                )
                role_sent = True
            yield _make_chunk(
                request_id=request_id,
                created=created,
                model=model,
                delta={"content": text},
                finish_reason=None,
            )
        elif event_name == "message_delta":
            delta_field = data.get("delta")
            if isinstance(delta_field, dict):
                stop_reason = delta_field.get("stop_reason")
                if isinstance(stop_reason, str):
                    finish_reason = _map_stop_reason(stop_reason)
        elif event_name == "message_stop":
            yield _make_chunk(
                request_id=request_id,
                created=created,
                model=model,
                delta={},
                finish_reason=finish_reason,
            )
            yield _DONE_LINE
            return
    yield _make_chunk(
        request_id=request_id,
        created=created,
        model=model,
        delta={},
        finish_reason=finish_reason,
    )
    yield _DONE_LINE


def new_request_id() -> str:
    return f"chatcmpl-{uuid.uuid4().hex}"


__all__ = [
    "AdapterError",
    "OpenAIChatMessage",
    "OpenAIChatRequest",
    "new_request_id",
    "to_anthropic_request",
    "transform_stream",
]
