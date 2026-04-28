"""Mock Bedrock client. Yields a canned Anthropic SSE stream so tests
exercise the full adapter pipeline without an AWS account."""

from __future__ import annotations

from collections.abc import AsyncIterator

from quill_enclave.bedrock import BedrockClient
from quill_enclave.types import AnthropicMessagesRequest


def _canned_sse(text: str) -> bytes:
    """Build a minimal but faithful Anthropic SSE stream that says `text`."""
    parts: list[str] = []
    parts.append(
        "event: message_start\n"
        'data: {"type":"message_start","message":{"id":"msg_mock","type":"message",'
        '"role":"assistant","content":[],"model":"claude-opus-4-7","stop_reason":null,'
        '"stop_sequence":null,"usage":{"input_tokens":3,"output_tokens":0}}}\n\n'
    )
    parts.append(
        "event: content_block_start\n"
        'data: {"type":"content_block_start","index":0,'
        '"content_block":{"type":"text","text":""}}\n\n'
    )
    for ch in text:
        parts.append(
            "event: content_block_delta\n"
            f'data: {{"type":"content_block_delta","index":0,'
            f'"delta":{{"type":"text_delta","text":{_json_str(ch)}}}}}\n\n'
        )
    parts.append('event: content_block_stop\ndata: {"type":"content_block_stop","index":0}\n\n')
    parts.append(
        "event: message_delta\n"
        'data: {"type":"message_delta","delta":{"stop_reason":"end_turn",'
        '"stop_sequence":null},"usage":{"output_tokens":' + str(len(text)) + "}}\n\n"
    )
    parts.append('event: message_stop\ndata: {"type":"message_stop"}\n\n')
    return "".join(parts).encode("utf-8")


def _json_str(s: str) -> str:
    """Encode a single character as a JSON string (handles quoting)."""
    import json as _json

    return _json.dumps(s)


class MockBedrockClient(BedrockClient):
    def __init__(self, canned_text: str = "Hello from mock Bedrock") -> None:
        self.canned_text = canned_text

    async def invoke_streaming(self, req: AnthropicMessagesRequest) -> AsyncIterator[bytes]:
        # Pretend to round-trip the request so tests exercise both directions.
        _ = req
        sse = _canned_sse(self.canned_text)
        # Chunk the bytes to simulate streaming.
        chunk_size = 32
        for i in range(0, len(sse), chunk_size):
            yield sse[i : i + chunk_size]
