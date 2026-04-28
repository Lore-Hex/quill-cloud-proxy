"""Outbound HTTP to AWS Bedrock via the parent's vsock-tcp relay.

The enclave can't speak HTTP directly to the internet. The parent runs a
dumb vsock→TCP relay (no inspection of payload). We open a TCP socket via
that relay, do TLS *inside the enclave*, and stream bytes both directions.

We use Bedrock's `InvokeModelWithResponseStream` with model body
identical to native Anthropic Messages — Bedrock unwraps the SSE events
into `{"chunk": {"bytes": <base64>}}` envelopes; we strip that and yield
the raw Anthropic SSE bytes for `adapter.transform_stream` to consume.

V1 leaves the SigV4 + TLS bring-up as a stub; the test path uses an
in-process callable. Production wiring lands in `_bedrock_real.py`.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from typing import Protocol

from quill_enclave.types import AnthropicMessagesRequest


class BedrockClient(Protocol):
    # NB: NOT `async def`. This is the signature of an async-generator
    # *function*, which returns an `AsyncIterator` directly (no coroutine
    # wrapping). Real implementations use `async def invoke_streaming(...)
    # -> AsyncIterator[bytes]: yield ...` which matches.
    def invoke_streaming(self, req: AnthropicMessagesRequest) -> AsyncIterator[bytes]: ...


# Maps OpenAI-friendly names to Bedrock model IDs in us-east-1. Confirm
# against `aws bedrock list-foundation-models --region us-east-1` before
# first deploy.
MODEL_ID_MAP: dict[str, str] = {
    "claude-opus-4-7": "anthropic.claude-opus-4-7-20251101-v1:0",
    "claude-sonnet-4-6": "anthropic.claude-sonnet-4-6-20250901-v1:0",
    "claude-haiku-4-5-20251001": "anthropic.claude-haiku-4-5-20251001-v1:0",
}


def map_model(openai_name: str) -> str:
    if openai_name not in MODEL_ID_MAP:
        # Fail closed: unknown models are rejected at the adapter, not here.
        raise ValueError(f"unknown model {openai_name!r}")
    return MODEL_ID_MAP[openai_name]


def get_client() -> BedrockClient:
    if os.environ.get("QUILL_TRANSPORT") == "unix-socket":
        from quill_enclave._bedrock_mock import MockBedrockClient

        return MockBedrockClient()
    from quill_enclave._bedrock_real import RealBedrockClient

    return RealBedrockClient()


__all__ = ["MODEL_ID_MAP", "BedrockClient", "get_client", "map_model"]
