"""Typed data shapes used across the enclave.

Deliberately small. No Pydantic in the enclave — every dependency expands
the measurement. Hand-validate at parse points.
"""

from __future__ import annotations

from typing import Literal, TypedDict


class DeviceConfig(TypedDict):
    key_hash: str  # hex SHA-256 of the bearer
    owner: str  # human-readable identifier (e.g. email)
    device_id: str  # opaque ID, used as DynamoDB partition key


class CounterDelta(TypedDict):
    """Sent over vsock to parent after a request completes.

    Aggregate-only. No prompt content, no completion content, no per-request
    timestamp. Parent batches these into a DynamoDB UpdateItem.
    """

    device_id: str
    d_requests: int
    d_input_tokens: int
    d_output_tokens: int
    d_errors: int


# Subset of the OpenAI Chat Completions request shape we accept.
# total=False because the body comes from arbitrary client JSON; we
# defensively check missing fields at runtime in the adapter.
class OpenAIChatMessage(TypedDict, total=False):
    role: Literal["system", "user", "assistant"]
    content: str


class OpenAIChatRequest(TypedDict, total=False):
    model: str
    messages: list[OpenAIChatMessage]
    stream: bool
    temperature: float
    top_p: float
    max_tokens: int
    stop: str | list[str]


class AnthropicMessage(TypedDict):
    role: Literal["user", "assistant"]
    content: str


class AnthropicMessagesRequest(TypedDict, total=False):
    model: str
    messages: list[AnthropicMessage]
    system: str
    max_tokens: int
    temperature: float
    top_p: float
    stop_sequences: list[str]
    stream: bool
    anthropic_version: str  # required by Bedrock


class OpenAIChatChunkDelta(TypedDict, total=False):
    role: Literal["assistant"]
    content: str


class OpenAIChatChunkChoice(TypedDict):
    index: int
    delta: OpenAIChatChunkDelta
    finish_reason: str | None


class OpenAIChatChunk(TypedDict):
    id: str
    object: Literal["chat.completion.chunk"]
    created: int
    model: str
    choices: list[OpenAIChatChunkChoice]
