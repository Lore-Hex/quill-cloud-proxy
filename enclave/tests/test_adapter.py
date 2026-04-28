from __future__ import annotations

import pytest

from quill_enclave.adapter import AdapterError, to_anthropic_request
from quill_enclave.types import OpenAIChatRequest


def _req(**kwargs: object) -> OpenAIChatRequest:
    base: dict[str, object] = {
        "model": "claude-opus-4-7",
        "messages": [{"role": "user", "content": "hi"}],
    }
    base.update(kwargs)
    return base  # type: ignore[return-value]  # TypedDict accepts dict at runtime


def test_system_collapses() -> None:
    out = to_anthropic_request(
        _req(
            messages=[{"role": "system", "content": "be terse"}, {"role": "user", "content": "hi"}]
        ),
        default_model="x",
        default_max_tokens=4096,
    )
    assert out["system"] == "be terse"
    assert out["messages"] == [{"role": "user", "content": "hi"}]
    assert out["anthropic_version"] == "bedrock-2023-05-31"


def test_max_tokens_default() -> None:
    out = to_anthropic_request(_req(), default_model="x", default_max_tokens=4096)
    assert out["max_tokens"] == 4096


def test_max_tokens_passthrough() -> None:
    out = to_anthropic_request(_req(max_tokens=200), default_model="x", default_max_tokens=4096)
    assert out["max_tokens"] == 200


def test_stop_string_becomes_list() -> None:
    out = to_anthropic_request(_req(stop="STOP"), default_model="x", default_max_tokens=100)
    assert out["stop_sequences"] == ["STOP"]


def test_empty_messages_rejected() -> None:
    with pytest.raises(AdapterError) as exc_info:
        to_anthropic_request(_req(messages=[]), default_model="x", default_max_tokens=100)
    assert exc_info.value.status_code == 400


def test_only_system_rejected() -> None:
    with pytest.raises(AdapterError) as exc_info:
        to_anthropic_request(
            _req(messages=[{"role": "system", "content": "x"}]),
            default_model="x",
            default_max_tokens=100,
        )
    assert exc_info.value.status_code == 400


def test_unsupported_role_rejected() -> None:
    with pytest.raises(AdapterError) as exc_info:
        to_anthropic_request(
            _req(messages=[{"role": "tool", "content": "x"}]),
            default_model="x",
            default_max_tokens=100,
        )
    assert exc_info.value.status_code == 400
