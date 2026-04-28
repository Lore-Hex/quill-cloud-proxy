from __future__ import annotations

import json
import os

from quill_enclave._bedrock_mock import MockBedrockClient
from quill_enclave.adapter import new_request_id, transform_stream


async def test_mock_stream_translates_to_openai_chunks() -> None:
    os.environ["QUILL_TRANSPORT"] = "unix-socket"  # not required here, but consistent
    client = MockBedrockClient(canned_text="hi")
    sse = client.invoke_streaming({"model": "x", "messages": []})
    out = transform_stream(sse, request_id=new_request_id(), model="claude-opus-4-7")

    chunks: list[bytes] = []
    async for c in out:
        chunks.append(c)

    text = b"".join(chunks).decode("utf-8")
    assert text.endswith("data: [DONE]\n\n")

    deltas: list[str] = []
    saw_finish = False
    for line in text.splitlines():
        if not line.startswith("data: ") or line == "data: [DONE]":
            continue
        body = json.loads(line[len("data: ") :])
        choice = body["choices"][0]
        delta = choice["delta"]
        if delta.get("content"):
            deltas.append(delta["content"])
        if choice.get("finish_reason") == "stop":
            saw_finish = True

    assert "".join(deltas) == "hi"
    assert saw_finish
