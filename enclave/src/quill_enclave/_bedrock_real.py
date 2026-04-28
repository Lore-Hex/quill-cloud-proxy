"""Real Bedrock client. Lands in V1 deployment. Stubbed for V1 scaffold.

The real shape:
  1. Open a TCP socket via the parent's vsock-tcp relay (port 8003 →
     bedrock-runtime.us-east-1.amazonaws.com:443).
  2. Do TLS handshake INSIDE the enclave (so parent can't see plaintext).
  3. Build a SigV4-signed POST to /model/<model_id>/invoke-with-response-stream.
     Credentials are temp creds released by KMS to the enclave under
     attestation (separate flow from the device-key blob decrypt).
  4. Read the chunked response, parse the AWS event-stream envelopes,
     extract `{"chunk":{"bytes":<base64>}}`, base64-decode, yield as the
     Anthropic SSE bytes the adapter expects.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

from quill_enclave.bedrock import BedrockClient
from quill_enclave.types import AnthropicMessagesRequest


class RealBedrockClient(BedrockClient):
    async def invoke_streaming(self, req: AnthropicMessagesRequest) -> AsyncIterator[bytes]:
        # The body of an async-generator function: must contain at least one
        # `yield` to be recognized as a generator (even if unreachable).
        yield b""  # pragma: no cover  -- never executed; raise above the yield
        raise NotImplementedError(
            "Real Bedrock client requires SigV4 + TLS-in-enclave + AWS "
            "EventStream parsing. Implement in V1 deployment phase."
        )
