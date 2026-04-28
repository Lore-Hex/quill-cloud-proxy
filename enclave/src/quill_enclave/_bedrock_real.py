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

import asyncio
import base64
import json
import ssl
import struct
from collections.abc import AsyncIterator

from botocore.auth import SigV4Auth  # type: ignore[import-untyped]
from botocore.awsrequest import AWSRequest  # type: ignore[import-untyped]
from botocore.session import get_session  # type: ignore[import-untyped]

from quill_enclave.bedrock import BedrockClient, map_model
from quill_enclave.transport import connect_outbound
from quill_enclave.types import AnthropicMessagesRequest


class RealBedrockClient(BedrockClient):
    async def invoke_streaming(self, req: AnthropicMessagesRequest) -> AsyncIterator[bytes]:
        session = get_session()
        creds = session.get_credentials()
        region = "us-east-1"
        model_id = map_model(req.get("model", "claude-opus-4-7"))
        host = f"bedrock-runtime.{region}.amazonaws.com"
        path = f"/model/{model_id}/invoke-with-response-stream"
        url = f"https://{host}{path}"

        body = json.dumps(req).encode("utf-8")

        aws_req = AWSRequest(method="POST", url=url, data=body)
        SigV4Auth(creds, "bedrock", region).add_auth(aws_req)

        headers = dict(aws_req.headers)
        headers["Content-Type"] = "application/json"
        if "Host" not in headers:
            headers["Host"] = host

        sock = connect_outbound(8003)
        context = ssl.create_default_context()
        reader, writer = await asyncio.open_connection(sock=sock, ssl=context, server_hostname=host)

        req_line = f"POST {path} HTTP/1.1\r\n"
        writer.write(req_line.encode("ascii"))
        for k, v in headers.items():
            writer.write(f"{k}: {v}\r\n".encode("ascii"))
        writer.write(b"Connection: close\r\n\r\n")
        writer.write(body)
        await writer.drain()

        head_buf = bytearray()
        while b"\r\n\r\n" not in head_buf:
            chunk = await reader.read(4096)
            if not chunk:
                break
            head_buf.extend(chunk)

        _, _, rest = head_buf.partition(b"\r\n\r\n")
        buf = bytearray(rest)

        while True:
            while len(buf) < 12:
                chunk = await reader.read(4096)
                if not chunk:
                    break
                buf.extend(chunk)
            if len(buf) < 12:
                break

            total_len, headers_len, _ = struct.unpack(">III", buf[:12])

            while len(buf) < total_len:
                chunk = await reader.read(4096)
                if not chunk:
                    break
                buf.extend(chunk)

            if len(buf) < total_len:
                break

            msg = buf[:total_len]
            buf = buf[total_len:]

            payload_bytes = msg[12 + headers_len : total_len - 4]
            if payload_bytes:
                try:
                    event = json.loads(payload_bytes)
                    if "bytes" in event:
                        yield base64.b64decode(event["bytes"])
                    elif "chunk" in event and "bytes" in event["chunk"]:
                        yield base64.b64decode(event["chunk"]["bytes"])
                except Exception:
                    pass
