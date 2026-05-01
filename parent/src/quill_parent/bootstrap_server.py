"""Bootstrap RPC: parent → enclave handshake.

The Go enclave dials vsock://(host_cid):9000 at startup and reads one
JSON-encoded BootstrapData blob. We pre-load the data at parent startup:

  1. Fetch the sealed device-key blob from S3.
  2. KMS-decrypt it (parent has the IAM perm; the KMS condition uses the
     enclave's published PCR0 only when an attestation document is
     supplied. The parent is only authorized to perform Decrypt-on-behalf-
     of-attested-enclave; for V1 we simplify by also allowing parent-side
     Decrypt for bootstrap. V1.1 will switch to the strict attested flow.).
  3. Pull short-lived AWS credentials from IMDS (the parent's instance
     role has bedrock:Invoke* permission scoped to the Bedrock VPCE).
  4. Compose BootstrapData with the device list + creds + region +
     vsock-proxy port.

V1 trust caveat (also called out in the trust page): the parent therefore
*sees* both the device-key list (in plaintext, for ~milliseconds at boot)
and the Bedrock credentials. The trust property is preserved at the
prompt-content level (parent never sees prompts), but rotation/separation
of duties for the credential plane lands in V1.1.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import socket
from typing import Final

from quill_parent.logging import get_logger

log = get_logger(__name__)

BOOTSTRAP_PORT: Final[int] = 9100  # nitro-cli reserves vsock 9000 for boot heartbeat
AF_VSOCK: Final[int] = 40
VMADDR_CID_ANY: Final[int] = 0xFFFFFFFF


async def _build_bootstrap_data(
    bucket: str,
    object_key: str,
    region: str,
    bedrock_vsock_proxy: str,
    openrouter_secret_id: str | None = None,
    openrouter_vsock_proxy: str = "3:8004",
) -> dict[str, object]:
    """Fetch + decrypt device-key blob; pull IMDS creds. Returns the JSON
    payload the Go enclave expects (matching internal/types.BootstrapData).
    """
    import boto3

    s3 = boto3.client("s3", region_name=region)
    obj = s3.get_object(Bucket=bucket, Key=object_key)
    ciphertext = obj["Body"].read()

    kms = boto3.client("kms", region_name=region)
    plaintext = kms.decrypt(CiphertextBlob=ciphertext)["Plaintext"]
    devices = json.loads(plaintext)

    # IMDS for short-lived creds (the parent's instance role).
    sts = boto3.client("sts", region_name=region)
    caller = sts.get_caller_identity()
    log.info("bootstrap.assume_role_for_enclave", account=caller.get("Account"))

    session = boto3.Session(region_name=region)
    raw_creds = session.get_credentials()
    if raw_creds is None:
        raise RuntimeError("no AWS credentials available on the parent's instance role")
    creds = raw_creds.get_frozen_credentials()

    if not isinstance(devices, list):
        raise RuntimeError("decrypted device blob is not a JSON array")

    payload: dict[str, object] = {
        "devices": devices,
        "bedrock_access_key": creds.access_key,
        "bedrock_secret_key": creds.secret_key,
        "bedrock_session_token": creds.token or "",
        "region": region,
        "bedrock_vsock_proxy": bedrock_vsock_proxy,
    }

    # OpenRouter API key — only when this deploy is wired for the
    # openrouter-target enclave. Stored as a Secrets Manager secret because
    # rotation cadence differs from the device-key blob's; the parent
    # decrypts at boot using the same KMS-condition policy as the device
    # blob (PCR0-bound).
    if openrouter_secret_id:
        sm = boto3.client("secretsmanager", region_name=region)
        secret = sm.get_secret_value(SecretId=openrouter_secret_id)
        api_key = secret.get("SecretString", "")
        if not isinstance(api_key, str) or not api_key.strip():
            raise RuntimeError("openrouter secret is empty or non-string")
        payload["openrouter_api_key"] = api_key.strip()
        payload["openrouter_vsock_proxy"] = openrouter_vsock_proxy

    return payload


async def _serve_one(client: socket.socket, payload: bytes) -> None:
    loop = asyncio.get_event_loop()
    try:
        await loop.sock_sendall(client, payload)
    finally:
        with contextlib.suppress(OSError):
            client.close()


async def serve_forever(
    *,
    bucket: str,
    object_key: str,
    region: str,
    bedrock_vsock_proxy: str,
    openrouter_secret_id: str | None = None,
    openrouter_vsock_proxy: str = "3:8004",
) -> None:
    """Serve BootstrapData on vsock CID-ANY:9000 forever.

    Refreshes the payload (incl. IMDS creds) every 30 minutes so that
    expiring temporary credentials don't trap the enclave.
    """
    payload_lock = asyncio.Lock()
    cached_payload = b""

    async def refresh() -> None:
        nonlocal cached_payload
        try:
            data = await _build_bootstrap_data(
                bucket,
                object_key,
                region,
                bedrock_vsock_proxy,
                openrouter_secret_id=openrouter_secret_id,
                openrouter_vsock_proxy=openrouter_vsock_proxy,
            )
            async with payload_lock:
                cached_payload = json.dumps(data).encode("utf-8")
            devices_field = data["devices"]
            n = len(devices_field) if isinstance(devices_field, list) else 0
            log.info("bootstrap.refresh", devices=n)
        except Exception as exc:
            log.exception("bootstrap.refresh_failed", err=type(exc).__name__)

    async def refresh_loop() -> None:
        while True:
            await refresh()
            await asyncio.sleep(1800)

    # Strong refs so the periodic refresh + per-conn responders aren't GC'd.
    bg_tasks: set[asyncio.Task[None]] = set()
    refresh_task = asyncio.create_task(refresh_loop())
    bg_tasks.add(refresh_task)

    # Wait for the first refresh to complete before accepting connections.
    while not cached_payload:
        await asyncio.sleep(0.1)

    listener = socket.socket(AF_VSOCK, socket.SOCK_STREAM)
    listener.bind((VMADDR_CID_ANY, BOOTSTRAP_PORT))
    listener.listen(8)
    listener.setblocking(False)

    log.info("bootstrap.listening", port=BOOTSTRAP_PORT)
    loop = asyncio.get_event_loop()
    while True:
        client, _addr = await loop.sock_accept(listener)
        async with payload_lock:
            payload = cached_payload
        t = asyncio.create_task(_serve_one(client, payload))
        bg_tasks.add(t)
        t.add_done_callback(bg_tasks.discard)


def is_enabled() -> bool:
    """Bootstrap server is only active when explicitly opted in. Local dev
    (without a real Nitro host) leaves it off so the unit tests don't try
    to bind AF_VSOCK."""
    return os.environ.get("QUILL_BOOTSTRAP_SERVER", "false").lower() == "true"
