"""Ciphertext-only Nitro bootstrap relay. No plaintext fallback exists here."""

from __future__ import annotations

import asyncio
import base64
import binascii
import contextlib
import json
import re
import socket
import struct
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Protocol, cast

from quill_parent.logging import get_logger

log = get_logger(__name__)
PROTOCOL = "trustedrouter.aws-bootstrap.v2"
PORT = 9101
MAX_REQUEST = 32 << 10
MAX_DOCUMENT = 16 << 10
MAX_BUNDLE = 64 << 10
MAX_RESPONSE = 96 << 10
MAX_CMS = 16 << 10
MAX_CLIENTS = 4


class SecretsAPI(Protocol):
    def get_secret_value(self, *, SecretId: str) -> dict[str, Any]: ...


class KMSAPI(Protocol):
    def decrypt(
        self, *, KeyId: str, CiphertextBlob: bytes, EncryptionContext: dict[str, str],
        Recipient: dict[str, object], EncryptionAlgorithm: str,
    ) -> dict[str, Any]: ...


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def decode_canonical(data: bytes, maximum: int) -> dict[str, Any]:
    if not 0 < len(data) <= maximum:
        raise ValueError("message_size")
    value = json.loads(data)
    if not isinstance(value, dict) or canonical(value) != data:
        raise ValueError("noncanonical_json")
    return value


def decode_base64(value: object, maximum: int) -> bytes:
    if not isinstance(value, str) or len(value) > 4 * ((maximum + 2) // 3):
        raise ValueError("base64_size")
    try:
        data = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("base64_encoding") from exc
    if not 0 < len(data) <= maximum or base64.b64encode(data).decode() != value:
        raise ValueError("base64_size")
    return data


class SealedRelay:
    def __init__(
        self, *, region: str, key_arn: str, secret_id: str,
        secrets: SecretsAPI, kms: KMSAPI,
    ) -> None:
        if region not in {"eu-west-1", "eu-west-3"}:
            raise ValueError("invalid_region")
        pattern = rf"arn:aws:kms:{region}:330422590279:key/[a-f0-9-]{{36}}"
        if re.fullmatch(pattern, key_arn) is None:
            raise ValueError("invalid_attested_key")
        # The relay must not become a general Secrets Manager proxy.
        if secret_id != "quill/attested-bootstrap-v2":
            raise ValueError("invalid_bundle_secret")
        self.region, self.key_arn, self.secret_id = region, key_arn, secret_id
        self.secrets, self.kms = secrets, kms

    def exchange(self, raw: bytes) -> bytes:
        request = decode_canonical(raw, MAX_REQUEST)
        if set(request) != {"attestation_document", "protocol"}:
            raise ValueError("request_fields")
        if request["protocol"] != PROTOCOL:
            raise ValueError("protocol")
        document = decode_base64(request["attestation_document"], MAX_DOCUMENT)
        result = self.secrets.get_secret_value(SecretId=self.secret_id)
        text = result.get("SecretString")
        if not isinstance(text, str):
            raise ValueError("bundle_missing")
        bundle = decode_canonical(text.encode(), MAX_BUNDLE)
        if set(bundle) != {"ciphertext", "encrypted_data_key", "manifest", "nonce", "signature"}:
            raise ValueError("bundle_fields")
        manifest = bundle["manifest"]
        if not isinstance(manifest, dict) or set(manifest) != {
            "region", "version", "ciphertext_sha384", "encrypted_data_key_sha384",
        }:
            raise ValueError("manifest_fields")
        version = manifest["version"]
        if (manifest["region"] != self.region or type(version) is not int
                or not 1 <= version <= (1 << 53) - 1):
            raise ValueError("bundle_metadata")
        encrypted_key = decode_base64(bundle["encrypted_data_key"], 6144)
        # Authenticity is checked INSIDE the enclave against its measured signer.
        # KMS independently validates the Nitro evidence and recipient policy.
        decrypted = self.kms.decrypt(
            KeyId=self.key_arn, CiphertextBlob=encrypted_key,
            EncryptionContext={
                "purpose": PROTOCOL, "region": self.region, "version": str(version),
            },
            Recipient={
                "AttestationDocument": document,
                "KeyEncryptionAlgorithm": "RSAES_OAEP_SHA_256",
            },
            EncryptionAlgorithm="SYMMETRIC_DEFAULT",
        )
        if decrypted.get("Plaintext") not in (None, b""):
            raise ValueError("unexpected_plaintext")
        if decrypted.get("KeyId") != self.key_arn:
            raise ValueError("unexpected_key")
        cms = decrypted.get("CiphertextForRecipient")
        if not isinstance(cms, bytes) or not 0 < len(cms) <= MAX_CMS:
            raise ValueError("recipient_ciphertext")
        response = canonical({
            "bundle": bundle, "ciphertext_for_recipient": base64.b64encode(cms).decode(),
        })
        if len(response) > MAX_RESPONSE:
            raise ValueError("response_size")
        return response


def production_relay(region: str, key_arn: str) -> SealedRelay:
    import boto3
    from botocore.config import Config

    config = Config(connect_timeout=1, read_timeout=2, retries={"total_max_attempts": 1})
    return SealedRelay(
        region=region, key_arn=key_arn, secret_id="quill/attested-bootstrap-v2",
        secrets=cast(SecretsAPI, boto3.client("secretsmanager", region_name=region, config=config)),
        kms=cast(KMSAPI, boto3.client("kms", region_name=region, config=config)),
    )


def bind_listener() -> socket.socket:
    listener = socket.socket(40, socket.SOCK_STREAM)
    try:
        listener.bind((0xFFFFFFFF, PORT))
        listener.listen(MAX_CLIENTS)
        listener.setblocking(False)
        return listener
    except BaseException:
        listener.close()
        raise


async def receive_exact(client: socket.socket, size: int) -> bytes:
    loop = asyncio.get_running_loop()
    body = bytearray()
    while len(body) < size:
        part = await loop.sock_recv(client, size - len(body))
        if not part:
            raise ValueError("truncated_frame")
        body.extend(part)
    return bytes(body)


async def serve_one(
    client: socket.socket, relay: SealedRelay, executor: ThreadPoolExecutor,
    slots: threading.BoundedSemaphore,
) -> None:
    try:
        async with asyncio.timeout(10):
            size = struct.unpack(">I", await receive_exact(client, 4))[0]
            if not 0 < size <= MAX_REQUEST:
                raise ValueError("request_size")
            request = await receive_exact(client, size)
            if not slots.acquire(blocking=False):
                raise ValueError("kms_workers_busy")
            try:
                future = executor.submit(relay.exchange, request)
            except BaseException:
                slots.release()
                raise
            # The slot follows the actual worker, not the caller's timeout.
            # Even a stuck SDK/DNS call cannot grow the executor queue.
            future.add_done_callback(lambda _: slots.release())
            response = await asyncio.wrap_future(future)
            await asyncio.get_running_loop().sock_sendall(
                client, struct.pack(">I", len(response)) + response,
            )
    except Exception as exc:
        # Do not log exception text, request bodies, evidence or SDK responses.
        log.warning("bootstrap.v2_rejected", error_type=type(exc).__name__)
    finally:
        client.close()


async def serve(listener: socket.socket, relay: SealedRelay) -> None:
    active: set[asyncio.Task[None]] = set()
    executor = ThreadPoolExecutor(max_workers=MAX_CLIENTS, thread_name_prefix="sealed-bootstrap")
    slots = threading.BoundedSemaphore(MAX_CLIENTS)
    try:
        log.info("bootstrap.v2_listening", port=PORT)
        while True:
            client, _ = await asyncio.get_running_loop().sock_accept(listener)
            client.setblocking(False)
            if len(active) >= MAX_CLIENTS:
                client.close()
                log.warning("bootstrap.v2_busy")
                continue
            task = asyncio.create_task(serve_one(client, relay, executor, slots))
            active.add(task)
            task.add_done_callback(active.discard)
    finally:
        listener.close()
        for task in active:
            task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await asyncio.gather(*active, return_exceptions=True)
        executor.shutdown(wait=False, cancel_futures=True)
