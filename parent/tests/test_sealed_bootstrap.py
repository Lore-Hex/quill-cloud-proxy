from __future__ import annotations

import asyncio
import base64
import json
import socket
import struct
import threading
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import AsyncMock, MagicMock, Mock

import pytest

from quill_parent import bootstrap_server
from quill_parent import sealed_bootstrap as sealed

KEY = "arn:aws:kms:eu-west-1:330422590279:key/11111111-1111-1111-1111-111111111111"


def encoded(value: bytes) -> str:
    return base64.b64encode(value).decode()


def make_relay() -> tuple[sealed.SealedRelay, Mock, Mock, bytes]:
    bundle = {
        "ciphertext": encoded(b"ciphertext"), "encrypted_data_key": encoded(b"sealed-key"),
        "manifest": {"region": "eu-west-1", "version": 7,
                     "ciphertext_sha384": "a" * 96, "encrypted_data_key_sha384": "b" * 96},
        "nonce": encoded(b"n" * 12), "signature": encoded(b"signature"),
    }
    secrets = Mock()
    secrets.get_secret_value.return_value = {"SecretString": sealed.canonical(bundle).decode()}
    kms = Mock()
    kms.decrypt.return_value = {"KeyId": KEY, "CiphertextForRecipient": b"encrypted-for-enclave"}
    relay = sealed.SealedRelay(
        region="eu-west-1", key_arn=KEY, secret_id="quill/attested-bootstrap-v2",
        secrets=secrets, kms=kms,
    )
    request = sealed.canonical({
        "attestation_document": encoded(b"NSM-document"), "protocol": sealed.PROTOCOL,
    })
    return relay, secrets, kms, request


def test_ciphertext_only_kms_recipient_contract():
    relay, secrets, kms, request = make_relay()
    response = json.loads(relay.exchange(request))
    secrets.get_secret_value.assert_called_once_with(SecretId="quill/attested-bootstrap-v2")
    kms.decrypt.assert_called_once_with(
        KeyId=KEY, CiphertextBlob=b"sealed-key", EncryptionAlgorithm="SYMMETRIC_DEFAULT",
        EncryptionContext={"purpose": sealed.PROTOCOL, "region": "eu-west-1", "version": "7"},
        Recipient={"AttestationDocument": b"NSM-document",
                   "KeyEncryptionAlgorithm": "RSAES_OAEP_SHA_256"},
    )
    assert response["ciphertext_for_recipient"] == encoded(b"encrypted-for-enclave")
    assert set(response) == {"bundle", "ciphertext_for_recipient"}


@pytest.mark.parametrize("change", [
    {"Plaintext": b"must-never-leave-parent"}, {"KeyId": "another-key"},
    {"CiphertextForRecipient": b""}, {"CiphertextForRecipient": "not-bytes"},
    {"CiphertextForRecipient": b"x" * (sealed.MAX_CMS + 1)},
])
def test_rejects_plaintext_wrong_key_or_invalid_kms_response(change: dict[str, object]):
    relay, _, kms, request = make_relay()
    kms.decrypt.return_value.update(change)
    with pytest.raises(ValueError):
        relay.exchange(request)


@pytest.mark.parametrize("raw_request", [
    b"{}", b"null", b"[]", b"x" * (sealed.MAX_REQUEST + 1),
    b'{"protocol":"x","protocol":"y"}',
    sealed.canonical({"attestation_document": "", "protocol": sealed.PROTOCOL}),
    sealed.canonical({"attestation_document": encoded(b"x"), "protocol": "other"}),
    sealed.canonical({"attestation_document": encoded(b"x"), "protocol": sealed.PROTOCOL,
                      "secret_id": "quill/a-plaintext-key"}),
])
def test_bad_request_has_no_aws_side_effect(raw_request: bytes):
    relay, secrets, kms, _ = make_relay()
    with pytest.raises(ValueError):
        relay.exchange(raw_request)
    secrets.get_secret_value.assert_not_called()
    kms.decrypt.assert_not_called()


@pytest.mark.parametrize("version,region", [(True, "eu-west-1"), (0, "eu-west-1"),
                                          (1, "eu-west-3"), (1 << 53, "eu-west-1")])
def test_invalid_bundle_metadata_cannot_reach_kms(version: object, region: str):
    relay, secrets, kms, request = make_relay()
    bundle = json.loads(secrets.get_secret_value.return_value["SecretString"])
    bundle["manifest"].update(version=version, region=region)
    secrets.get_secret_value.return_value = {"SecretString": sealed.canonical(bundle).decode()}
    with pytest.raises(ValueError):
        relay.exchange(request)
    kms.decrypt.assert_not_called()


async def test_framed_exchange_and_oversized_request_are_bounded():
    relay, _, kms, request = make_relay()
    for oversized in (False, True):
        server, client = socket.socketpair()
        server.setblocking(False)
        client.setblocking(False)
        with ThreadPoolExecutor(max_workers=1) as executor:
            slots = threading.BoundedSemaphore(1)
            task = asyncio.create_task(sealed.serve_one(server, relay, executor, slots))
            size = sealed.MAX_REQUEST + 1 if oversized else len(request)
            await asyncio.get_running_loop().sock_sendall(
                client, struct.pack(">I", size) + (b"" if oversized else request),
            )
            if not oversized:
                header = await sealed.receive_exact(client, 4)
                response = await sealed.receive_exact(client, struct.unpack(">I", header)[0])
                assert json.loads(response)["ciphertext_for_recipient"]
            await asyncio.wait_for(task, 2)
        client.close()
    assert kms.decrypt.call_count == 1


async def test_busy_worker_does_not_queue_more_sdk_work():
    relay, secrets, kms, request = make_relay()
    server, client = socket.socketpair()
    server.setblocking(False)
    client.setblocking(False)
    slots = threading.BoundedSemaphore(1)
    slots.acquire()
    try:
        with ThreadPoolExecutor(max_workers=1) as executor:
            task = asyncio.create_task(sealed.serve_one(server, relay, executor, slots))
            await asyncio.get_running_loop().sock_sendall(
                client, struct.pack(">I", len(request)) + request,
            )
            await asyncio.wait_for(task, 2)
        secrets.get_secret_value.assert_not_called()
        kms.decrypt.assert_not_called()
    finally:
        slots.release()
        client.close()


@pytest.mark.parametrize("mode", ["dual", "v2-only"])
async def test_v2_binds_before_v1_and_strict_never_reads_v1(
    mode: str, monkeypatch: pytest.MonkeyPatch,
):
    bound = False
    listener = MagicMock()

    def bind() -> MagicMock:
        nonlocal bound
        bound = True
        return listener

    async def legacy(**kwargs: object) -> None:
        assert bound

    old = AsyncMock(side_effect=legacy)
    monkeypatch.setenv("QUILL_BOOTSTRAP_MODE", mode)
    monkeypatch.setattr(sealed, "production_relay", Mock())
    monkeypatch.setattr(sealed, "bind_listener", bind)
    monkeypatch.setattr(sealed, "serve", AsyncMock())
    monkeypatch.setattr(bootstrap_server, "_serve_legacy_forever", old)
    await bootstrap_server.serve_forever(region="eu-west-1")
    assert old.await_count == (1 if mode == "dual" else 0)


async def test_bind_failure_never_starts_plaintext_listener(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("QUILL_BOOTSTRAP_MODE", "dual")
    monkeypatch.setattr(sealed, "production_relay", Mock())
    monkeypatch.setattr(sealed, "bind_listener", Mock(side_effect=OSError("bind failed")))
    legacy = AsyncMock()
    monkeypatch.setattr(bootstrap_server, "_serve_legacy_forever", legacy)
    with pytest.raises(OSError):
        await bootstrap_server.serve_forever(region="eu-west-1")
    legacy.assert_not_called()
