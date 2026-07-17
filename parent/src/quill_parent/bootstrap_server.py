"""Bootstrap RPC: parent → enclave handshake (AWS multi-provider variant).

The Go enclave dials vsock://(host_cid):9100 at startup and reads one
JSON-encoded BootstrapData blob (matches `enclave-go/internal/types/types.go::BootstrapData`).

We pre-load the data at parent startup:

  1. Pull every provider API key from AWS Secrets Manager. Keys live at
     `quill/trustedrouter-{anthropic,openai,gemini,...}-api-key`,
     mirrored from GCP Secret Manager by `tools/sync-secrets-to-aws.sh`.
     `secretsmanager.GetSecretValue` returns the raw key string — no
     extra wrapping, AWS Secrets Manager handles its own at-rest
     encryption.

  2. Pull the cross-cloud GCP service-account key from
     `quill/trustedrouter-aws-cross-cloud-sa-key`. This one IS
     KMS-wrapped on top of Secrets Manager because the trust posture
     calls for the CMK's key policy to gate decrypt on the enclave's
     attestation document (V1.1 work — V1 simplifies to parent-side
     decrypt). The stored secret value is base64(KMS_ciphertext);
     we GetSecretValue → base64-decode → kms.Decrypt → raw JSON.

  3. Pull the TrustedRouter internal token (used by the enclave for
     control-plane callbacks like /v1/internal/keys/lookup) from
     `quill/trustedrouter-tr-api-key-for-self-heal`.

  4. Compose BootstrapData JSON, cache it, serve on vsock 9100. Refresh
     every 30 min so a key rotation in AWS Secrets Manager flows to
     the enclave on its next bootstrap (the enclave fetches once per
     boot; rotation requires a rolling restart of enclave instances).

V1 trust caveat (also called out on the trust page): the parent
therefore *sees* every provider API key + the GCP SA key in plaintext
for ~ms at boot. The trust property is preserved at the prompt-content
level (parent never sees prompts), but credential-plane separation of
duties lands in V1.1 via attestation-gated KMS Decrypt.

Why not run this directly from the enclave (skipping the parent):
The Nitro enclave has no network interface — no IMDS, no
`secretsmanager.amazonaws.com` egress. Every byte in or out goes via
vsock to the parent. So the parent has to do the AWS API calls.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import json
import os
import socket
from typing import Final

from quill_parent.logging import get_logger

log = get_logger(__name__)

# vsock port the enclave dials. nitro-cli reserves 9000 for the boot
# heartbeat between host and enclave so we use 9100. This MUST stay in
# sync with `BootstrapPort` in enclave-go/internal/bootstrap/bootstrap.go.
BOOTSTRAP_PORT: Final[int] = 9100
AF_VSOCK: Final[int] = 40
VMADDR_CID_ANY: Final[int] = 0xFFFFFFFF

# Refresh interval. Long enough to amortize the AWS API round-trip cost
# (16+ secrets per refresh), short enough that a key rotation in
# Secrets Manager reaches the enclave within ~30 min on a rolling
# restart.
REFRESH_SECONDS: Final[int] = 1800

# Provider key catalog: each entry is (BootstrapData field name, AWS
# Secrets Manager secret name suffix). The full secret path is
# `${secret_prefix}${suffix}`. This list MUST stay in sync with:
#   - tools/sync-secrets-to-aws.sh SECRETS array (mirror source)
#   - enclave-go/internal/types/types.go BootstrapData fields
#   - enclave-go/internal/bootstrap/bootstrap_gcp.go (sibling)
#
# An entry is optional iff the secret is missing in AWS Secrets Manager
# (skip and leave the BootstrapData field empty); the enclave's
# build-tag-gated provider clients ignore empty keys.
_PROVIDER_KEYS: Final[tuple[tuple[str, str], ...]] = (
    ("openrouter_api_key", "quill-openrouter-key"),
    ("anthropic_api_key", "trustedrouter-anthropic-api-key"),
    ("openai_api_key", "trustedrouter-openai-api-key"),
    ("gemini_api_key", "trustedrouter-gemini-api-key"),
    ("cerebras_api_key", "trustedrouter-cerebras-api-key"),
    ("deepseek_api_key", "trustedrouter-deepseek-api-key"),
    ("mistral_api_key", "trustedrouter-mistral-api-key"),
    ("kimi_api_key", "trustedrouter-kimi-api-key"),
    ("zai_api_key", "trustedrouter-zai-api-key"),
    ("together_api_key", "trustedrouter-together-api-key"),
    ("fireworks_api_key", "trustedrouter-fireworks-api-key"),
    ("grok_api_key", "trustedrouter-grok-api-key"),
    ("novita_api_key", "trustedrouter-novita-api-key"),
    # phala_api_key now points at the GPU-TEE-attested confidential
    # AI tier (Phala Cloud), not the upstream-pass-through redpill
    # tier. Same api.redpill.ai host, but the key issued from
    # cloud.phala.com / dashboard is what gates GPU TEE inference.
    # Model id format must be `phala/<bare>` per
    # docs.phala.com/phala-cloud/confidential-ai (enforced by the
    # enclave's phalaModelMap).
    ("phala_api_key", "trustedrouter-phala-confidential-api-key"),
    ("siliconflow_api_key", "trustedrouter-siliconflow-api-key"),
    ("tinfoil_api_key", "trustedrouter-tinfoil-api-key"),
    ("venice_api_key", "trustedrouter-venice-api-key"),
    # 2026-05-11 batch — three new OpenAI-compatible providers, all
    # hosting google/gemma-4-31b-it among other open-weight models.
    ("parasail_api_key", "trustedrouter-parasail-api-key"),
    ("lightning_api_key", "trustedrouter-lightning-api-key"),
    ("gmi_api_key", "trustedrouter-gmi-api-key"),
    ("deepinfra_api_key", "trustedrouter-deepinfra-api-key"),
    ("friendli_api_key", "trustedrouter-friendli-api-key"),
    ("baseten_api_key", "trustedrouter-baseten-api-key"),
    ("thinking_machines_api_key", "trustedrouter-thinking-machines-api-key"),
    ("wafer_api_key", "trustedrouter-wafer-api-key"),
    ("crusoe_api_key", "trustedrouter-crusoe-api-key"),
    ("makora_api_key", "trustedrouter-makora-api-key"),
    ("nebius_api_key", "trustedrouter-nebius-api-key"),
    ("minimax_api_key", "trustedrouter-minimax-api-key"),
    # Voyage AI — embeddings only (OpenAI-shaped /v1/embeddings). Optional like
    # every other key: if trustedrouter-voyage-api-key is absent in AWS Secrets
    # Manager the parent skips it and the enclave's voyage client stays empty.
    ("voyage_api_key", "trustedrouter-voyage-api-key"),
    # Xiaomi MiMo — OpenAI-compatible chat (api.xiaomimimo.com/v1).
    ("xiaomi_api_key", "trustedrouter-xiaomi-api-key"),
)

_PROMPT_KEYS: Final[tuple[tuple[str, str], ...]] = (
    ("synth_panel_prompt", "trustedrouter-synth-panel-prompt-v1"),
    ("synth_synthesis_prompt", "trustedrouter-synth-synthesis-prompt-v1"),
    ("synth_code_panel_prompt", "trustedrouter-synth-code-panel-prompt-v1"),
    ("synth_code_synthesis_prompt", "trustedrouter-synth-code-synthesis-prompt-v1"),
)

_GCP_SA_KEY_SECRET_SUFFIX: Final[str] = "trustedrouter-aws-cross-cloud-sa-key"
# The TR internal gateway token authenticates enclave → TR control
# plane calls (sent as the `x-trustedrouter-internal-token` header on
# /v1/internal/* endpoints). Distinct from
# `trustedrouter-tr-api-key-for-self-heal`, which is a customer-facing
# API key used by TR's self-heal flow when TR calls itself as a
# customer. Initial wiring used the wrong secret here — confirmed by a
# 45s "gateway authorization failed" 401 with the customer key — so we
# point at the same Secret Manager value Cloud Run consumes via the
# `TR_INTERNAL_GATEWAY_TOKEN` env var. Mirrored to AWS Secrets Manager
# by tools/sync-secrets-to-aws.sh.
_TR_INTERNAL_TOKEN_SECRET_SUFFIX: Final[str] = "trustedrouter-internal-gateway-token"

# DNS-01 ACME fallback path (enclave-go/internal/enclavetls/dns01.go).
# Token is scoped Zone:DNS:Edit on quillrouter.com. Zone ID is a
# stable 32-char hex string; we store it as a separate secret rather
# than env-var so it's rotatable + auditable + survives a parent
# container redeploy without changes elsewhere.
_CLOUDFLARE_API_TOKEN_SECRET_SUFFIX: Final[str] = "cloudflare-api-token"
_CLOUDFLARE_ZONE_ID_SECRET_SUFFIX: Final[str] = "cloudflare-zone-id"


def _read_one_secret(sm_client: object, secret_id: str) -> str | None:
    """Fetch one Secrets Manager secret as a string. Returns None if the
    secret doesn't exist (so missing-provider keys don't crash the
    bootstrap), re-raises any other error so a misconfigured deploy
    fails loudly."""
    try:
        # boto3 stub-friendly call signature.
        resp = sm_client.get_secret_value(SecretId=secret_id)  # type: ignore[attr-defined]
    except Exception as exc:
        # Botocore raises ClientError with response['Error']['Code']
        # == 'ResourceNotFoundException' for missing secrets. Anything
        # else is a real error (auth failure, throttle, etc.).
        code = getattr(getattr(exc, "response", {}), "get", lambda _k: None)("Error")
        if isinstance(code, dict) and code.get("Code") == "ResourceNotFoundException":
            log.warning("bootstrap.secret_missing", id=secret_id)
            return None
        raise
    value = resp.get("SecretString")
    if value is None:
        # Some secrets are stored as binary; we don't use that pattern
        # for provider keys but handle it gracefully.
        binary = resp.get("SecretBinary")
        if binary is None:
            return None
        if isinstance(binary, (bytes, bytearray)):
            return binary.decode("utf-8")
        return str(binary)
    return value if isinstance(value, str) else str(value)


def _unwrap_gcp_sa_key(sm_client: object, kms_client: object, secret_id: str) -> str:
    """Fetch the wrapped GCP SA key from Secrets Manager, base64-decode
    the ciphertext, and KMS Decrypt to JSON bytes. Returns the JSON
    string the enclave drops at GOOGLE_APPLICATION_CREDENTIALS.

    The wrapped value was placed in Secrets Manager by
    `tools/deploy-aws-nitro.sh phase_cross_cloud_key`:
        aws kms encrypt --output text --query CiphertextBlob > b64
        aws secretsmanager create-secret --secret-string file://b64
    so the SecretString IS the base64-encoded KMS ciphertext.
    """
    raw = _read_one_secret(sm_client, secret_id)
    if not raw:
        raise RuntimeError(f"bootstrap: cross-cloud GCP SA key secret missing: {secret_id}")
    try:
        ciphertext = base64.b64decode(raw)
    except Exception as exc:
        raise RuntimeError(f"bootstrap: SA key secret value is not valid base64: {exc}") from exc
    resp = kms_client.decrypt(CiphertextBlob=ciphertext)  # type: ignore[attr-defined]
    plaintext = resp.get("Plaintext")
    if not plaintext:
        raise RuntimeError("bootstrap: KMS Decrypt returned empty plaintext")
    if isinstance(plaintext, (bytes, bytearray)):
        return plaintext.decode("utf-8")
    return str(plaintext)


def _build_bootstrap_data(
    *,
    region: str,
    secret_prefix: str,
    gcp_sa_kms_alias: str,
    tr_control_plane_base_url: str | None,
    sm_client_factory: object | None = None,
    kms_client_factory: object | None = None,
) -> dict[str, object]:
    """Synchronously build the BootstrapData payload. Run inside an
    asyncio executor to avoid blocking the event loop on AWS API
    round-trips (each provider key is one GetSecretValue, ~30-100ms
    each, ~2-3s total for 16 keys).

    `sm_client_factory` and `kms_client_factory` are escape hatches
    for tests — production passes None and we build real boto3
    clients. The factories are zero-arg callables returning a client.
    """
    import boto3

    if sm_client_factory:
        sm_client = sm_client_factory()  # type: ignore[operator]
    else:
        sm_client = boto3.client("secretsmanager", region_name=region)
    if kms_client_factory:
        kms_client = kms_client_factory()  # type: ignore[operator]
    else:
        kms_client = boto3.client("kms", region_name=region)
    # mention to keep mypy happy without changing types in the production path
    assert sm_client is not None
    assert kms_client is not None

    payload: dict[str, object] = {
        "region": region,
        # Devices is required by the enclave's BootstrapData but we no
        # longer use sealed device blobs on the AWS path — the trust
        # boundary is the attested-gateway-issued API keys, not a
        # parent-injected device list. Empty array satisfies the JSON
        # schema without claiming devices we can't enumerate.
        "devices": [],
    }

    # 1. Provider keys.
    found = 0
    for field, suffix in _PROVIDER_KEYS:
        value = _read_one_secret(sm_client, f"{secret_prefix}{suffix}")
        if value:
            payload[field] = value.strip()
            found += 1
    log.info("bootstrap.provider_keys", found=found, total=len(_PROVIDER_KEYS))

    prompt_found = 0
    for field, suffix in _PROMPT_KEYS:
        value = _read_one_secret(sm_client, f"{secret_prefix}{suffix}")
        if value:
            payload[field] = value.strip()
            prompt_found += 1
    log.info("bootstrap.prompt_keys", found=prompt_found, total=len(_PROMPT_KEYS))

    # 2. GCP SA key (KMS-unwrapped).
    sa_secret_id = f"{secret_prefix}{_GCP_SA_KEY_SECRET_SUFFIX}"
    payload["gcp_service_account_key_json"] = _unwrap_gcp_sa_key(
        sm_client, kms_client, sa_secret_id
    )
    log.info("bootstrap.gcp_sa_key_unwrapped", kms_alias=gcp_sa_kms_alias)

    # 3. TrustedRouter internal token (no KMS wrapping; just a Secrets
    # Manager string). Optional — only the multi-region control-plane
    # callbacks need it.
    tr_token = _read_one_secret(sm_client, f"{secret_prefix}{_TR_INTERNAL_TOKEN_SECRET_SUFFIX}")
    if tr_token:
        payload["trustedrouter_internal_token"] = tr_token.strip()
    if tr_control_plane_base_url:
        payload["trustedrouter_base_url"] = tr_control_plane_base_url

    # 4. Cloudflare credentials for the DNS-01 ACME fallback. Both
    # are optional — if either is missing, the enclave's DNS-01
    # renewer goroutine no-ops (TLS-ALPN-01 still works via the
    # shared GCS cache, this is defense-in-depth). Token must be
    # scoped `Zone:DNS:Edit` on the quillrouter.com zone.
    cf_token = _read_one_secret(sm_client, f"{secret_prefix}{_CLOUDFLARE_API_TOKEN_SECRET_SUFFIX}")
    if cf_token:
        payload["cloudflare_api_token"] = cf_token.strip()
    cf_zone = _read_one_secret(sm_client, f"{secret_prefix}{_CLOUDFLARE_ZONE_ID_SECRET_SUFFIX}")
    if cf_zone:
        payload["cloudflare_zone_id"] = cf_zone.strip()

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
    region: str,
    secret_prefix: str = "quill/",
    gcp_sa_kms_alias: str = "alias/quill-enclave-cmk",
    tr_control_plane_base_url: str | None = None,
) -> None:
    """Serve BootstrapData on vsock CID-ANY:BOOTSTRAP_PORT forever.

    Refreshes the payload every REFRESH_SECONDS so a key rotation in
    AWS Secrets Manager (e.g. via tools/sync-secrets-to-aws.sh after a
    GCP-side rotation) flows to the enclave on its next boot. Existing
    enclave processes are unaffected — they fetched at startup and
    cache the keys for the lifetime of the process.

    Arguments:
      region: AWS region (e.g. "us-west-2") for the Secrets Manager
        and KMS clients. The CMK lives in the same region as the
        secrets, so a single region applies to both.
      secret_prefix: prepended to every provider/SA-key suffix to form
        the full Secrets Manager SecretId. Defaults to "quill/" which
        matches `tools/sync-secrets-to-aws.sh`'s AWS_SECRET_PREFIX.
      gcp_sa_kms_alias: the KMS CMK alias used to wrap the cross-cloud
        GCP SA key. The alias is informational here (KMS Decrypt
        infers the key from the ciphertext header); we log it so a
        misrouted decrypt is debuggable from the parent's stdout.
      tr_control_plane_base_url: when set, propagated to the enclave
        as `trustedrouter_base_url` so it knows which region's API
        endpoint to call for control-plane operations.
    """
    payload_lock = asyncio.Lock()
    cached_payload = b""

    def _build_sync() -> dict[str, object]:
        return _build_bootstrap_data(
            region=region,
            secret_prefix=secret_prefix,
            gcp_sa_kms_alias=gcp_sa_kms_alias,
            tr_control_plane_base_url=tr_control_plane_base_url,
        )

    async def refresh() -> None:
        nonlocal cached_payload
        loop = asyncio.get_event_loop()
        try:
            data = await loop.run_in_executor(None, _build_sync)
            async with payload_lock:
                cached_payload = json.dumps(data).encode("utf-8")
            log.info(
                "bootstrap.refresh",
                # don't log the actual key values; just a count of
                # which provider fields ended up populated
                providers_loaded=sum(1 for field, _suffix in _PROVIDER_KEYS if data.get(field)),
            )
        except Exception as exc:
            log.exception("bootstrap.refresh_failed", err=type(exc).__name__)

    async def refresh_loop() -> None:
        while True:
            await refresh()
            await asyncio.sleep(REFRESH_SECONDS)

    bg_tasks: set[asyncio.Task[None]] = set()
    refresh_task = asyncio.create_task(refresh_loop())
    bg_tasks.add(refresh_task)

    # Wait for the first refresh to land before accepting connections.
    # Otherwise a fast-booting enclave can dial the parent's listener
    # before the payload exists and get an empty response.
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
    """Bootstrap server is only active when explicitly opted in. Local
    dev (without a real Nitro host) leaves it off so unit tests don't
    try to bind AF_VSOCK."""
    return os.environ.get("QUILL_BOOTSTRAP_SERVER", "false").lower() == "true"
