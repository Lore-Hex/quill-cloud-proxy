"""Tests for the rewritten bootstrap_server.

The production path makes 16+ AWS API calls (GetSecretValue per
provider key + KMS Decrypt for the GCP SA key). To test it without
booting moto or requiring real AWS creds, we plug stub
secretsmanager/kms clients into _build_bootstrap_data via the
sm_client_factory / kms_client_factory escape hatches.
"""

from __future__ import annotations

import base64
from typing import Any

import pytest

from quill_parent import bootstrap_server


class _StubSecretsManager:
    """Returns canned SecretString responses; raises ResourceNotFoundException
    for any SecretId not in the canned dict."""

    def __init__(self, secrets: dict[str, str]) -> None:
        self.secrets = secrets
        self.calls: list[str] = []

    def get_secret_value(self, *, SecretId: str) -> dict[str, Any]:
        self.calls.append(SecretId)
        if SecretId not in self.secrets:
            err: Any = type(
                "ClientError",
                (Exception,),
                {"response": {"Error": {"Code": "ResourceNotFoundException"}}},
            )
            raise err(f"secret not found: {SecretId}")
        return {"SecretString": self.secrets[SecretId]}


class _StubKMS:
    """Decrypts by lookup in a canned ciphertext-bytes → plaintext-bytes map."""

    def __init__(self, decrypt_map: dict[bytes, bytes]) -> None:
        self.decrypt_map = decrypt_map
        self.calls: list[bytes] = []

    def decrypt(self, *, CiphertextBlob: bytes) -> dict[str, Any]:
        self.calls.append(CiphertextBlob)
        if CiphertextBlob not in self.decrypt_map:
            raise RuntimeError("unexpected ciphertext")
        return {"Plaintext": self.decrypt_map[CiphertextBlob]}


# A minimal valid GCP SA key JSON (just the fields the GCP client libs
# actually parse). We don't validate it cryptographically here — we
# just verify it round-trips through the bootstrap unchanged.
_FAKE_SA_KEY = (
    '{"type":"service_account","project_id":"quill-cloud-proxy",'
    '"private_key":"-----BEGIN PRIVATE KEY-----...-----END PRIVATE KEY-----",'
    '"client_email":"tr-aws-cross-cloud@quill-cloud-proxy.iam.gserviceaccount.com"}'
)
_FAKE_KMS_CIPHERTEXT = b"\x01\x02\x03KMS-fake-ciphertext"


def _build_payload(
    *,
    sm: _StubSecretsManager,
    kms: _StubKMS,
    region: str = "us-west-2",
    secret_prefix: str = "quill/",
    tr_url: str | None = None,
) -> dict[str, Any]:
    return bootstrap_server._build_bootstrap_data(
        region=region,
        secret_prefix=secret_prefix,
        gcp_sa_kms_alias="alias/quill-enclave-cmk",
        tr_control_plane_base_url=tr_url,
        sm_client_factory=lambda: sm,
        kms_client_factory=lambda: kms,
    )


def test_build_payload_loads_present_provider_keys_and_skips_missing() -> None:
    """A subset of provider keys are present in Secrets Manager; the
    rest don't exist (ResourceNotFoundException). The bootstrap should
    populate the present ones and silently skip the missing ones."""
    sm = _StubSecretsManager(
        {
            "quill/quill-openrouter-key": "sk-or-FAKE",
            "quill/trustedrouter-anthropic-api-key": "sk-ant-FAKE",
            "quill/trustedrouter-openai-api-key": "sk-FAKE-OPENAI",
            "quill/trustedrouter-aws-cross-cloud-sa-key": base64.b64encode(
                _FAKE_KMS_CIPHERTEXT
            ).decode("ascii"),
            # gemini, cerebras, ... all missing on purpose
        }
    )
    kms = _StubKMS({_FAKE_KMS_CIPHERTEXT: _FAKE_SA_KEY.encode("utf-8")})

    payload = _build_payload(sm=sm, kms=kms)

    assert payload["region"] == "us-west-2"
    assert payload["devices"] == []  # always empty on the AWS multi-provider path
    assert payload["anthropic_api_key"] == "sk-ant-FAKE"
    assert payload["openai_api_key"] == "sk-FAKE-OPENAI"
    assert payload["openrouter_api_key"] == "sk-or-FAKE"
    # Missing keys produce no field at all (omitempty on the Go side).
    assert "gemini_api_key" not in payload
    assert "cerebras_api_key" not in payload
    # GCP SA key gets unwrapped + put into the right field.
    assert payload["gcp_service_account_key_json"] == _FAKE_SA_KEY


def test_build_payload_strips_whitespace_from_provider_keys() -> None:
    """Some provider portals return keys with trailing newlines (when
    the operator pasted them via heredoc). Make sure we strip so the
    enclave's HTTP Authorization header isn't rejected."""
    sm = _StubSecretsManager(
        {
            "quill/trustedrouter-openai-api-key": "  sk-FAKE-OPENAI\n",
            "quill/trustedrouter-aws-cross-cloud-sa-key": base64.b64encode(
                _FAKE_KMS_CIPHERTEXT
            ).decode("ascii"),
        }
    )
    kms = _StubKMS({_FAKE_KMS_CIPHERTEXT: _FAKE_SA_KEY.encode("utf-8")})

    payload = _build_payload(sm=sm, kms=kms)
    assert payload["openai_api_key"] == "sk-FAKE-OPENAI"


def test_build_payload_loads_prompt_bundle() -> None:
    sm = _StubSecretsManager(
        {
            "quill/trustedrouter-synth-panel-prompt-v1": "  general panel\n",
            "quill/trustedrouter-synth-synthesis-prompt-v1": "general final",
            "quill/trustedrouter-synth-code-panel-prompt-v1": "code panel",
            "quill/trustedrouter-synth-code-synthesis-prompt-v1": "code final\n",
            "quill/trustedrouter-aws-cross-cloud-sa-key": base64.b64encode(
                _FAKE_KMS_CIPHERTEXT
            ).decode("ascii"),
        }
    )
    kms = _StubKMS({_FAKE_KMS_CIPHERTEXT: _FAKE_SA_KEY.encode("utf-8")})

    payload = _build_payload(sm=sm, kms=kms)
    assert payload["synth_panel_prompt"] == "general panel"
    assert payload["synth_synthesis_prompt"] == "general final"
    assert payload["synth_code_panel_prompt"] == "code panel"
    assert payload["synth_code_synthesis_prompt"] == "code final"


def test_build_payload_propagates_tr_control_plane_url() -> None:
    sm = _StubSecretsManager(
        {
            "quill/trustedrouter-aws-cross-cloud-sa-key": base64.b64encode(
                _FAKE_KMS_CIPHERTEXT
            ).decode("ascii"),
            "quill/trustedrouter-internal-gateway-token": "tr_internal_token_FAKE",
        }
    )
    kms = _StubKMS({_FAKE_KMS_CIPHERTEXT: _FAKE_SA_KEY.encode("utf-8")})

    payload = _build_payload(sm=sm, kms=kms, tr_url="https://api-us-central1.quillrouter.com/v1")
    assert payload["trustedrouter_base_url"] == "https://api-us-central1.quillrouter.com/v1"
    assert payload["trustedrouter_internal_token"] == "tr_internal_token_FAKE"


def test_build_payload_raises_when_gcp_sa_key_missing() -> None:
    """The GCP SA key is REQUIRED (not optional) — without it the
    AWS-side enclave can't read GCP Spanner/Bigtable cross-cloud and
    every credit-ledger call fails. Bootstrap should fail loudly so
    the parent restarts (and the ASG replaces the instance) instead
    of silently shipping a broken BootstrapData."""
    sm = _StubSecretsManager(
        {
            "quill/trustedrouter-anthropic-api-key": "sk-ant-FAKE",
            # SA key DELIBERATELY missing
        }
    )
    kms = _StubKMS({})  # Decrypt should never be called

    with pytest.raises(RuntimeError, match="cross-cloud GCP SA key"):
        _build_payload(sm=sm, kms=kms)


def test_build_payload_raises_when_gcp_sa_secret_value_is_not_base64() -> None:
    """The wrapped SA key is stored as base64(KMS_ciphertext). If
    Terraform / a manual rotation script writes the raw bytes by
    accident, base64.b64decode raises — surface that with a clear
    error so the operator knows to re-run phase_cross_cloud_key."""
    sm = _StubSecretsManager(
        {
            # `*` is not a valid base64 character; b64decode strict mode rejects it
            "quill/trustedrouter-aws-cross-cloud-sa-key": "this-is-***-not-base64",
        }
    )
    kms = _StubKMS({})

    # Strict base64 decode is the default in Python 3.10+ via
    # base64.b64decode(s, validate=True). _unwrap_gcp_sa_key uses the
    # default-non-strict variant, but invalid characters still produce
    # binascii.Error → wrapped into RuntimeError by our handler.
    with pytest.raises(RuntimeError):
        _build_payload(sm=sm, kms=kms)


def test_build_payload_iterates_all_known_providers() -> None:
    """All provider key suffixes from sync-secrets-to-aws.sh map to
    a BootstrapData field that the enclave knows about. This test is
    a regression guard: if someone adds a provider to the AWS sync
    script but forgets the bootstrap_server _PROVIDER_KEYS entry, the
    new key never reaches the enclave."""
    expected_fields = {
        "openrouter_api_key",
        "anthropic_api_key",
        "openai_api_key",
        "gemini_api_key",
        "cerebras_api_key",
        "deepseek_api_key",
        "mistral_api_key",
        "kimi_api_key",
        "zai_api_key",
        "together_api_key",
        "fireworks_api_key",
        "grok_api_key",
        "novita_api_key",
        "phala_api_key",
        "siliconflow_api_key",
        "tinfoil_api_key",
        "venice_api_key",
        "parasail_api_key",
        "lightning_api_key",
        "gmi_api_key",
        "deepinfra_api_key",
        "friendli_api_key",
        "baseten_api_key",
        "thinking_machines_api_key",
        "wafer_api_key",
        "crusoe_api_key",
        "makora_api_key",
        "nebius_api_key",
        "minimax_api_key",
        "voyage_api_key",
        "xiaomi_api_key",
    }
    actual_fields = {field for field, _suffix in bootstrap_server._PROVIDER_KEYS}
    assert actual_fields == expected_fields, (
        f"missing: {expected_fields - actual_fields} extra: {actual_fields - expected_fields}"
    )
