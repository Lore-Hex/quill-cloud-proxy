from __future__ import annotations

from pathlib import Path

from pydantic import SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Parent-host config.

    History note: this used to carry Bedrock + OpenRouter-via-vsock-proxy
    settings (`bedrock_vsock_proxy`, `openrouter_secret_id`,
    `device_keys_bucket`, ...) for the older single-provider-per-image
    architecture. Those are gone in the multi-provider direct-API path:
    the enclave egresses directly to api.anthropic.com, api.openai.com,
    etc., so there's no per-provider vsock proxy to configure and no
    sealed device-key blob in S3 to fetch.

    What's left:
      - Where the enclave's vsock listener is (matches enclave-go/cmd/enclave/listener_aws.go).
      - DynamoDB table for usage counters.
      - AWS region (used by both the bootstrap server and the usage reporter).
      - Bootstrap-server knobs: prefix + KMS alias + optional control-plane URL.
      - Operator htpasswd path for /admin/usage.
      - Heartbeat + dev-transport flags.
      - Trust-page injectables (PCR0, git commit, image digest).
    """

    model_config = SettingsConfigDict(env_file=".env", env_prefix="QUILL_", extra="ignore")

    # Where the enclave's vsock listener is. In dev mode (transport=unix-socket)
    # we point at /tmp/quill-enclave-<port>.sock instead.
    enclave_relay_port: int = 8001
    # Keep aligned with the enclave prompt-path cap. Vision requests often
    # contain base64 JSON payloads several times larger than the original image.
    max_request_body_bytes: int = 32 * 1024 * 1024

    # DynamoDB table for usage counters.
    usage_table_name: str = "quill_usage"

    # AWS region (used by both the bootstrap server's Secrets Manager +
    # KMS clients and the usage reporter's DynamoDB client). On the
    # production us-west-2 path this is "us-west-2"; the older
    # bedrock-deploy default of "us-east-1" stays as a fallback so dev
    # boxes that haven't set the env var still work.
    aws_region: str = "us-east-1"

    # ─── Bootstrap server config (AWS multi-provider path) ─────────────
    # All Secrets Manager SecretIds are formed as f"{prefix}{suffix}".
    # `tools/sync-secrets-to-aws.sh` writes provider keys with prefix
    # "quill/" by default; we mirror that here so the parent doesn't
    # need to know about the per-secret naming.
    secret_prefix: str = "quill/"

    # KMS alias used to wrap the cross-cloud GCP service-account JSON
    # key. The alias is informational at decrypt time — KMS infers the
    # key from the ciphertext header — but we log it so a misrouted
    # decrypt is debuggable from the parent's stdout.
    gcp_sa_kms_alias: str = "alias/quill-enclave-cmk"

    # When set, propagated to the enclave as `trustedrouter_base_url`
    # so it knows which region's control-plane endpoint to call for
    # the few callbacks that go via TR (e.g. /v1/internal/keys/lookup).
    # Empty disables those callbacks; the inference path doesn't need
    # them.
    tr_control_plane_base_url: str | None = None

    # ─── Operator + admin ──────────────────────────────────────────────
    # Operator credential for /admin/usage. Stored as a Terraform-issued
    # htpasswd-style hash in /etc/quill/admin-htpasswd. NEVER a device key.
    admin_htpasswd_path: Path = Path("/etc/quill/admin-htpasswd")

    # Heartbeat interval (seconds). 3600 = once per hour. The single line
    # parent ever logs to CloudWatch.
    heartbeat_interval_seconds: int = 3600

    # Whether to use the unix-socket dev transport. In production this MUST
    # be False; the systemd unit explicitly omits the env var.
    use_dev_transport: bool = False

    # ─── Trust-page injectables ───────────────────────────────────────
    # The published PCR0 of the deployed enclave (env-injected at deploy
    # time so /trust shows it without an AWS call).
    published_pcr0_hex: SecretStr | None = None
    git_commit: str = "unknown"
    image_digest: str = "unknown"

    @field_validator("tr_control_plane_base_url", mode="before")
    @classmethod
    def _empty_string_is_none(cls, v: object) -> object:
        # Terraform user-data always sets the env var (with "" when no
        # control-plane URL is configured for this region). Treat empty
        # as unset.
        if isinstance(v, str) and not v.strip():
            return None
        return v


def get_settings() -> Settings:
    return Settings()
