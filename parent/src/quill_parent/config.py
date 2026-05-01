from __future__ import annotations

from pathlib import Path

from pydantic import SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="QUILL_", extra="ignore")

    # Where the enclave's vsock listener is. In dev mode (transport=unix-socket)
    # we point at /tmp/quill-enclave-<port>.sock instead.
    enclave_relay_port: int = 8001

    # DynamoDB table for usage counters.
    usage_table_name: str = "quill_usage"

    # S3 location of the sealed device-key blob.
    device_keys_bucket: str = "quill-device-keys"
    device_keys_object_key: str = "blob.enc"

    # AWS region (used by both DynamoDB and S3 clients).
    aws_region: str = "us-east-1"

    # Where the bootstrap RPC tells the enclave to find Bedrock over vsock.
    # Format: "<cid>:<port>", e.g. "3:8003". The user-data sets up
    # vsock-proxy listening on this CID/port forwarding to bedrock-runtime.
    bedrock_vsock_proxy: str = "3:8003"

    # OpenRouter ZDR provider (only used by the openrouter-target enclave
    # build). When set, the parent ships the API key in BootstrapData and
    # runs a vsock-proxy on this CID/port forwarding to openrouter.ai:443.
    # The API key itself is fetched from the same KMS-sealed config as the
    # device-key blob — the parent only sees plaintext for ~ms at boot.
    openrouter_secret_id: str | None = None
    openrouter_vsock_proxy: str = "3:8004"

    @field_validator("openrouter_secret_id", mode="before")
    @classmethod
    def _empty_string_is_none(cls, v: object) -> object:
        # Terraform user-data always sets the env var (with "" when no
        # OpenRouter deploy is configured). Treat empty as unset so the
        # bootstrap path stays AWS-only by default.
        if isinstance(v, str) and not v.strip():
            return None
        return v

    # Operator credential for /admin/usage. Stored as a Terraform-issued
    # htpasswd-style hash in /etc/quill/admin-htpasswd. NEVER a device key.
    admin_htpasswd_path: Path = Path("/etc/quill/admin-htpasswd")

    # Heartbeat interval (seconds). 3600 = once per hour. The single line
    # parent ever logs to CloudWatch.
    heartbeat_interval_seconds: int = 3600

    # Whether to use the unix-socket dev transport. In production this MUST
    # be False; the systemd unit explicitly omits the env var.
    use_dev_transport: bool = False

    # Trust page: the published PCR0 of the deployed enclave (env-injected
    # at deploy time so /trust shows it without an AWS call).
    published_pcr0_hex: SecretStr | None = None
    git_commit: str = "unknown"
    image_digest: str = "unknown"


def get_settings() -> Settings:
    return Settings()
