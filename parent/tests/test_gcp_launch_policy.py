from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_gcp_multi_launch_policy_allows_deployed_env_overrides() -> None:
    dockerfile = REPO_ROOT / "enclave-go" / "Dockerfile.enclave.gcp.multi"
    deploy_script = REPO_ROOT / "tools" / "deploy-gcp-mig.sh"

    label_match = re.search(
        r'LABEL "tee\.launch_policy\.allow_env_override"="([^"]+)"',
        dockerfile.read_text(),
    )
    assert label_match is not None
    allowed_envs = set(label_match.group(1).split(","))

    metadata_envs = set(re.findall(r"tee-env-([A-Z0-9_]+)=", deploy_script.read_text()))

    assert metadata_envs <= allowed_envs
    assert "QUILL_OPENROUTER_SECRET" in metadata_envs
    assert "QUILL_OPENROUTER_SECRET" in allowed_envs


def test_gcp_bootstrap_grants_workload_access_to_openrouter_secret() -> None:
    bootstrap_script = REPO_ROOT / "tools" / "deploy-gcp-bootstrap.sh"
    source = bootstrap_script.read_text()

    assert 'OPENROUTER_SECRET="${OPENROUTER_SECRET:-quill-openrouter-key}"' in source
    assert '"$OPENROUTER_SECRET" \\' in source


def test_aws_meta_route_mirrors_key_and_vsock_tunnel() -> None:
    sync_script = (REPO_ROOT / "tools" / "sync-secrets-to-aws.sh").read_text()
    deploy_script = (REPO_ROOT / "tools" / "deploy-aws-nitro.sh").read_text()
    tunnel_source = (
        REPO_ROOT / "enclave-go" / "internal" / "llm" / "http_client_aws.go"
    ).read_text()

    assert "quill-openrouter-key" in sync_script
    assert "write_vsock_unit 8041 openrouter.ai" in deploy_script
    assert 'Host: "openrouter.ai", CID: 3, Port: 8041' in tunnel_source
