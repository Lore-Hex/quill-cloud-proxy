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
    assert "QUILL_NEUROMETRIC_SECRET" in metadata_envs
    assert "QUILL_NEUROMETRIC_SECRET" in allowed_envs
    assert "QUILL_ENGY_SECRET" in metadata_envs
    assert "QUILL_ENGY_SECRET" in allowed_envs
    assert "QUILL_ALIBABA_SECRET" in metadata_envs
    assert "QUILL_ALIBABA_SECRET" in allowed_envs
    for name in ("QUILL_LTX_SECRET", "QUILL_RUNWAY_SECRET", "QUILL_KLING_SECRET"):
        assert name in metadata_envs
        assert name in allowed_envs
    assert "QUILL_OPENAI_VIDEO_SECRET" in allowed_envs
    assert "OPENAI_VIDEO_TEE_ENV" in deploy_script.read_text()


def test_gcp_bootstrap_grants_workload_access_to_openrouter_secret() -> None:
    bootstrap_script = REPO_ROOT / "tools" / "deploy-gcp-bootstrap.sh"
    source = bootstrap_script.read_text()

    assert 'OPENROUTER_SECRET="${OPENROUTER_SECRET:-quill-openrouter-key}"' in source
    assert '"$OPENROUTER_SECRET" \\' in source


def test_gcp_bootstrap_grants_workload_access_to_neurometric_secret() -> None:
    bootstrap_script = REPO_ROOT / "tools" / "deploy-gcp-bootstrap.sh"
    source = bootstrap_script.read_text()

    assert (
        'NEUROMETRIC_SECRET="${NEUROMETRIC_SECRET:-trustedrouter-neurometric-api-key}"'
    ) in source
    assert '"$NEUROMETRIC_SECRET" \\' in source


def test_gcp_bootstrap_grants_workload_access_to_engy_secret() -> None:
    bootstrap_script = REPO_ROOT / "tools" / "deploy-gcp-bootstrap.sh"
    source = bootstrap_script.read_text()

    assert 'ENGY_SECRET="${ENGY_SECRET:-trustedrouter-engy-api-key}"' in source
    assert '"$ENGY_SECRET" \\' in source

    deploy = (REPO_ROOT / "tools" / "deploy-gcp-mig.sh").read_text()
    assert 'if [ "${QUILL_ENGY_SECRET+x}" != "x" ]; then' in deploy
    assert "gc secrets describe trustedrouter-engy-api-key" in deploy
    assert 'ENGY_TEE_ENV="|tee-env-QUILL_ENGY_SECRET=${QUILL_ENGY_SECRET}"' in deploy


def test_gcp_bootstrap_grants_workload_access_to_direct_video_secrets() -> None:
    bootstrap_script = REPO_ROOT / "tools" / "deploy-gcp-bootstrap.sh"
    source = bootstrap_script.read_text()

    expected = {
        "LTX_SECRET": "trustedrouter-ltx-api-key",
        "RUNWAY_SECRET": "trustedrouter-runway-api-key",
        "KLING_SECRET": "trustedrouter-kling-api-key",
    }
    for env_name, secret_name in expected.items():
        assert f'{env_name}="${{{env_name}:-{secret_name}}}"' in source
        assert f'"${env_name}" \\' in source


def test_openai_video_secret_is_separate_and_optional() -> None:
    bootstrap_script = REPO_ROOT / "tools" / "deploy-gcp-bootstrap.sh"
    source = bootstrap_script.read_text()

    assert 'OPENAI_VIDEO_SECRET="${OPENAI_VIDEO_SECRET:-}"' in source
    assert '"$OPENAI_VIDEO_SECRET" \\' in source


def test_aws_meta_route_mirrors_key_and_vsock_tunnel() -> None:
    sync_script = (REPO_ROOT / "tools" / "sync-secrets-to-aws.sh").read_text()
    deploy_script = (REPO_ROOT / "tools" / "deploy-aws-nitro.sh").read_text()
    tunnel_source = (
        REPO_ROOT / "enclave-go" / "internal" / "llm" / "http_client_aws.go"
    ).read_text()

    assert "quill-openrouter-key" in sync_script
    assert "write_vsock_unit 8041 openrouter.ai" in deploy_script
    assert 'Host: "openrouter.ai", CID: 3, Port: 8041' in tunnel_source
