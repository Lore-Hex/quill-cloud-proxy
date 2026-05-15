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
