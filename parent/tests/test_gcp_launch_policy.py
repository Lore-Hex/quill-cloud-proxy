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
    assert "QUILL_AZURE_SECRET" in metadata_envs
    assert "QUILL_AZURE_SECRET" in allowed_envs
    assert "QUILL_SPEND_LEASE_ISSUER_CONFIG_SECRET" in metadata_envs
    assert "QUILL_SPEND_LEASE_ISSUER_CONFIG_SECRET" in allowed_envs
    for name in ("QUILL_LTX_SECRET", "QUILL_RUNWAY_SECRET", "QUILL_KLING_SECRET"):
        assert name in metadata_envs
        assert name in allowed_envs
    assert "QUILL_OPENAI_VIDEO_SECRET" in allowed_envs
    assert "OPENAI_VIDEO_TEE_ENV" in deploy_script.read_text()
    assert "TR_NATIVE_BATCH_PROVIDERS" not in allowed_envs
    assert "TR_NATIVE_BATCH_PROVIDERS" not in deploy_script.read_text()


def test_batch_resource_provisioning_is_attestation_and_retention_scoped() -> None:
    provision = (REPO_ROOT / "tools" / "provision-gcp-batch-resources.sh").read_text()
    reconcile = (REPO_ROOT / "tools" / "reconcile-gcp-batch-image-access.sh").read_text()

    assert "assertion.swname == 'CONFIDENTIAL_SPACE'" in provision
    assert "assertion.dbgstat == 'disabled-since-boot'" in provision
    assert "'STABLE' in assertion.submods.confidential_space.support_attributes" in provision
    assert "assertion.submods.gce.project_number == '${PROJECT_NUMBER}'" in provision
    assert "'${WORKLOAD_SA}' in assertion.google_service_accounts" in provision
    assert "--uniform-bucket-level-access" in provision
    assert "--public-access-prevention" in provision
    assert "--clear-soft-delete" in provision
    assert '"age":30' in provision
    assert "--rotation-period=90d" in provision
    assert '--next-rotation-time="${next_rotation_time}"' in provision
    assert "roles/storage.objectAdmin" in reconcile
    assert "roles/cloudkms.cryptoKeyEncrypterDecrypter" in reconcile
    assert "/attribute.image_digest/" in reconcile
    assert 'CURRENT_MEMBER="${MEMBER_PREFIX}${IMAGE_DIGEST}"' in reconcile
    assert 'BATCH_RELEASE_SA="${BATCH_RELEASE_SA:-tr-batch-release@' in provision
    assert "serviceAccount:${BATCH_RELEASE_SA}" in provision
    assert provision.count("retry_eventual_iam gcloud") == 3
    assert "serviceAccount:${DEPLOY_SA}" not in provision
    assert "subject/repo:${GITHUB_REPOSITORY}:environment:batch-release" in provision


def test_gcp_rollout_grants_before_rollout_and_never_prunes_in_same_release() -> None:
    workflow = (REPO_ROOT / ".github" / "workflows" / "deploy-enclave-gcp.yml").read_text()
    grant = 'reconcile-gcp-batch-image-access.sh grant "${IMAGE_DIGEST}"'
    first_rollout = "name: Roll the GCP MIG (us-central1)"
    prune = 'reconcile-gcp-batch-image-access.sh prune "${IMAGE_DIGEST}"'

    assert workflow.index(grant) < workflow.index(first_rollout)
    assert prune not in workflow
    assert workflow.count("tr-batch-release@quill-cloud-proxy.iam.gserviceaccount.com") == 1
    assert "native_batch_enabled" not in workflow
    assert "environment: batch-release" in workflow
    assert "Require explicit Batch storage activation" in workflow
    assert 'if [ "${TR_BATCH_STORAGE_ENABLED}" != "true" ]; then' in workflow
    assert "batch-image-access-not-required:" not in workflow
    assert (
        "needs: [build-and-release, grant-batch-image-access, verify-transition-trust-page]"
    ) in workflow
    assert "needs.grant-batch-image-access.result == 'success'" in workflow
    assert "needs.verify-transition-trust-page.result == 'success'" in workflow
    assert "TR_NATIVE_BATCH_PROVIDERS" not in workflow


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


def test_azure_foundry_secret_is_granted_and_activated_only_when_present() -> None:
    bootstrap = (REPO_ROOT / "tools" / "deploy-gcp-bootstrap.sh").read_text()
    deploy = (REPO_ROOT / "tools" / "deploy-gcp-mig.sh").read_text()

    assert 'AZURE_SECRET="${AZURE_SECRET:-trustedrouter-azure-api-key}"' in bootstrap
    assert '"$AZURE_SECRET" \\' in bootstrap
    assert 'if [ "${QUILL_AZURE_SECRET+x}" != "x" ]; then' in deploy
    assert "secret_inventory_has trustedrouter-azure-api-key" in deploy
    assert 'AZURE_TEE_ENV="|tee-env-QUILL_AZURE_SECRET=${QUILL_AZURE_SECRET}"' in deploy


def test_gcp_bootstrap_grants_workload_access_to_engy_secret() -> None:
    bootstrap_script = REPO_ROOT / "tools" / "deploy-gcp-bootstrap.sh"
    source = bootstrap_script.read_text()

    assert 'ENGY_SECRET="${ENGY_SECRET:-trustedrouter-engy-api-key}"' in source
    assert '"$ENGY_SECRET" \\' in source

    deploy = (REPO_ROOT / "tools" / "deploy-gcp-mig.sh").read_text()
    assert 'if [ "${QUILL_ENGY_SECRET+x}" != "x" ]; then' in deploy
    assert "secret_inventory_has trustedrouter-engy-api-key" in deploy
    assert 'ENGY_TEE_ENV="|tee-env-QUILL_ENGY_SECRET=${QUILL_ENGY_SECRET}"' in deploy


def test_spend_lease_issuer_config_secret_name_is_granted_and_injected() -> None:
    bootstrap = (REPO_ROOT / "tools" / "deploy-gcp-bootstrap.sh").read_text()
    deploy = (REPO_ROOT / "tools" / "deploy-gcp-mig.sh").read_text()
    secret_name = "trustedrouter-spend-lease-issuer-config"

    assert (
        f'SPEND_LEASE_ISSUER_CONFIG_SECRET="${{SPEND_LEASE_ISSUER_CONFIG_SECRET:-{secret_name}}}"'
    ) in bootstrap
    assert '"$SPEND_LEASE_ISSUER_CONFIG_SECRET" \\' in bootstrap
    assert (
        'QUILL_SPEND_LEASE_ISSUER_CONFIG_SECRET="'
        "${QUILL_SPEND_LEASE_ISSUER_CONFIG_SECRET:-"
        f'{secret_name}}}"'
    ) in deploy
    assert (
        'SPEND_LEASE_ISSUER_CONFIG_TEE_ENV="'
        "|tee-env-QUILL_SPEND_LEASE_ISSUER_CONFIG_SECRET="
        '${QUILL_SPEND_LEASE_ISSUER_CONFIG_SECRET}"'
    ) in deploy
    assert "${SPEND_LEASE_ISSUER_CONFIG_TEE_ENV}" in deploy


def test_provider_wave_secrets_are_injected_only_after_existence_check() -> None:
    bootstrap = (REPO_ROOT / "tools" / "deploy-gcp-bootstrap.sh").read_text()
    deploy = (REPO_ROOT / "tools" / "deploy-gcp-mig.sh").read_text()
    expected = {
        "QUILL_STEPFUN_SECRET": "trustedrouter-stepfun-api-key",
        "QUILL_RELACE_SECRET": "trustedrouter-relace-api-key",
        "QUILL_DECART_SECRET": "trustedrouter-decart-api-key",
        "QUILL_RECRAFT_SECRET": "trustedrouter-recraft-api-key",
        "QUILL_BFL_SECRET": "trustedrouter-bfl-api-key",
        "QUILL_NEXTBIT_SECRET": "trustedrouter-nextbit-api-key",
        "QUILL_AION_LABS_SECRET": "trustedrouter-aion-labs-api-key",
        "QUILL_SAMBANOVA_SECRET": "trustedrouter-sambanova-api-key",
        "QUILL_INCEPTION_SECRET": "trustedrouter-inception-api-key",
        "QUILL_AKASHML_SECRET": "trustedrouter-akashml-api-key",
        "QUILL_ARCEE_SECRET": "trustedrouter-arcee-api-key",
        "QUILL_UPSTAGE_SECRET": "trustedrouter-upstage-api-key",
        "QUILL_REKA_SECRET": "trustedrouter-reka-api-key",
        "QUILL_SAIL_RESEARCH_SECRET": "trustedrouter-sail-research-api-key",
        "QUILL_MANCER_SECRET": "trustedrouter-mancer-api-key",
    }
    assert "configure_optional_provider_secret()" in deploy
    assert "${PROVIDER_WAVE_TEE_ENV}" in deploy
    for env_name, secret_name in expected.items():
        assert f"configure_optional_provider_secret {env_name} {secret_name}" in deploy
        assert f'{env_name}="${{{env_name}:-{secret_name}}}"' not in deploy
        bootstrap_name = env_name.removeprefix("QUILL_")
        assert f'{bootstrap_name}="${{{bootstrap_name}:-{secret_name}}}"' in bootstrap
        assert f'"${bootstrap_name}" \\' in bootstrap


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


def test_aws_azure_route_mirrors_key_and_both_protocol_tunnels() -> None:
    sync_script = (REPO_ROOT / "tools" / "sync-secrets-to-aws.sh").read_text()
    deploy_script = (REPO_ROOT / "tools" / "deploy-aws-nitro.sh").read_text()
    tunnel_source = (
        REPO_ROOT / "enclave-go" / "internal" / "llm" / "http_client_aws.go"
    ).read_text()

    assert "trustedrouter-azure-api-key" in sync_script
    expected = {
        8053: "trustedrouter-foundry-eastus2.openai.azure.com",
        8054: "trustedrouter-foundry-eastus2.services.ai.azure.com",
    }
    for port, host in expected.items():
        assert f"write_vsock_unit {port} {host}" in deploy_script
        assert f'Host: "{host}", CID: 3, Port: {port}' in tunnel_source
