# Azure identity for rollout-azure-gateway.yml

`main.tf` declares the user-assigned managed identity `tr-gateway-rollout`
(resource group `tr-azure`), its GitHub federated credential, and the role
assignments the workflow's steps need, each at the narrowest scope that
covers one documented call of `tools/deploy-azure-aci.sh` or
`tools/azure_gateway_rollout.py`:

| scope | grant | for |
| --- | --- | --- |
| `TR-TEE-DUBAI`, `tr-tee-sydney` | custom: container groups, ARM deployments, assign identity | replace `quill-enclave-<region>` |
| registry `trquillacr` | custom: task runs; `AcrPush` | `az acr build`, confcom pull |
| key `trquillkv/keys/tr-bootstrap-wrap` | `Key Vault Crypto Officer` | bind, verify, narrow, rollback |
| storage `trquillacmecache` | `Reader` | deploy preflight (no blob data) |
| subscription | custom: role definitions read | preflight role lookup |
| profile `trquill-azure-gw` | custom: external endpoints read/write | drain and re-enable |

There is no Terraform backend for Azure in quill-router's `infra-apply.yml`,
and the apply creates role definitions and assignments, which needs Owner or
User Access Administrator. It is therefore applied by an operator with that
role, like `tools/aws-secrets`. Keep the state in restricted operator storage.

```sh
terraform -chdir=tools/azure-gateway-rollout-identity init
terraform -chdir=tools/azure-gateway-rollout-identity plan -out=identity.tfplan
terraform -chdir=tools/azure-gateway-rollout-identity apply identity.tfplan
```

Expected: one identity, one federated credential, four custom role
definitions, eight role assignments; nothing changed or destroyed.

Then, once:

```sh
# The workflow reads the identity's client id from this variable.
gh variable set AZURE_GATEWAY_ROLLOUT_CLIENT_ID --repo Lore-Hex/quill-cloud-proxy \
  --body "$(terraform -chdir=tools/azure-gateway-rollout-identity output -raw client_id)"
# The federated credential's subject names this environment; restrict it to main.
gh api -X PUT repos/Lore-Hex/quill-cloud-proxy/environments/azure-gateway-rollout \
  -F 'deployment_branch_policy[protected_branches]=false' -F 'deployment_branch_policy[custom_branch_policies]=true'
gh api -X POST repos/Lore-Hex/quill-cloud-proxy/environments/azure-gateway-rollout/deployment-branch-policies \
  -f name=main -f type=branch
```

The workflow also needs the GCP deploy identity (the shared rollout journal
and the Sydney Cloud DNS record): quill-router `infra/gcp_wif.tf` admits
`rollout-azure-gateway.yml@refs/heads/main`.

Azure managed-identity federated credentials match the token's `sub` exactly
and cannot test `job_workflow_ref`, so the environment is the narrowing: only
jobs that declare `environment: azure-gateway-rollout`, on main, can obtain a
token this identity accepts. Do not add the environment to another workflow.
