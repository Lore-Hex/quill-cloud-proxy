# The Azure identity rollout-azure-gateway.yml logs in as, and exactly what it
# may change. Operator-applied (see README.md): creating an identity, custom
# roles and role assignments needs Owner or User Access Administrator, which
# no deploy identity holds by design.

terraform {
  required_version = ">= 1.7, < 2.0"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
  }
}

provider "azurerm" {
  features {}
  subscription_id                 = local.subscription_id
  resource_provider_registrations = "none"
}

locals {
  subscription_id = "2fc83893-ca6c-48e4-b090-8860fba33d33"
  subscription    = "/subscriptions/${local.subscription_id}"
  # The only token this identity accepts: a job of rollout-azure-gateway.yml
  # in this GitHub environment, whose deployment branch policy admits main
  # only. A plain `ref:refs/heads/main` subject would admit every workflow on
  # main; Azure managed-identity federated credentials match `sub` exactly
  # and cannot see job_workflow_ref, so the environment is the narrowing.
  github_subject = "repo:Lore-Hex/quill-cloud-proxy:environment:azure-gateway-rollout"

  enclave_groups = {
    dubai  = "${local.subscription}/resourceGroups/TR-TEE-DUBAI"
    sydney = "${local.subscription}/resourceGroups/tr-tee-sydney"
  }
  registry        = "${local.subscription}/resourceGroups/TR-TEE-DUBAI/providers/Microsoft.ContainerRegistry/registries/trquillacr"
  wrapping_key    = "${local.subscription}/resourceGroups/TR-TEE-DUBAI/providers/Microsoft.KeyVault/vaults/trquillkv/keys/tr-bootstrap-wrap"
  acme_storage    = "${local.subscription}/resourceGroups/TR-TEE-DUBAI/providers/Microsoft.Storage/storageAccounts/trquillacmecache"
  traffic_manager = "${local.subscription}/resourceGroups/tr-azure/providers/Microsoft.Network/trafficManagerProfiles/trquill-azure-gw"
}

resource "azurerm_user_assigned_identity" "rollout" {
  name                = "tr-gateway-rollout"
  resource_group_name = "tr-azure"
  location            = "uaenorth"
  tags = {
    purpose = "quill-cloud-proxy rollout-azure-gateway.yml"
  }
}

resource "azurerm_federated_identity_credential" "github" {
  name                = "quill-cloud-proxy-azure-gateway-rollout"
  resource_group_name = azurerm_user_assigned_identity.rollout.resource_group_name
  parent_id           = azurerm_user_assigned_identity.rollout.id
  issuer              = "https://token.actions.githubusercontent.com"
  subject             = local.github_subject
  audience            = ["api://AzureADTokenExchange"]
}

# tools/deploy-azure-aci.sh in the two enclave resource groups: read, delete
# and recreate the confidential container group through an ARM deployment that
# assigns the existing tr-skr-identity, read its logs. No network, vault,
# storage or authorization action.
resource "azurerm_role_definition" "enclave" {
  name        = "TR Gateway Rollout - Enclave Container Groups"
  scope       = local.subscription
  description = "rollout-azure-gateway.yml: replace the regional quill-enclave confidential container group."
  permissions {
    actions = [
      "Microsoft.ContainerInstance/containerGroups/read",
      "Microsoft.ContainerInstance/containerGroups/write",
      "Microsoft.ContainerInstance/containerGroups/delete",
      "Microsoft.ContainerInstance/containerGroups/containers/logs/read",
      "Microsoft.ContainerInstance/locations/operations/read",
      "Microsoft.Resources/deployments/read",
      "Microsoft.Resources/deployments/write",
      "Microsoft.Resources/deployments/validate/action",
      "Microsoft.Resources/deployments/operations/read",
      "Microsoft.Resources/deployments/operationstatuses/read",
      "Microsoft.Resources/subscriptions/resourceGroups/read",
      "Microsoft.ManagedIdentity/userAssignedIdentities/read",
      "Microsoft.ManagedIdentity/userAssignedIdentities/assign/action",
    ]
  }
  assignable_scopes = values(local.enclave_groups)
}

resource "azurerm_role_assignment" "enclave" {
  for_each           = local.enclave_groups
  scope              = each.value
  role_definition_id = azurerm_role_definition.enclave.role_definition_resource_id
  principal_id       = azurerm_user_assigned_identity.rollout.principal_id
  principal_type     = "ServicePrincipal"
}

# `az acr build` (a registry task run) and the digest lookup after it.
resource "azurerm_role_definition" "registry_build" {
  name        = "TR Gateway Rollout - Registry Build"
  scope       = local.subscription
  description = "rollout-azure-gateway.yml: run az acr build on trquillacr."
  permissions {
    actions = [
      "Microsoft.ContainerRegistry/registries/read",
      "Microsoft.ContainerRegistry/registries/listBuildSourceUploadUrl/action",
      "Microsoft.ContainerRegistry/registries/scheduleRun/action",
      "Microsoft.ContainerRegistry/registries/runs/read",
      "Microsoft.ContainerRegistry/registries/runs/listLogSasUrl/action",
    ]
  }
  assignable_scopes = [local.registry]
}

resource "azurerm_role_assignment" "registry_build" {
  scope              = local.registry
  role_definition_id = azurerm_role_definition.registry_build.role_definition_resource_id
  principal_id       = azurerm_user_assigned_identity.rollout.principal_id
  principal_type     = "ServicePrincipal"
}

# Push the built image; pull it for `az confcom acipolicygen`.
resource "azurerm_role_assignment" "registry_push" {
  scope                = local.registry
  role_definition_name = "AcrPush"
  principal_id         = azurerm_user_assigned_identity.rollout.principal_id
  principal_type       = "ServicePrincipal"
}

# bind (widen), verify, narrow and rollback read and set the release policy of
# the one wrapping key. Scoped to that key, not the vault: no secret, no other
# key. This is the same authority the measured deploy has always needed; the
# narrow happens only after the new measurement is public.
resource "azurerm_role_assignment" "wrapping_key" {
  scope                = local.wrapping_key
  role_definition_name = "Key Vault Crypto Officer"
  principal_id         = azurerm_user_assigned_identity.rollout.principal_id
  principal_type       = "ServicePrincipal"
}

# The deploy preflight reads the ACME cache account's security settings, its
# migration marker (container metadata, through ARM) and the regional
# identities' role assignments on it. Reader: no data-plane access to blobs.
resource "azurerm_role_assignment" "acme_storage_reader" {
  scope                = local.acme_storage
  role_definition_name = "Reader"
  principal_id         = azurerm_user_assigned_identity.rollout.principal_id
  principal_type       = "ServicePrincipal"
}

# The preflight resolves the "Storage Blob Data Contributor" definition by
# name at subscription scope.
resource "azurerm_role_definition" "role_definition_reader" {
  name        = "TR Gateway Rollout - Role Definition Reader"
  scope       = local.subscription
  description = "rollout-azure-gateway.yml: resolve built-in role definitions by name."
  permissions {
    actions = ["Microsoft.Authorization/roleDefinitions/read"]
  }
  assignable_scopes = [local.subscription]
}

resource "azurerm_role_assignment" "role_definition_reader" {
  scope              = local.subscription
  role_definition_id = azurerm_role_definition.role_definition_reader.role_definition_resource_id
  principal_id       = azurerm_user_assigned_identity.rollout.principal_id
  principal_type     = "ServicePrincipal"
}

# Drain and re-enable one region's endpoint of the shared hostname's profile.
resource "azurerm_role_definition" "traffic_manager_endpoints" {
  name        = "TR Gateway Rollout - Traffic Manager Endpoints"
  scope       = local.subscription
  description = "rollout-azure-gateway.yml: disable and enable trquill-azure-gw endpoints."
  permissions {
    actions = [
      "Microsoft.Network/trafficManagerProfiles/read",
      "Microsoft.Network/trafficManagerProfiles/externalEndpoints/read",
      "Microsoft.Network/trafficManagerProfiles/externalEndpoints/write",
    ]
  }
  assignable_scopes = [local.traffic_manager]
}

resource "azurerm_role_assignment" "traffic_manager_endpoints" {
  scope              = local.traffic_manager
  role_definition_id = azurerm_role_definition.traffic_manager_endpoints.role_definition_resource_id
  principal_id       = azurerm_user_assigned_identity.rollout.principal_id
  principal_type     = "ServicePrincipal"
}

output "client_id" {
  description = "Set as the quill-cloud-proxy repository variable AZURE_GATEWAY_ROLLOUT_CLIENT_ID."
  value       = azurerm_user_assigned_identity.rollout.client_id
}
