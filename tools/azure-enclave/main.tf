// Azure enclave region SCAFFOLDING, declared once so a new region is a map
// entry rather than a sequence of remembered `az` commands.
//
// ---------------------------------------------------------------------------
// WHAT THIS DOES *NOT* MANAGE, AND WHY
// ---------------------------------------------------------------------------
// The container group itself is deliberately absent. Its CCE policy hash is a
// function of the ENTIRE container definition -- image digest, every env var
// name AND value, resources, the sidecar -- so it changes on essentially every
// deploy, and the Key Vault release policy must be WIDENED to {old,new} before
// the group is created and NARROWED to {new} only after a live attestation has
// been checked against what the key actually expects.
//
// A single `terraform apply` that swapped that pin in one step is precisely the
// failure tools/deploy-azure-aci.sh's header warns about: a confidential group
// must be deleted before it can be recreated, so a create that fails for an
// ordinary reason (ACR pull, capacity, quota) would leave no group AND no way
// back. Plan/apply cannot express "widen, create, verify against ground truth,
// narrow". So the measured deploy stays in that script, and this file owns only
// the parts that are genuinely static:
//
//     terraform  ->  resource group, managed identity, attestation provider,
//                    role assignments
//     the script ->  build, template, policy, bind, deploy, verify, narrow
//
// The SKR key (tr-bootstrap-wrap) is NOT managed here for the same reason, and
// one more: it is the single key that gates every provider secret on Azure. A
// terraform resource that could replace it is a terraform resource that could
// destroy the platform.
//
// ---------------------------------------------------------------------------
// STATE
// ---------------------------------------------------------------------------
// Local state, matching tools/dns. That is a deliberate limitation, not an
// oversight: a remote backend would have to live in some cloud, and putting
// Azure's bring-up state in AWS or GCP would make one cloud a prerequisite for
// provisioning another -- the exact hub dependency the multi-cloud split exists
// to avoid (see scripts/deploy/azure_control_plane.sh in quill-router). Until
// there is an Azure-local state container, treat `terraform plan` here as a
// DRIFT DETECTOR run by one operator, and import before you apply.
//
// Adopting the resources that already exist (one-time, per resource):
//   terraform import 'azurerm_resource_group.region["australiaeast"]' \
//     /subscriptions/<sub>/resourceGroups/tr-tee-sydney
//   terraform import 'azurerm_user_assigned_identity.skr["australiaeast"]' \
//     /subscriptions/<sub>/resourceGroups/tr-tee-sydney/providers/Microsoft.ManagedIdentity/userAssignedIdentities/tr-skr-identity
//   ... see README.md for the full list.

terraform {
  required_version = ">= 1.5"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.100"
    }
  }
}

provider "azurerm" {
  subscription_id = var.subscription_id
  features {}
}

// ---------------------------------------------------------------------------
// Shared, cross-region resources. READ-ONLY on purpose.
//
// trquillkv, trquillacr and trquillacmecache all live in TR-TEE-DUBAI for
// historical reasons -- Dubai was the first region -- so that resource group is
// NOT a per-region resource and must never be managed (or destroyed) by a
// per-region lifecycle. Every region's identity is granted rights ON these.
// ---------------------------------------------------------------------------
data "azurerm_key_vault" "shared" {
  name                = var.shared_vault_name
  resource_group_name = var.shared_resource_group
}

data "azurerm_container_registry" "shared" {
  name                = var.shared_acr_name
  resource_group_name = var.shared_resource_group
}

data "azurerm_storage_account" "acme_cache" {
  name                = var.shared_acme_storage_account
  resource_group_name = var.shared_resource_group
}

locals {
  // Regions whose resource group this configuration owns. Dubai's is excluded
  // because it also holds the shared vault/registry/storage above.
  owned_groups = {
    for name, cfg in var.regions : name => cfg if cfg.manage_resource_group
  }

  // The four grants an enclave identity actually needs.
  //
  //   crypto service release user -> exchange an attestation for the SKR key
  //   secrets user                -> read the sealed bootstrap bundle
  //   acr pull                    -> pull the enclave image
  //   storage blob data contributor -> share the ACME cert cache
  //
  // "Key Vault Crypto Officer" is deliberately NOT in this list even though
  // Dubai's identity holds it. That role lets a workload rewrite the release
  // policy that constrains it, which collapses the SKR guarantee: a compromised
  // enclave could authorise any future workload, including a non-confidential
  // one. Rebinding is an OPERATOR action (deploy-azure-aci.sh bind/narrow runs
  // under the operator's own credential), so the identity never needs it.
  // var.regions[*].grant_crypto_officer exists only to describe Dubai's
  // existing, pre-import reality honestly -- do not set it true for new regions.
  base_roles = {
    kv_release = { role = "Key Vault Crypto Service Release User", scope = data.azurerm_key_vault.shared.id }
    kv_secrets = { role = "Key Vault Secrets User", scope = data.azurerm_key_vault.shared.id }
    acr_pull   = { role = "AcrPull", scope = data.azurerm_container_registry.shared.id }
    acme_blob  = { role = "Storage Blob Data Contributor", scope = data.azurerm_storage_account.acme_cache.id }
  }

  // Flattened {region, role} pairs, plus Crypto Officer only where a region
  // explicitly admits to having it.
  region_roles = merge(
    {
      for pair in setproduct(keys(var.regions), keys(local.base_roles)) :
      "${pair[0]}:${pair[1]}" => {
        region = pair[0]
        role   = local.base_roles[pair[1]].role
        scope  = local.base_roles[pair[1]].scope
      }
    },
    {
      for name, cfg in var.regions : "${name}:kv_crypto_officer" => {
        region = name
        role   = "Key Vault Crypto Officer"
        scope  = data.azurerm_key_vault.shared.id
      } if cfg.grant_crypto_officer
    },
  )
}

resource "azurerm_resource_group" "region" {
  for_each = local.owned_groups

  name     = each.value.resource_group
  location = each.key

  lifecycle {
    // Destroying a region's group takes the managed identity with it, and the
    // identity's principal id is what the role assignments and the running
    // enclave's SKR exchange are bound to.
    prevent_destroy = true
  }
}

resource "azurerm_user_assigned_identity" "skr" {
  for_each = var.regions

  name                = var.identity_name
  resource_group_name = each.value.resource_group
  location            = each.key

  lifecycle {
    // A replaced identity gets a NEW principal id, which silently invalidates
    // every role assignment below and leaves the enclave unable to release its
    // key on the next cold start.
    prevent_destroy = true
  }

  depends_on = [azurerm_resource_group.region]
}

resource "azurerm_attestation_provider" "maa" {
  for_each = var.regions

  name                = each.value.attestation_provider
  resource_group_name = each.value.resource_group
  location            = each.key

  lifecycle {
    // The provider's attest URI is named verbatim in the SKR key's release
    // policy (`authority`). Recreating it under a new name would strand the
    // region: attestations would be issued by an authority the key does not
    // trust, and the enclave would get a 403 it cannot explain.
    prevent_destroy = true

    // MAA seeds a default policy per attestation type on creation. Leaving them
    // unset in config reads to the provider as "remove these", which it
    // refuses, so every one has to be ignored explicitly.
    //
    // None of them is the control this fleet actually relies on. What decides
    // whether an enclave gets its secrets is the SKR key's release policy,
    // which pins (this provider's authority URI + the CCE policy hash) -- see
    // tools/deploy-azure-aci.sh. These are MAA's own defaults for evaluating a
    // report; we neither set nor version them, so tracking them here would
    // report drift we have no opinion about.
    ignore_changes = [
      open_enclave_policy_base64,
      sgx_enclave_policy_base64,
      tpm_policy_base64,
      sev_snp_policy_base64,
    ]
  }

  depends_on = [azurerm_resource_group.region]
}

resource "azurerm_role_assignment" "enclave" {
  for_each = local.region_roles

  principal_id         = azurerm_user_assigned_identity.skr[each.value.region].principal_id
  role_definition_name = each.value.role
  scope                = each.value.scope

  // Terraform would otherwise try to resolve the principal before the identity
  // has propagated through AAD, which fails intermittently on first apply.
  skip_service_principal_aad_check = true
}
