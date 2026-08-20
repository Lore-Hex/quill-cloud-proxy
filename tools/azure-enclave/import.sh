#!/usr/bin/env bash
# Adopt the Azure enclave scaffolding that already exists into terraform state.
#
# Every resource here was created by hand before this configuration existed, so
# a first `terraform apply` without importing would try to CREATE resources that
# are already there. For the resource group and the managed identities that is
# merely an error; for the attestation providers it would be worse, because the
# provider's URI is named verbatim in the SKR key's release policy.
#
# Safe to re-run: anything already in state is skipped, and anything that does
# not exist in Azure yet is skipped too (terraform apply creates those). In
# particular Sydney's four role assignments are expected to be ABSENT on first
# run -- creating them is a privilege change, which is the one thing this repo
# deliberately leaves to a human running `terraform apply`.
#
# Usage:  bash tools/azure-enclave/import.sh
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

SUB="${SUBSCRIPTION_ID:-2fc83893-ca6c-48e4-b090-8860fba33d33}"
IDENTITY_NAME="${IDENTITY_NAME:-tr-skr-identity}"
SHARED_RG="${SHARED_RG:-TR-TEE-DUBAI}"
VAULT="${VAULT:-trquillkv}"
ACR="${ACR:-trquillacr}"
ACME_SA="${ACME_SA:-trquillacmecache}"

KV_ID="/subscriptions/${SUB}/resourceGroups/${SHARED_RG}/providers/Microsoft.KeyVault/vaults/${VAULT}"
ACR_ID="/subscriptions/${SUB}/resourceGroups/${SHARED_RG}/providers/Microsoft.ContainerRegistry/registries/${ACR}"
SA_ID="/subscriptions/${SUB}/resourceGroups/${SHARED_RG}/providers/Microsoft.Storage/storageAccounts/${ACME_SA}"

# region | resource group | attestation provider | owns its resource group
REGIONS=(
  "uaenorth|TR-TEE-DUBAI|trquilluaen|false"
  "australiaeast|tr-tee-sydney|trquillsyd|true"
)

# terraform address | role name | scope
ROLES=(
  "kv_release|Key Vault Crypto Service Release User|${KV_ID}"
  "kv_secrets|Key Vault Secrets User|${KV_ID}"
  "acr_pull|AcrPull|${ACR_ID}"
  "acme_blob|Storage Blob Data Contributor|${SA_ID}"
  "kv_crypto_officer|Key Vault Crypto Officer|${KV_ID}"
)

# Snapshot the state once. Re-running `terraform state list` per resource hid a
# real failure behind 2>/dev/null: any error (config error, held lock) produced
# empty output, which reads identically to "not in state" and sent the script on
# to import something it already managed.
STATE_SNAPSHOT="$(terraform state list)" || {
  echo "terraform state list failed; refusing to guess what is already managed" >&2
  exit 1
}

in_state() { printf '%s\n' "$STATE_SNAPSHOT" | grep -qxF "$1"; }

# Keep the snapshot honest as we import.
remember() { STATE_SNAPSHOT="${STATE_SNAPSHOT}"$'\n'"$1"; }

adopt() {
  local addr="$1" id="$2"
  if in_state "$addr"; then
    echo "  already in state: ${addr}"
    return
  fi
  if [ -z "$id" ] || [ "$id" = "null" ]; then
    echo "  not in Azure yet, terraform apply will create it: ${addr}"
    return
  fi
  # ARM hands back user-assigned identity ids with a lowercase "resourcegroups"
  # segment, and the azurerm provider's ID parser rejects anything but the
  # camel-cased "resourceGroups". Azure accepts both; terraform does not.
  id="$(printf %s "$id" | sed 's#/resourcegroups/#/resourceGroups/#')"
  terraform import -input=false "$addr" "$id" >/dev/null && { remember "$addr"; echo "  imported: ${addr}"; }
}

for spec in "${REGIONS[@]}"; do
  IFS='|' read -r region rg maa owns <<<"$spec"
  echo "=== ${region}"

  if [ "$owns" = "true" ]; then
    rg_id="$(az group show -n "$rg" --query id -o tsv 2>/dev/null || true)"
    adopt "azurerm_resource_group.region[\"${region}\"]" "$rg_id"
  else
    echo "  resource group ${rg} is shared, not managed here"
  fi

  mi_id="$(az identity show -g "$rg" -n "$IDENTITY_NAME" --query id -o tsv 2>/dev/null || true)"
  adopt "azurerm_user_assigned_identity.skr[\"${region}\"]" "$mi_id"

  maa_id="$(az attestation show -g "$rg" -n "$maa" --query id -o tsv 2>/dev/null || true)"
  adopt "azurerm_attestation_provider.maa[\"${region}\"]" "$maa_id"

  mi_pid="$(az identity show -g "$rg" -n "$IDENTITY_NAME" --query principalId -o tsv 2>/dev/null || true)"
  if [ -z "$mi_pid" ]; then
    echo "  no identity yet; skipping role assignments"
    continue
  fi

  for role_spec in "${ROLES[@]}"; do
    IFS='|' read -r key role scope <<<"$role_spec"
    # Only Dubai declares Crypto Officer (grant_crypto_officer). Probing for it
    # elsewhere would print "terraform apply will create it" about an address
    # the configuration deliberately does not contain -- the opposite of true.
    if [ "$key" = "kv_crypto_officer" ] && [ "$region" != "uaenorth" ]; then
      continue
    fi
    # --scope alone still returns inherited assignments from parent scopes, so
    # filter on the exact scope too: importing an inherited subscription-level
    # assignment would put terraform in charge of a grant it did not make.
    ra_id="$(az role assignment list --assignee "$mi_pid" --scope "$scope" \
      --query "[?roleDefinitionName=='${role}' && scope=='${scope}'].id | [0]" -o tsv 2>/dev/null || true)"
    adopt "azurerm_role_assignment.enclave[\"${region}:${key}\"]" "$ra_id"
  done
done

echo
echo "=== drift after import (expect: Sydney's 4 role assignments to add, nothing to destroy)"
terraform plan -input=false -no-color 2>&1 | tail -5
