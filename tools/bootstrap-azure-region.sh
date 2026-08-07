#!/usr/bin/env bash
#
# One-time prerequisites for a new Azure enclave region.
#
# tools/deploy-azure-aci.sh deliberately refuses to create these. Creating
# identities and role assignments from a deploy script is how a deploy pipeline
# quietly becomes a subscription admin: every run then carries the authority to
# grant itself vault access, and the blast radius of a compromised build stops
# being "ships a bad image" and starts being "reads the wrapping key". So the
# grants live here, run by a human, once per region.
#
#   LOCATION=southeastasia RESOURCE_GROUP=TR-TEE-SEA \
#     ./tools/bootstrap-azure-region.sh --apply
#
# Dry-run is the default and prints exactly what it would create.
#
# WHAT IS REGIONAL AND WHAT IS SHARED. The vault, the wrapping key and the
# registry are deliberately SHARED across regions: one key, `tr-bootstrap-wrap`,
# with a release policy carrying one `anyOf` clause per region's MAA authority.
# Per-region keys would mean per-region bundle re-sealing, and a bundle that
# drifts between regions is a provider that 401s in one region only — the
# failure shape this stack keeps paying for. What IS regional: the resource
# group, the MAA instance (attestation is a regional service and each region
# must attest against its own), the managed identity, and the container group.
#
# The cost of sharing is honest and should be recorded rather than hidden: the
# vault lives in UAE North, so a UAE North vault outage blocks a COLD START in
# every region. It does not touch a running enclave, which holds its unwrapped
# secrets in memory. That is the right trade while the alternative is bundle
# drift, but it is the reason a region loss is survivable and a vault loss is
# not.
#
# THE TRAP THIS SCRIPT EXISTS TO SPRING. Azure role assignments are eventually
# consistent. A deploy started seconds after the grant hits Key Vault 403 — and
# a 403 from a not-yet-propagated grant is byte-identical to a 403 from a
# HOST_DATA that does not match the release policy. One is fixed by waiting and
# the other by a re-bind, so guessing wrong costs a full deploy cycle in each
# direction. This script therefore does not return until it has PROVEN the
# grants are live, by reading the key as the identity would.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

LOCATION="${LOCATION:-}"
RESOURCE_GROUP="${RESOURCE_GROUP:-}"
IDENTITY_NAME="${IDENTITY_NAME:-tr-skr-identity}"
VAULT="${VAULT:-trquillkv}"
VAULT_GROUP="${VAULT_GROUP:-TR-TEE-DUBAI}"
ACR="${ACR:-trquillacr}"
ACR_GROUP="${ACR_GROUP:-TR-TEE-DUBAI}"
SKR_KEY="${SKR_KEY:-tr-bootstrap-wrap}"
PROPAGATION_TIMEOUT="${PROPAGATION_TIMEOUT:-300}"

APPLY=0
[[ "${1:-}" == "--apply" ]] && APPLY=1

die() { printf '\n[FAIL] %b\n' "$1" >&2; exit 1; }
ok()  { printf '[ok] %b\n' "$1"; }
step(){ printf '\n== %s\n' "$1"; }

[[ -n "$LOCATION" ]]       || die "LOCATION is required (e.g. southeastasia)"
[[ -n "$RESOURCE_GROUP" ]] || die "RESOURCE_GROUP is required (e.g. TR-TEE-SEA)"

SUB="$(az account show --query id -o tsv)"
VAULT_SCOPE="/subscriptions/${SUB}/resourceGroups/${VAULT_GROUP}/providers/Microsoft.KeyVault/vaults/${VAULT}"
ACR_SCOPE="/subscriptions/${SUB}/resourceGroups/${ACR_GROUP}/providers/Microsoft.ContainerRegistry/registries/${ACR}"

# The four grants, and why each one is needed. Dropping any of them produces a
# 403 at a DIFFERENT point in the boot, so the list is worth reading before
# trimming it:
#
#   Crypto Service Release User  release the wrapped key after attestation
#   Crypto Officer               read and re-bind the key's release policy —
#                                the deploy widens the policy to add this
#                                region's MAA authority
#   Secrets User                 read the sealed bundle
#   AcrPull                      pull the enclave image
GRANTS=(
  "Key Vault Crypto Service Release User|${VAULT_SCOPE}"
  "Key Vault Crypto Officer|${VAULT_SCOPE}"
  "Key Vault Secrets User|${VAULT_SCOPE}"
  "AcrPull|${ACR_SCOPE}"
)

step "plan"
printf '  subscription   %s\n' "$SUB"
printf '  region         %s (resource group %s)\n' "$LOCATION" "$RESOURCE_GROUP"
printf '  identity       %s\n' "$IDENTITY_NAME"
printf '  shared vault   %s (%s)\n' "$VAULT" "$VAULT_GROUP"
printf '  shared acr     %s (%s)\n' "$ACR" "$ACR_GROUP"
for g in "${GRANTS[@]}"; do printf '  grant          %s\n' "${g%%|*}"; done
if (( ! APPLY )); then
  printf '\nDRY RUN — nothing was created. Re-run with --apply.\n'
  exit 0
fi

step "resource group"
az group show -n "$RESOURCE_GROUP" >/dev/null 2>&1 \
  || die "resource group '$RESOURCE_GROUP' does not exist. Create it in $LOCATION first —
       this script grants access, it does not choose where a region lives."
ok "$RESOURCE_GROUP exists"

step "shared prerequisites"
az keyvault show -n "$VAULT" -g "$VAULT_GROUP" >/dev/null 2>&1 || die "vault $VAULT not found"
az keyvault key show --vault-name "$VAULT" --name "$SKR_KEY" >/dev/null 2>&1 \
  || die "wrapping key '$SKR_KEY' not found in $VAULT"
az acr show -n "$ACR" -g "$ACR_GROUP" >/dev/null 2>&1 || die "registry $ACR not found"
ok "vault, wrapping key and registry all present"

step "managed identity"
if az identity show -n "$IDENTITY_NAME" -g "$RESOURCE_GROUP" >/dev/null 2>&1; then
  ok "$IDENTITY_NAME already exists — reusing"
else
  az identity create -n "$IDENTITY_NAME" -g "$RESOURCE_GROUP" -l "$LOCATION" -o none
  ok "created $IDENTITY_NAME"
fi
PRINCIPAL_ID="$(az identity show -n "$IDENTITY_NAME" -g "$RESOURCE_GROUP" --query principalId -o tsv)"
[[ -n "$PRINCIPAL_ID" ]] || die "identity has no principalId"
printf '  principalId %s\n' "$PRINCIPAL_ID"

step "role assignments"
for g in "${GRANTS[@]}"; do
  role="${g%%|*}"; scope="${g##*|}"
  # --assignee-object-id with --assignee-principal-type skips the Graph lookup,
  # which fails for a just-created identity that has not replicated to AAD yet.
  if az role assignment create \
        --assignee-object-id "$PRINCIPAL_ID" \
        --assignee-principal-type ServicePrincipal \
        --role "$role" --scope "$scope" -o none 2>/dev/null; then
    ok "granted $role"
  else
    az role assignment list --assignee "$PRINCIPAL_ID" --scope "$scope" \
        --query "[?roleDefinitionName=='$role'] | [0].id" -o tsv | grep -q . \
      || die "could not grant '$role' on
       $scope
       and it is not already present. You likely lack User Access Administrator."
    ok "$role already granted"
  fi
done

step "prove the grants are live"
# Eventual consistency: assert rather than sleep-and-hope. Reading the key's
# release policy is the closest cheap proxy for what the deploy does first, and
# it exercises the same Crypto Officer grant the deploy needs to widen it.
deadline=$(( SECONDS + PROPAGATION_TIMEOUT ))
until az keyvault key show --vault-name "$VAULT" --name "$SKR_KEY" \
        --query 'releasePolicy.encodedPolicy' -o tsv >/dev/null 2>&1; do
  (( SECONDS < deadline )) || die "role assignments did not propagate within ${PROPAGATION_TIMEOUT}s"
  printf '  waiting for RBAC propagation...\n'
  sleep 15
done
ok "grants are live"

cat <<EOF

Region ${LOCATION} is ready for a deploy. The MAA instance is NOT created here —
attestation is regional and the deploy binds to whichever endpoint you name, so
confirm it exists and is Ready, then:

  export LOCATION=${LOCATION} RESOURCE_GROUP=${RESOURCE_GROUP}
  export MAA_ENDPOINT=<this region's MAA host>
  export API_HOST=<this region's api host>
  ./tools/deploy-azure-aci.sh --apply all

The deploy ADDS this region's authority to ${SKR_KEY}'s release policy. It must
report that it preserved the other regions' clauses — if it does not, those
regions keep serving but fail their next COLD START, which is the quietest
possible way to lose a region.
EOF
