#!/usr/bin/env bash
# Provision the Azure-local, encrypted ACME cache used by Azure confidential
# containers. Dry-run is the default. This tool creates infrastructure only;
# it never reads provider keys or certificate material.
set -euo pipefail

APPLY=0
for arg in "$@"; do
  case "$arg" in
    --apply) APPLY=1 ;;
    -h|--help)
      sed -n '2,42p' "${BASH_SOURCE[0]}"
      exit 0
      ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

SUBSCRIPTION="${SUBSCRIPTION:-}"
RESOURCE_GROUP="${AZURE_ACME_STORAGE_RESOURCE_GROUP:-TR-TEE-DUBAI}"
LOCATION="${AZURE_ACME_STORAGE_LOCATION:-uaenorth}"
ACCOUNT="${AZURE_ACME_STORAGE_ACCOUNT:-trquillacmecache}"
CONTAINER="${AZURE_ACME_STORAGE_CONTAINER:-acme-cache}"
SKU="${AZURE_ACME_STORAGE_SKU:-Standard_GRS}"
KEY_FILE="${AZURE_ACME_CACHE_KEY_FILE:-$HOME/.quill-secrets/tr-azure-acme-cache-key}"
IDENTITIES="${AZURE_ACME_IDENTITIES:-TR-TEE-DUBAI/tr-skr-identity,TR-TEE-SEA/tr-skr-identity}"
ROLE="Storage Blob Data Contributor"

log() { printf '==> %s\n' "$*" >&2; }
die() { printf '[FAIL] %s\n' "$*" >&2; exit 1; }
run() {
  if [ "$APPLY" = "1" ]; then
    "$@"
  else
    printf '+ ' >&2
    printf '%q ' "$@" >&2
    printf '\n' >&2
  fi
}

command -v az >/dev/null 2>&1 || die "az is required"
az account show >/dev/null 2>&1 || die "Azure login required: run az login"
if [ -n "$SUBSCRIPTION" ]; then
  run az account set --subscription "$SUBSCRIPTION"
fi
SUBSCRIPTION_ID="$(az account show --query id -o tsv)"
[ -n "$SUBSCRIPTION_ID" ] || die "could not resolve the active Azure subscription"

if ! az group show --name "$RESOURCE_GROUP" >/dev/null 2>&1; then
  die "resource group $RESOURCE_GROUP does not exist"
fi

if az storage account show --resource-group "$RESOURCE_GROUP" --name "$ACCOUNT" >/dev/null 2>&1; then
  log "storage account exists: $ACCOUNT"
else
  log "creating storage account: $ACCOUNT"
  run az storage account create \
    --resource-group "$RESOURCE_GROUP" \
    --name "$ACCOUNT" \
    --location "$LOCATION" \
    --sku "$SKU" \
    --kind StorageV2 \
    --https-only true \
    --min-tls-version TLS1_2 \
    --allow-blob-public-access false \
    --allow-shared-key-access false \
    --public-network-access Enabled \
    --output none
fi

ACCOUNT_ID="/subscriptions/${SUBSCRIPTION_ID}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.Storage/storageAccounts/${ACCOUNT}"
CONTAINER_URL="https://management.azure.com${ACCOUNT_ID}/blobServices/default/containers/${CONTAINER}?api-version=2023-05-01"
if az rest --method get --url "$CONTAINER_URL" >/dev/null 2>&1; then
  log "private blob container exists: $CONTAINER"
else
  log "creating private blob container: $CONTAINER"
  run az rest --method put --url "$CONTAINER_URL" \
    --headers Content-Type=application/json \
    --body '{"properties":{"publicAccess":"None"}}' \
    --output none
fi

IFS=',' read -r -a identity_specs <<< "$IDENTITIES"
for spec in "${identity_specs[@]}"; do
  spec="${spec//[[:space:]]/}"
  identity_rg="${spec%%/*}"
  identity_name="${spec#*/}"
  [ -n "$identity_rg" ] && [ "$identity_name" != "$spec" ] || die "invalid identity coordinate: $spec"
  principal_id="$(az identity show --resource-group "$identity_rg" --name "$identity_name" --query principalId -o tsv 2>/dev/null || true)"
  [ -n "$principal_id" ] || die "identity not found: $spec"
  assignment="$(az role assignment list \
    --assignee "$principal_id" \
    --scope "$ACCOUNT_ID" \
    --role "$ROLE" \
    --query '[0].id' -o tsv 2>/dev/null || true)"
  if [ -n "$assignment" ]; then
    log "$spec already has $ROLE"
  else
    log "granting $ROLE to $spec"
    run az role assignment create \
      --assignee-object-id "$principal_id" \
      --assignee-principal-type ServicePrincipal \
      --role "$ROLE" \
      --scope "$ACCOUNT_ID" \
      --output none
  fi
done

if [ -f "$KEY_FILE" ]; then
  python3 - "$KEY_FILE" <<'PY'
import base64, pathlib, sys
path = pathlib.Path(sys.argv[1])
raw = path.read_text(encoding="ascii").strip()
try:
    key = base64.b64decode(raw, validate=True)
except Exception as exc:
    raise SystemExit(f"[FAIL] {path} is not standard base64: {exc}")
if len(key) != 32:
    raise SystemExit(f"[FAIL] {path} decodes to {len(key)} bytes; want 32")
print(f"==> Azure cache key exists and is valid: {path}", file=sys.stderr)
PY
elif [ "$APPLY" = "1" ]; then
  log "generating Azure-only cache encryption key: $KEY_FILE"
  install -d -m 700 "$(dirname "$KEY_FILE")"
  umask 077
  python3 - "$KEY_FILE" <<'PY'
import base64, os, pathlib, sys
path = pathlib.Path(sys.argv[1])
if path.exists():
    raise SystemExit(f"refusing to overwrite {path}")
path.write_text(base64.b64encode(os.urandom(32)).decode("ascii") + "\n", encoding="ascii")
path.chmod(0o600)
PY
else
  log "would generate Azure-only cache encryption key: $KEY_FILE"
fi

if [ "$APPLY" = "1" ]; then
  log "Azure ACME storage is ready"
  printf 'Next: migrate the existing cache, then reseal the Azure bundle:\n' >&2
  printf '  python3 tools/migrate-acme-cache-gcs-to-azure.py --apply\n' >&2
  printf '  bash tools/azure-sync-secrets.sh --apply\n' >&2
else
  log "dry-run only; re-run with --apply"
fi
