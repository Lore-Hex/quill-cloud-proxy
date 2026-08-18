#!/usr/bin/env bash
# Seed the Azure bootstrap bundle, the same way every other cloud gets seeded.
#
# Why this looks like tools/sync-secrets-to-aws.sh
# ================================================
# That script mirrors provider keys from GCP Secret Manager into AWS Secrets
# Manager, and says why: GCP stays the single source of truth, and the AWS
# enclave then consumes secrets from its OWN cloud's store the same way the GCP
# enclave consumes them from Secret Manager. Provisioning reads from GCP; the
# enclave never does.
#
# Azure is the same shape with one difference. Key Vault holds ONE secret - an
# encrypted bundle of all of them - because Key Vault's per-secret access is
# granted to an identity, and an identity is attached to a container group
# rather than to a measurement. Sealing the bundle to the SKR key means the
# managed identity can fetch it and still not read it: only a workload whose
# x-ms-sevsnpvm-hostdata matches the release policy can decrypt.
#
# An earlier version of this read from AWS Secrets Manager, which was simply
# wrong. AWS is a peer cloud, not a source of truth; it happened to hold most of
# these keys because it had been seeded the same way. Reading from it made Azure
# inherit whatever AWS was missing - the device-key blob, both advisor prompts,
# the cohere key - and turned a straightforward mirror into a two-source merge.
#
# SOURCE: --values FILE, a JSON object of {logical name: value} supplied by the
# deploy. There is no other source, deliberately - the same rule
# tools/sync-secrets-to-aws.sh now follows.
#
# Reading another cloud's secret store would make that cloud a hub every other
# one needs in order to be PROVISIONED: no cloud brought up, and no key rotated,
# while the hub is unreachable. A second source kept "for migration" is a second
# source somebody uses, and the two produce different bundles without saying
# which ran.
#
# WHAT THIS TOUCHES: every provider key in plaintext, in memory and in one
# mode-0600 temp file removed on every exit path. Secret NAMES are printed;
# values never are.
#
# Usage:
#   bash tools/azure-sync-secrets.sh --values ./secrets.json           # dry-run
#   bash tools/azure-sync-secrets.sh --values ./secrets.json --apply
set -euo pipefail

VAULT="${VAULT:-trquillkv}"
SKR_KEY="${SKR_KEY:-tr-bootstrap-wrap}"
BUNDLE_SECRET="${BUNDLE_SECRET:-tr-bootstrap-bundle}"
SEALER_PYTHON="${SEALER_PYTHON:-python3}"

APPLY=0
VALUES_IN=""
TEMPLATE_OUT=""
# The operator's own files. Provider keys are short tokens already living in an
# env file; prompts are multi-KB documents and the device blob is JSON, so those
# get one file each. See tools/quill_secret_sources.py.
KEYS_FILE="${KEYS_FILE:-$HOME/.quill_cloud_keys.private}"
SECRETS_DIR="${SECRETS_DIR:-$HOME/.quill-secrets}"
while [ $# -gt 0 ]; do
  case "$1" in
    --apply)     APPLY=1; shift ;;
    --values)    VALUES_IN="$2"; shift 2 ;;
    --keys-file)   KEYS_FILE="$2"; shift 2 ;;
    --secrets-dir) SECRETS_DIR="$2"; shift 2 ;;
    --template)  TEMPLATE_OUT="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/.." && pwd)"

env_json="$(mktemp)"; values_json="$(mktemp)"
chmod 600 "$env_json" "$values_json"
cleanup() {
  rm -f "$env_json" "$values_json"
  [ -z "${needed:-}" ] || rm -f "$needed"
  [ -z "${tmpl_env:-}" ] || rm -f "$tmpl_env"
  [ -z "${tmpl_needed:-}" ] || rm -f "$tmpl_needed"
}
trap cleanup EXIT

# --template gives the values file an origin.
#
# Without it, --values is required and NOTHING in either repo produces one: the
# operator is told to supply a file whose required key names exist only inside
# print-env. That is a flow with a hole in the middle, and it is the hole that
# opened when the GCP source was removed.
#
# This reads no secret store, so it is safe to run anywhere. It writes every
# required name with an empty value; the operator fills them from wherever they
# keep them.
if [ -n "$TEMPLATE_OUT" ]; then
  tmpl_env="$(mktemp)"; tmpl_needed="$(mktemp)"
  chmod 600 "$tmpl_env" "$tmpl_needed"
  RESOURCE_GROUP="${RESOURCE_GROUP:-TR-TEE-DUBAI}" \
  SKR_COMMAND="${SKR_COMMAND:-/bin/skr}" \
    bash "$repo/tools/deploy-azure-aci.sh" print-env > "$tmpl_env"
  "$SEALER_PYTHON" "$repo/tools/quill_secret_sources.py" \
    --required-from-env "$tmpl_env" "$tmpl_needed"
  "$SEALER_PYTHON" -c '
import json, sys
names = json.load(open(sys.argv[1]))
json.dump({n: "" for n in names}, open(sys.argv[2], "w"), indent=2, sort_keys=True)
print(f"[ok] wrote {sys.argv[2]} with {len(names)} empty entries")
print("     Fill each value from wherever you keep them, then:")
print(f"       bash tools/azure-sync-secrets.sh --values {sys.argv[2]} --apply")
print("     Every measured provider key is mandatory. If the deploy uses the")
print("     shared ACME cache, tr-cross-cloud-sa-key is mandatory too.")
' "$tmpl_needed" "$TEMPLATE_OUT"
  chmod 600 "$TEMPLATE_OUT"
  exit 0
fi

echo "==> rendering the deploy env (the bundle's key names come from it)"
# print-env is the single source of truth for which logical names the container
# group will ask for, and the env is MEASURED. Deriving the list any other way
# is how a bundle ends up valid for a measurement other than the one deployed -
# which surfaces as a 403 from Key Vault with nothing pointing at the cause.
RESOURCE_GROUP="${RESOURCE_GROUP:-TR-TEE-DUBAI}" \
SKR_COMMAND="${SKR_COMMAND:-/bin/skr}" \
  bash "$repo/tools/deploy-azure-aci.sh" print-env > "$env_json"

needed="$(mktemp)"; chmod 600 "$needed"
"$SEALER_PYTHON" "$repo/tools/quill_secret_sources.py" \
  --required-from-env "$env_json" "$needed"

if [ -n "$VALUES_IN" ]; then
  echo "==> using operator-supplied values: ${VALUES_IN}"
  cp "$VALUES_IN" "$values_json"
  "$SEALER_PYTHON" - "$needed" "$values_json" <<'PY'
import json, sys
names, values = (json.load(open(p)) for p in sys.argv[1:3])
have = [n for n in names if str(values.get(n, "")).strip()]
print(f"    required : {len(names)}")
print(f"    supplied : {len(have)}")
absent = [n for n in names if n not in have]
if absent:
    print(f"    ABSENT   : {absent}")
PY
else
  echo "==> resolving from your files"
  echo "    keys : ${KEYS_FILE}"
  echo "    dir  : ${SECRETS_DIR}"
  "$SEALER_PYTHON" "$repo/tools/quill_secret_sources.py" \
    "$needed" "$values_json" "$KEYS_FILE" "$SECRETS_DIR"
fi

if [ $APPLY -eq 0 ]; then
  echo
  echo "dry-run only. Re-run with --apply to seal and upload."
  exit 0
fi

echo "==> sealing to ${VAULT}/${SKR_KEY} and uploading as ${BUNDLE_SECRET}"
# --deploy-env makes the sealer validate against the SAME env the container
# group is measured with, so it cannot produce a bundle valid for a different
# measurement than the one being deployed.
"$SEALER_PYTHON" "$repo/tools/azure-seal-bundle.py" \
  --deploy-env "$env_json" \
  --values "$values_json" \
  --vault "$VAULT" \
  --key-name "$SKR_KEY" \
  --upload-secret "$BUNDLE_SECRET"

echo
echo "Sealed. Ciphertext at rest: the managed identity can fetch this secret"
echo "and still not read it — only a workload whose hostdata matches the SKR"
echo "release policy can decrypt it."
