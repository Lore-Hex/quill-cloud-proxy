#!/usr/bin/env bash
# Seed the Azure bootstrap bundle from the AWS copies of the provider secrets.
#
# Azure must hold its OWN copies of the keys. Booting it from Google Secret
# Manager would mean the enclave cannot start when GCP is down, which voids the
# independence a separate cloud exists for. AWS already replicated these 35+
# secrets into eu-west-3 for exactly the same reason, so that region is the
# nearest authoritative source and this script copies from there.
#
# WHAT THIS TOUCHES: every provider API key, in plaintext, in memory and in one
# mode-0600 temp file that is removed on exit. It prints secret NAMES and never
# values. Run it from a machine you would already trust with those keys - it is
# the same trust boundary as `aws secretsmanager get-secret-value`.
#
# The output is ONE Key Vault secret containing an encrypted envelope that only
# an attested workload can open: the bundle is sealed to the SKR key's public
# half, and the private half is released solely to a workload whose
# x-ms-sevsnpvm-hostdata matches the release policy. A reader with the managed
# identity gets ciphertext.
#
# Usage:
#   bash tools/azure-seed-bundle-from-aws.sh            # dry-run: report coverage
#   bash tools/azure-seed-bundle-from-aws.sh --apply    # seal and upload
set -euo pipefail

SRC_REGION="${SRC_REGION:-eu-west-3}"
SECRET_PREFIX="${SECRET_PREFIX:-quill/}"
VAULT="${VAULT:-trquillkv}"
SKR_KEY="${SKR_KEY:-tr-bootstrap-wrap}"
BUNDLE_SECRET="${BUNDLE_SECRET:-tr-bootstrap-bundle}"
SEALER_PYTHON="${SEALER_PYTHON:-python3}"
# Fallback source for the secrets AWS never held (device keys, advisor prompts,
# some provider keys). Provisioning-time only; see the note at the fallback.
GCP_PROJECT="${GCP_PROJECT:-quill-cloud-proxy}"
GCP_ACCOUNT="${GCP_ACCOUNT:-tr-deploy@quill-cloud-proxy.iam.gserviceaccount.com}"

APPLY=0
[ "${1:-}" = "--apply" ] && APPLY=1

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/.." && pwd)"

env_json="$(mktemp)"; values_json="$(mktemp)"
chmod 600 "$env_json" "$values_json"
# The values file holds every provider key. Remove it on ANY exit path,
# including a failure midway through the AWS reads.
trap 'rm -f "$env_json" "$values_json"' EXIT

echo "==> rendering the deploy env (the bundle's key names come from it)"
# print-env is the single source of truth for which logical names the container
# group will ask for. Deriving them any other way is how a bundle ends up valid
# for a measurement that is not the one being deployed.
RESOURCE_GROUP="${RESOURCE_GROUP:-TR-TEE-DUBAI}" \
SKR_COMMAND="${SKR_COMMAND:-/bin/skr}" \
  bash "$repo/tools/deploy-azure-aci.sh" print-env > "$env_json"

echo "==> reading secrets from ${SRC_REGION}"
"$SEALER_PYTHON" - "$env_json" "$values_json" "$SRC_REGION" "$SECRET_PREFIX" "$GCP_PROJECT" "$GCP_ACCOUNT" <<'PY'
import json, subprocess, sys

env_path, values_path, region, prefix, gcp_project, gcp_account = sys.argv[1:7]
env = json.load(open(env_path))

# Only QUILL_*_SECRET entries name bundle keys -- with one exception that is
# not cosmetic. QUILL_AZURE_BUNDLE_SECRET names the Key Vault secret this script
# WRITES; treating it as a bundle key makes the script hunt for a secret that by
# definition cannot exist yet, and report a self-inflicted "missing" that hides
# the real gaps underneath it.
EXCLUDED = {"QUILL_AZURE_BUNDLE_SECRET"}
names = sorted({
    v for k, v in env.items()
    if k.startswith("QUILL_") and k.endswith("_SECRET") and k not in EXCLUDED
})

values, missing, from_gcp = {}, [], []
for name in names:
    proc = subprocess.run(
        ["aws", "secretsmanager", "get-secret-value", "--region", region,
         "--secret-id", f"{prefix}{name}", "--query", "SecretString", "--output", "text"],
        capture_output=True, text=True,
    )
    # A trailing newline in a stored secret becomes a 401 that looks like a bad
    # key, so strip exactly the newline the CLI adds and nothing else.
    if proc.returncode == 0 and proc.stdout.strip():
        values[name] = proc.stdout.rstrip("\n")
        continue

    # AWS is an INCOMPLETE source. It never held the device-key blob, the
    # advisor prompts, or every provider key -- those live only in Google
    # Secret Manager. Falling back to it here is a one-time PROVISIONING copy,
    # which is a different thing from the enclave calling Google at BOOT: the
    # sealed bundle is what Azure reads at runtime, and nothing in that path
    # touches Google.
    gproc = subprocess.run(
        ["gcloud", "secrets", "versions", "access", "latest",
         "--secret", name, "--project", gcp_project, "--account", gcp_account],
        capture_output=True, text=True,
    )
    if gproc.returncode == 0 and gproc.stdout.strip():
        values[name] = gproc.stdout.rstrip("\n")
        from_gcp.append(name)
    else:
        missing.append(name)

json.dump(values, open(values_path, "w"))
print(f"    required : {len(names)}")
print(f"    resolved : {len(values)}  (AWS {len(values)-len(from_gcp)}, GCP fallback {len(from_gcp)})")
if from_gcp:
    print(f"    via GCP  : {sorted(from_gcp)}")
if missing:
    print(f"    MISSING  : {missing}")
    print("    A missing provider key does not stop the enclave booting; that")
    print("    provider is simply unavailable on this cloud. A missing")
    print("    device-keys blob DOES stop it, and the sealer refuses that.")
PY

if [ $APPLY -eq 0 ]; then
  echo
  echo "dry-run only. Re-run with --apply to seal and upload."
  exit 0
fi

echo "==> sealing to ${VAULT}/${SKR_KEY} and uploading as ${BUNDLE_SECRET}"
# --deploy-env makes the sealer validate the bundle against the SAME env the
# container group will be measured with, so it refuses to produce a bundle that
# is valid for a different measurement than the one being deployed.
"$SEALER_PYTHON" "$repo/tools/azure-seal-bundle.py" \
  --deploy-env "$env_json" \
  --values "$values_json" \
  --vault "$VAULT" \
  --key-name "$SKR_KEY" \
  --upload-secret "$BUNDLE_SECRET"

echo
echo "Sealed. The bundle is ciphertext at rest: only a workload whose"
echo "hostdata matches the SKR release policy can open it."
