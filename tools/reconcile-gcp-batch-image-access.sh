#!/usr/bin/env bash
set -euo pipefail

# Grant the current attested enclave digest access to Batch ciphertext and its
# envelope key. During a rollout, grant the new digest before touching a region
# and prune old digests only after every region has passed its smoke checks.

PROJECT_ID="${PROJECT_ID:-quill-cloud-proxy}"
PROJECT_NUMBER="${PROJECT_NUMBER:-44325983244}"
BATCH_BUCKET="${BATCH_BUCKET:-quill-cloud-proxy-batch-artifacts}"
KMS_LOCATION="${KMS_LOCATION:-us-central1}"
KMS_KEYRING="${KMS_KEYRING:-trusted-router}"
KMS_KEY="${KMS_KEY:-batch-envelope}"
WIF_POOL="${WIF_POOL:-trustedrouter-batch}"

MODE="${1:-}"
IMAGE_DIGEST="${2:-}"
if [[ "${MODE}" != "grant" && "${MODE}" != "prune" ]]; then
  echo "usage: $0 grant|prune sha256:<64 lowercase hex characters>" >&2
  exit 2
fi
if [[ ! "${IMAGE_DIGEST}" =~ ^sha256:[0-9a-f]{64}$ ]]; then
  echo "invalid image digest: ${IMAGE_DIGEST}" >&2
  exit 2
fi

MEMBER_PREFIX="principalSet://iam.googleapis.com/projects/${PROJECT_NUMBER}/locations/global/workloadIdentityPools/${WIF_POOL}/attribute.image_digest/"
CURRENT_MEMBER="${MEMBER_PREFIX}${IMAGE_DIGEST}"
KMS_RESOURCE="projects/${PROJECT_ID}/locations/${KMS_LOCATION}/keyRings/${KMS_KEYRING}/cryptoKeys/${KMS_KEY}"

grant_current() {
  gcloud storage buckets add-iam-policy-binding "gs://${BATCH_BUCKET}" \
    --project="${PROJECT_ID}" \
    --member="${CURRENT_MEMBER}" \
    --role=roles/storage.objectAdmin \
    --condition=None \
    --quiet >/dev/null
  gcloud kms keys add-iam-policy-binding "${KMS_RESOURCE}" \
    --project="${PROJECT_ID}" \
    --member="${CURRENT_MEMBER}" \
    --role=roles/cloudkms.cryptoKeyEncrypterDecrypter \
    --condition=None \
    --quiet >/dev/null
}

policy_members() {
  local resource="$1"
  if [[ "${resource}" == gs://* ]]; then
    gcloud storage buckets get-iam-policy "${resource}" --project="${PROJECT_ID}" --format=json
  else
    gcloud kms keys get-iam-policy "${resource}" --project="${PROJECT_ID}" --format=json
  fi | python3 -c '
import json
import sys

prefix, role = sys.argv[1:]
policy = json.load(sys.stdin)
for binding in policy.get("bindings", []):
    if binding.get("role") != role:
        continue
    for member in binding.get("members", []):
        if member.startswith(prefix):
            print(member)
' "${MEMBER_PREFIX}" "$2"
}

remove_member() {
  local resource="$1"
  local role="$2"
  local member="$3"
  if [[ "${resource}" == gs://* ]]; then
    gcloud storage buckets remove-iam-policy-binding "${resource}" \
      --project="${PROJECT_ID}" --member="${member}" --role="${role}" --condition=None --quiet >/dev/null
  else
    gcloud kms keys remove-iam-policy-binding "${resource}" \
      --project="${PROJECT_ID}" --member="${member}" --role="${role}" --condition=None --quiet >/dev/null
  fi
}

grant_current
if [[ "${MODE}" == "grant" ]]; then
  echo "Granted attested Batch access to ${IMAGE_DIGEST}."
  exit 0
fi

bucket_members="$(policy_members "gs://${BATCH_BUCKET}" roles/storage.objectAdmin)"
while IFS= read -r member; do
	[[ -z "${member}" || "${member}" == "${CURRENT_MEMBER}" ]] && continue
	remove_member "gs://${BATCH_BUCKET}" roles/storage.objectAdmin "${member}"
done <<<"${bucket_members}"

kms_members="$(policy_members "${KMS_RESOURCE}" roles/cloudkms.cryptoKeyEncrypterDecrypter)"
while IFS= read -r member; do
	[[ -z "${member}" || "${member}" == "${CURRENT_MEMBER}" ]] && continue
	remove_member "${KMS_RESOURCE}" roles/cloudkms.cryptoKeyEncrypterDecrypter "${member}"
done <<<"${kms_members}"

echo "Pruned stale attested Batch digests; ${IMAGE_DIGEST} remains authorized."
