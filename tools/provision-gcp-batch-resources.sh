#!/usr/bin/env bash
set -euo pipefail

# One-time, idempotent provisioning for encrypted Batch artifacts. The workload
# obtains direct federated credentials from a production Confidential Space
# attestation token. IAM then restricts access to explicitly approved enclave
# image digests; the VM service account itself receives no data access.

PROJECT_ID="${PROJECT_ID:-quill-cloud-proxy}"
PROJECT_NUMBER="${PROJECT_NUMBER:-44325983244}"
WORKLOAD_SA="${WORKLOAD_SA:-quill-workload@${PROJECT_ID}.iam.gserviceaccount.com}"
BATCH_RELEASE_SA="${BATCH_RELEASE_SA:-tr-batch-release@${PROJECT_ID}.iam.gserviceaccount.com}"
GITHUB_WIF_POOL="${GITHUB_WIF_POOL:-github-actions}"
GITHUB_REPOSITORY="${GITHUB_REPOSITORY:-Lore-Hex/quill-cloud-proxy}"
BATCH_BUCKET="${BATCH_BUCKET:-quill-cloud-proxy-batch-artifacts}"
BUCKET_LOCATION="${BUCKET_LOCATION:-US}"
KMS_LOCATION="${KMS_LOCATION:-us-central1}"
KMS_KEYRING="${KMS_KEYRING:-trusted-router}"
KMS_KEY="${KMS_KEY:-batch-envelope}"
WIF_POOL="${WIF_POOL:-trustedrouter-batch}"
WIF_PROVIDER="${WIF_PROVIDER:-confidential-space}"
DIGEST_MANAGER_ROLE="${DIGEST_MANAGER_ROLE:-trustedRouterBatchDigestManager}"
IMAGE_DIGEST="${1:-}"

if [[ ! "${IMAGE_DIGEST}" =~ ^sha256:[0-9a-f]{64}$ ]]; then
  echo "usage: $0 sha256:<64 lowercase hex characters>" >&2
  exit 2
fi

retry_eventual_iam() {
  local attempt
  for ((attempt = 1; attempt <= 12; attempt++)); do
    if "$@" >/dev/null 2>&1; then
      return 0
    fi
    sleep 5
  done
  "$@"
}

gcloud services enable \
  cloudkms.googleapis.com \
  confidentialcomputing.googleapis.com \
  iam.googleapis.com \
  iamcredentials.googleapis.com \
  sts.googleapis.com \
  storage.googleapis.com \
  --project="${PROJECT_ID}" --quiet

if ! gcloud kms keys describe "${KMS_KEY}" \
  --project="${PROJECT_ID}" --location="${KMS_LOCATION}" --keyring="${KMS_KEYRING}" >/dev/null 2>&1; then
  if next_rotation_time="$(date -u -d '+90 days' '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null)"; then
    :
  else
    next_rotation_time="$(date -u -v+90d '+%Y-%m-%dT%H:%M:%SZ')"
  fi
  gcloud kms keys create "${KMS_KEY}" \
    --project="${PROJECT_ID}" \
    --location="${KMS_LOCATION}" \
    --keyring="${KMS_KEYRING}" \
    --purpose=encryption \
    --rotation-period=90d \
    --next-rotation-time="${next_rotation_time}" \
    --quiet
fi

if ! gcloud storage buckets describe "gs://${BATCH_BUCKET}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
  gcloud storage buckets create "gs://${BATCH_BUCKET}" \
    --project="${PROJECT_ID}" \
    --location="${BUCKET_LOCATION}" \
    --default-storage-class=STANDARD \
    --uniform-bucket-level-access \
    --public-access-prevention \
    --soft-delete-duration=0 \
    --quiet
fi

LIFECYCLE_FILE="$(mktemp)"
trap 'rm -f "${LIFECYCLE_FILE}"' EXIT
printf '%s\n' '{"rule":[{"action":{"type":"Delete"},"condition":{"age":30}}]}' >"${LIFECYCLE_FILE}"
gcloud storage buckets update "gs://${BATCH_BUCKET}" \
  --project="${PROJECT_ID}" \
  --uniform-bucket-level-access \
  --public-access-prevention \
  --no-versioning \
  --clear-soft-delete \
  --lifecycle-file="${LIFECYCLE_FILE}" \
  --quiet

if ! gcloud iam workload-identity-pools describe "${WIF_POOL}" \
  --project="${PROJECT_ID}" --location=global >/dev/null 2>&1; then
  gcloud iam workload-identity-pools create "${WIF_POOL}" \
    --project="${PROJECT_ID}" \
    --location=global \
    --display-name="TrustedRouter attested Batch" \
    --description="Direct GCS and KMS access for approved production enclave digests" \
    --quiet
fi

ATTRIBUTE_MAPPING='google.subject="gcpcs::"+assertion.submods.container.image_digest+"::"+assertion.submods.gce.project_number+"::"+assertion.submods.gce.instance_id,attribute.image_digest=assertion.submods.container.image_digest'
ATTRIBUTE_CONDITION="assertion.swname == 'CONFIDENTIAL_SPACE' && assertion.dbgstat == 'disabled-since-boot' && 'STABLE' in assertion.submods.confidential_space.support_attributes && assertion.submods.gce.project_number == '${PROJECT_NUMBER}' && '${WORKLOAD_SA}' in assertion.google_service_accounts"
if gcloud iam workload-identity-pools providers describe "${WIF_PROVIDER}" \
  --project="${PROJECT_ID}" --location=global --workload-identity-pool="${WIF_POOL}" >/dev/null 2>&1; then
  gcloud iam workload-identity-pools providers update-oidc "${WIF_PROVIDER}" \
    --project="${PROJECT_ID}" \
    --location=global \
    --workload-identity-pool="${WIF_POOL}" \
    --issuer-uri="https://confidentialcomputing.googleapis.com/" \
    --allowed-audiences="https://sts.googleapis.com" \
    --attribute-mapping="${ATTRIBUTE_MAPPING}" \
    --attribute-condition="${ATTRIBUTE_CONDITION}" \
    --quiet
else
  gcloud iam workload-identity-pools providers create-oidc "${WIF_PROVIDER}" \
    --project="${PROJECT_ID}" \
    --location=global \
    --workload-identity-pool="${WIF_POOL}" \
    --display-name="Confidential Space" \
    --issuer-uri="https://confidentialcomputing.googleapis.com/" \
    --allowed-audiences="https://sts.googleapis.com" \
    --attribute-mapping="${ATTRIBUTE_MAPPING}" \
    --attribute-condition="${ATTRIBUTE_CONDITION}" \
    --quiet
fi

ROLE_NAME="projects/${PROJECT_ID}/roles/${DIGEST_MANAGER_ROLE}"
ROLE_PERMISSIONS="cloudkms.cryptoKeys.get,cloudkms.cryptoKeys.getIamPolicy,cloudkms.cryptoKeys.setIamPolicy,storage.buckets.get,storage.buckets.getIamPolicy,storage.buckets.setIamPolicy"
if gcloud iam roles describe "${DIGEST_MANAGER_ROLE}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
  gcloud iam roles update "${DIGEST_MANAGER_ROLE}" \
    --project="${PROJECT_ID}" \
    --title="TrustedRouter Batch digest manager" \
    --description="Reconcile exact Confidential Space image-digest access to Batch GCS and KMS resources" \
    --permissions="${ROLE_PERMISSIONS}" \
    --stage=GA \
    --quiet
else
  gcloud iam roles create "${DIGEST_MANAGER_ROLE}" \
    --project="${PROJECT_ID}" \
    --title="TrustedRouter Batch digest manager" \
    --description="Reconcile exact Confidential Space image-digest access to Batch GCS and KMS resources" \
    --permissions="${ROLE_PERMISSIONS}" \
    --stage=GA \
    --quiet
fi

if ! gcloud iam service-accounts describe "${BATCH_RELEASE_SA}" \
  --project="${PROJECT_ID}" >/dev/null 2>&1; then
  gcloud iam service-accounts create "${BATCH_RELEASE_SA%%@*}" \
    --project="${PROJECT_ID}" \
    --display-name="TrustedRouter Batch release IAM" \
    --description="Isolated release identity for attested Batch digest grants" \
    --quiet
fi

retry_eventual_iam gcloud iam service-accounts add-iam-policy-binding "${BATCH_RELEASE_SA}" \
  --project="${PROJECT_ID}" \
  --member="principal://iam.googleapis.com/projects/${PROJECT_NUMBER}/locations/global/workloadIdentityPools/${GITHUB_WIF_POOL}/subject/repo:${GITHUB_REPOSITORY}:environment:batch-release" \
  --role=roles/iam.workloadIdentityUser \
  --condition=None --quiet

retry_eventual_iam gcloud storage buckets add-iam-policy-binding "gs://${BATCH_BUCKET}" \
  --project="${PROJECT_ID}" \
  --member="serviceAccount:${BATCH_RELEASE_SA}" \
  --role="${ROLE_NAME}" \
  --condition=None --quiet
retry_eventual_iam gcloud kms keys add-iam-policy-binding "${KMS_KEY}" \
  --project="${PROJECT_ID}" \
  --location="${KMS_LOCATION}" \
  --keyring="${KMS_KEYRING}" \
  --member="serviceAccount:${BATCH_RELEASE_SA}" \
  --role="${ROLE_NAME}" \
  --condition=None --quiet

"$(dirname "$0")/reconcile-gcp-batch-image-access.sh" grant "${IMAGE_DIGEST}"

echo "Provisioned attested Batch resources for ${IMAGE_DIGEST}."
