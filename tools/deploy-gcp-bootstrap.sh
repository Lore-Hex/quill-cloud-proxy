#!/usr/bin/env bash
# One-time per-project bootstrap for the GCP quill-enclave deploy.
# Idempotent: re-running produces no changes when state matches.
#
# Creates / verifies, in this order:
#
#   1. The KMS key that encrypts the shared autocert cache.
#   2. The GCS bucket that holds the shared autocert cache (CMEK with the
#      key from step 1).
#   3. The Bigtable secondary cluster (europe-west4) and switches the
#      default app profile to multi-cluster routing so writes go to
#      the nearest cluster and replicate async.
#   4. IAM bindings the workload service account needs:
#        - storage.objectAdmin on gs://quill-acme-cache
#        - secretmanager.secretAccessor on the Anthropic key
#        - secretmanager.secretAccessor on the trustedrouter internal
#          gateway token
#
# Things this script does NOT create (manual prerequisites):
#
#   - The Bigtable instance + primary us-central1 cluster
#   - Secret Manager secrets (trustedrouter-anthropic-api-key,
#     quill-device-keys, trustedrouter-internal-gateway-token)
#   - The Cloud Run trusted-router service (deployed by quill-router)
#   - The global LB in front of trusted-router
#   - Cloudflare DNS records (set out of band)
#
# After this script runs, deploy each region with:
#
#   IMAGE_REF=us-central1-docker.pkg.dev/.../enclave-anthropic:gcp-release-XXX \
#   API_HOST=api.quillrouter.com \
#     ./tools/deploy-gcp-mig.sh us-central1
#
#   IMAGE_REF=us-central1-docker.pkg.dev/.../enclave-anthropic:gcp-release-XXX \
#   API_HOST=api-europe-west4.quillrouter.com \
#     ./tools/deploy-gcp-mig.sh europe-west4

set -euo pipefail

PROJECT_ID="${PROJECT_ID:-quill-cloud-proxy}"
KMS_LOCATION="${KMS_LOCATION:-us-central1}"
KMS_KEYRING="${KMS_KEYRING:-trusted-router}"
ACME_KMS_KEY="${ACME_KMS_KEY:-acme-cache-envelope}"
ACME_BUCKET="${ACME_BUCKET:-quill-acme-cache}"
BIGTABLE_INSTANCE="${BIGTABLE_INSTANCE:-trusted-router-logs}"
BIGTABLE_EU_CLUSTER="${BIGTABLE_EU_CLUSTER:-trusted-router-logs-eu}"
BIGTABLE_EU_ZONE="${BIGTABLE_EU_ZONE:-europe-west4-a}"
WORKLOAD_SA="${WORKLOAD_SA:-quill-workload@${PROJECT_ID}.iam.gserviceaccount.com}"
ANTHROPIC_SECRET="${ANTHROPIC_SECRET:-trustedrouter-anthropic-api-key}"
OPENAI_SECRET="${OPENAI_SECRET:-trustedrouter-openai-api-key}"
GEMINI_SECRET="${GEMINI_SECRET:-trustedrouter-gemini-api-key}"
CEREBRAS_SECRET="${CEREBRAS_SECRET:-trustedrouter-cerebras-api-key}"
DEEPSEEK_SECRET="${DEEPSEEK_SECRET:-trustedrouter-deepseek-api-key}"
MISTRAL_SECRET="${MISTRAL_SECRET:-trustedrouter-mistral-api-key}"
KIMI_SECRET="${KIMI_SECRET:-trustedrouter-kimi-api-key}"
ZAI_SECRET="${ZAI_SECRET:-trustedrouter-zai-api-key}"
TOGETHER_SECRET="${TOGETHER_SECRET:-trustedrouter-together-api-key}"
FIREWORKS_SECRET="${FIREWORKS_SECRET:-trustedrouter-fireworks-api-key}"
COHERE_SECRET="${COHERE_SECRET:-trustedrouter-cohere-api-key}"
VOYAGE_SECRET="${VOYAGE_SECRET:-trustedrouter-voyage-api-key}"
GROK_SECRET="${GROK_SECRET:-trustedrouter-grok-api-key}"
NOVITA_SECRET="${NOVITA_SECRET:-trustedrouter-novita-api-key}"
PHALA_SECRET="${PHALA_SECRET:-trustedrouter-phala-api-key}"
SILICONFLOW_SECRET="${SILICONFLOW_SECRET:-trustedrouter-siliconflow-api-key}"
TINFOIL_SECRET="${TINFOIL_SECRET:-trustedrouter-tinfoil-api-key}"
VENICE_SECRET="${VENICE_SECRET:-trustedrouter-venice-api-key}"
PARASAIL_SECRET="${PARASAIL_SECRET:-trustedrouter-parasail-api-key}"
LIGHTNING_SECRET="${LIGHTNING_SECRET:-trustedrouter-lightning-api-key}"
GMI_SECRET="${GMI_SECRET:-trustedrouter-gmi-api-key}"
DEEPINFRA_SECRET="${DEEPINFRA_SECRET:-trustedrouter-deepinfra-api-key}"
NEBIUS_SECRET="${NEBIUS_SECRET:-trustedrouter-nebius-api-key}"
MINIMAX_SECRET="${MINIMAX_SECRET:-trustedrouter-minimax-api-key}"
XIAOMI_SECRET="${XIAOMI_SECRET:-trustedrouter-xiaomi-api-key}"
INTERNAL_GATEWAY_SECRET="${INTERNAL_GATEWAY_SECRET:-trustedrouter-internal-gateway-token}"
DEVICE_KEYS_SECRET="${DEVICE_KEYS_SECRET:-quill-device-keys}"

log() { echo "[$(date +%H:%M:%S)] $*" >&2; }
gc() { gcloud --project "$PROJECT_ID" "$@"; }

PROJECT_NUMBER=$(gc projects describe "$PROJECT_ID" --format='value(projectNumber)')
GCS_AGENT="service-${PROJECT_NUMBER}@gs-project-accounts.iam.gserviceaccount.com"

# 1. KMS key for ACME cache encryption.
if ! gc kms keys describe "$ACME_KMS_KEY" --keyring="$KMS_KEYRING" --location="$KMS_LOCATION" >/dev/null 2>&1; then
  log "creating KMS key $ACME_KMS_KEY"
  gc kms keys create "$ACME_KMS_KEY" \
    --keyring="$KMS_KEYRING" \
    --location="$KMS_LOCATION" \
    --purpose=encryption
fi

# Cloud Storage service agent needs Encrypter/Decrypter on the KMS key
# before we can put a CMEK-encrypted bucket on top of it.
log "ensuring GCS service agent has access to KMS key"
gc kms keys add-iam-policy-binding "$ACME_KMS_KEY" \
  --keyring="$KMS_KEYRING" \
  --location="$KMS_LOCATION" \
  --member="serviceAccount:${GCS_AGENT}" \
  --role=roles/cloudkms.cryptoKeyEncrypterDecrypter \
  --quiet >/dev/null

# 2. GCS bucket for shared autocert cache.
if ! gc storage buckets describe "gs://${ACME_BUCKET}" >/dev/null 2>&1; then
  log "creating bucket gs://${ACME_BUCKET}"
  gc storage buckets create "gs://${ACME_BUCKET}" \
    --location="$KMS_LOCATION" \
    --default-storage-class=STANDARD \
    --uniform-bucket-level-access \
    --default-encryption-key="projects/${PROJECT_ID}/locations/${KMS_LOCATION}/keyRings/${KMS_KEYRING}/cryptoKeys/${ACME_KMS_KEY}"
fi
log "ensuring workload SA has objectAdmin on gs://${ACME_BUCKET}"
gc storage buckets add-iam-policy-binding "gs://${ACME_BUCKET}" \
  --member="serviceAccount:${WORKLOAD_SA}" \
  --role=roles/storage.objectAdmin \
  --quiet >/dev/null

# 3. Bigtable secondary cluster + multi-cluster routing.
if ! gc bigtable clusters describe "$BIGTABLE_EU_CLUSTER" --instance="$BIGTABLE_INSTANCE" >/dev/null 2>&1; then
  log "creating Bigtable EU cluster $BIGTABLE_EU_CLUSTER (provisioning takes ~5-10 min)"
  gc bigtable clusters create "$BIGTABLE_EU_CLUSTER" \
    --instance="$BIGTABLE_INSTANCE" \
    --zone="$BIGTABLE_EU_ZONE" \
    --num-nodes=1
fi
# Switch the default profile to multi-cluster routing. Loses transactional
# writes (single-cluster only) — fine for the append-only activity logs
# trusted-router stores in this instance.
log "ensuring default app profile uses multi-cluster routing"
CURRENT_ROUTING=$(gc bigtable app-profiles describe default --instance="$BIGTABLE_INSTANCE" --format='value(multiClusterRoutingUseAny)' 2>/dev/null || true)
if [ -z "$CURRENT_ROUTING" ]; then
  gc bigtable app-profiles update default \
    --instance="$BIGTABLE_INSTANCE" \
    --route-any \
    --force >/dev/null
fi

# 4. IAM bindings on the secrets the workload reads at boot.
for secret in \
  "$ANTHROPIC_SECRET" \
  "$OPENAI_SECRET" \
  "$GEMINI_SECRET" \
  "$CEREBRAS_SECRET" \
  "$DEEPSEEK_SECRET" \
  "$MISTRAL_SECRET" \
  "$KIMI_SECRET" \
  "$ZAI_SECRET" \
  "$TOGETHER_SECRET" \
  "$FIREWORKS_SECRET" \
  "$COHERE_SECRET" \
  "$VOYAGE_SECRET" \
  "$GROK_SECRET" \
  "$NOVITA_SECRET" \
  "$PHALA_SECRET" \
  "$SILICONFLOW_SECRET" \
  "$TINFOIL_SECRET" \
  "$VENICE_SECRET" \
  "$PARASAIL_SECRET" \
  "$LIGHTNING_SECRET" \
  "$GMI_SECRET" \
  "$DEEPINFRA_SECRET" \
  "$NEBIUS_SECRET" \
  "$MINIMAX_SECRET" \
  "$XIAOMI_SECRET" \
  "$INTERNAL_GATEWAY_SECRET" \
  "$DEVICE_KEYS_SECRET"; do
  if gc secrets describe "$secret" >/dev/null 2>&1; then
    log "ensuring workload SA can access secret $secret"
    gc secrets add-iam-policy-binding "$secret" \
      --member="serviceAccount:${WORKLOAD_SA}" \
      --role=roles/secretmanager.secretAccessor \
      --quiet >/dev/null
  else
    echo "WARNING: secret $secret does not exist — create it before running deploy-gcp-mig.sh" >&2
  fi
done

cat <<EOF

quill-enclave per-project bootstrap complete.

  KMS key:        projects/${PROJECT_ID}/locations/${KMS_LOCATION}/keyRings/${KMS_KEYRING}/cryptoKeys/${ACME_KMS_KEY}
  ACME bucket:    gs://${ACME_BUCKET}
  Bigtable EU:    ${BIGTABLE_EU_CLUSTER} in ${BIGTABLE_EU_ZONE}
  Workload SA:    ${WORKLOAD_SA}

Next: per-region deploy via tools/deploy-gcp-mig.sh
EOF
