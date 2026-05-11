#!/usr/bin/env bash
# Deploy (or refresh) one regional gateway MIG + L4 TCP-passthrough LB.
#
# What this script provisions, idempotently, in $REGION:
#
#   - quill-enclave-tpl-${REGION}-NNN     instance template (n2d SEV-SNP,
#                                          confidential-space-debug image,
#                                          metadata wired to the Anthropic
#                                          variant of the workload)
#   - quill-enclave-tcp-443-${REGION}      regional TCP health check on :443
#   - quill-enclave-mig-${REGION}          regional MIG, autohealing,
#                                          target size 2 (HA across zones)
#   - quill-lb-ip-${REGION}                static external IP for the LB
#   - quill-enclave-bes-${REGION}          regional backend service
#                                          (TCP, EXTERNAL, attaches the MIG)
#   - quill-enclave-fr-${REGION}           forwarding rule on :443 binding
#                                          the static IP to the backend
#
# The trust property: the LB is pure TCP passthrough — it forwards the raw
# byte stream to whichever backend handles the connection. TLS terminates
# *inside* the attested workload (autocert on :443), with the ACME cache
# shared across replicas via gs://quill-acme-cache so any replica can
# answer Let's Encrypt's TLS-ALPN-01 challenge for the same hostname.
#
# Per-region ACME account: each region's template sets
# QUILL_ACME_EMAIL=acme-${REGION}@trustedrouter.com. Let's Encrypt's
# "5 failed validations per account per hostname per hour" rate limit
# is scoped per ACME-account; using a unique email per region means
# us-east4's autocert failures (e.g. AMD stockout → switch to Intel
# TDX → new IP → failed validations) don't poison the rate-limit
# budget for europe-west4 or us-central1. Recovery from a stuck
# region is also faster — bump the region's email to a fresh
# `acme-${REGION}-002@…` and the next deploy gets a clean account.
#
# DNS for api{,-${REGION}}.quillrouter.com is set out of band (Cloudflare,
# DNS-only / grey-cloud) to point at the static IP this script reserves.
# The deploy script does NOT modify DNS.
#
# Usage:
#   IMAGE_REF=us-central1-docker.pkg.dev/.../enclave-anthropic:gcp-release-XXX \
#   API_HOST=api.quillrouter.com \
#     ./tools/deploy-gcp-mig.sh us-central1
#
#   IMAGE_REF=... API_HOST=api-europe-west4.quillrouter.com \
#     ./tools/deploy-gcp-mig.sh europe-west4

set -euo pipefail

REGION="${1:-}"
if [ -z "$REGION" ]; then
  echo "usage: $0 <region>" >&2
  exit 1
fi
PROJECT_ID="${PROJECT_ID:-quill-cloud-proxy}"
NETWORK="${NETWORK:-default}"
SUBNET="${SUBNET:-default}"
# REGION_SHORT lets you keep names stable when GCP region names shift (and
# avoids the ugly `uscentral1` if you'd rather have `us`). Defaults to the
# dashes-stripped region — override per-region to match existing live
# resources, e.g. REGION_SHORT=us for us-central1, REGION_SHORT=eu for
# europe-west4.
REGION_SHORT="${REGION_SHORT:-${REGION//-/}}"
TEMPLATE_PREFIX="${TEMPLATE_PREFIX:-quill-enclave-tpl-${REGION_SHORT}}"
MIG_NAME="${MIG_NAME:-quill-enclave-mig-${REGION_SHORT}}"
HC_NAME="quill-enclave-tcp-443-${REGION_SHORT}"
BES_NAME="quill-enclave-bes-${REGION_SHORT}"
FR_NAME="quill-enclave-fr-${REGION_SHORT}"
LB_IP_NAME="quill-lb-ip-${REGION_SHORT}"
TARGET_SIZE="${TARGET_SIZE:-2}"
MAX_SURGE="${MAX_SURGE:-3}"
MAX_UNAVAILABLE="${MAX_UNAVAILABLE:-0}"

IMAGE_REF="${IMAGE_REF:?set IMAGE_REF=us-central1-docker.pkg.dev/.../enclave-anthropic:gcp-release-XXX}"
API_HOST="${API_HOST:?set API_HOST=api.quillrouter.com (or api-${REGION}.quillrouter.com)}"

# Per-build env vars wired into VM metadata.
# QUILL_ANTHROPIC_SECRET names the Secret Manager secret that holds the
# api.anthropic.com api key — the value is fetched inside the workload,
# never injected as plaintext metadata.
QUILL_ANTHROPIC_SECRET="${QUILL_ANTHROPIC_SECRET:-trustedrouter-anthropic-api-key}"
# Additional providers compiled into the multi build. Each is independently
# optional — leaving the Secret Manager name blank skips fetching it; the
# corresponding case in the multi dispatcher will fail with "missing api
# key" if a request actually reaches that backend without one configured.
# Default to the canonical Secret Manager names created by the
# trusted-router setup. Override with an empty value only for a deliberately
# disabled provider; the catalog publishes prepaid routes for these.
QUILL_OPENAI_SECRET="${QUILL_OPENAI_SECRET:-trustedrouter-openai-api-key}"
QUILL_GEMINI_SECRET="${QUILL_GEMINI_SECRET:-trustedrouter-gemini-api-key}"
QUILL_GEMINI_VERTEX_REGION="${QUILL_GEMINI_VERTEX_REGION:-global}"
QUILL_CEREBRAS_SECRET="${QUILL_CEREBRAS_SECRET:-trustedrouter-cerebras-api-key}"
QUILL_DEEPSEEK_SECRET="${QUILL_DEEPSEEK_SECRET:-trustedrouter-deepseek-api-key}"
QUILL_MISTRAL_SECRET="${QUILL_MISTRAL_SECRET:-trustedrouter-mistral-api-key}"
QUILL_KIMI_SECRET="${QUILL_KIMI_SECRET:-trustedrouter-kimi-api-key}"
QUILL_ZAI_SECRET="${QUILL_ZAI_SECRET:-trustedrouter-zai-api-key}"
QUILL_TOGETHER_SECRET="${QUILL_TOGETHER_SECRET:-trustedrouter-together-api-key}"
QUILL_GROK_SECRET="${QUILL_GROK_SECRET:-trustedrouter-grok-api-key}"
QUILL_NOVITA_SECRET="${QUILL_NOVITA_SECRET:-trustedrouter-novita-api-key}"
QUILL_PHALA_SECRET="${QUILL_PHALA_SECRET:-trustedrouter-phala-api-key}"
QUILL_SILICONFLOW_SECRET="${QUILL_SILICONFLOW_SECRET:-trustedrouter-siliconflow-api-key}"
QUILL_TINFOIL_SECRET="${QUILL_TINFOIL_SECRET:-trustedrouter-tinfoil-api-key}"
QUILL_VENICE_SECRET="${QUILL_VENICE_SECRET:-trustedrouter-venice-api-key}"
QUILL_PARASAIL_SECRET="${QUILL_PARASAIL_SECRET:-trustedrouter-parasail-api-key}"
QUILL_LIGHTNING_SECRET="${QUILL_LIGHTNING_SECRET:-trustedrouter-lightning-api-key}"
QUILL_GMI_SECRET="${QUILL_GMI_SECRET:-trustedrouter-gmi-api-key}"
QUILL_DEEPINFRA_SECRET="${QUILL_DEEPINFRA_SECRET:-trustedrouter-deepinfra-api-key}"
QUILL_DEVICE_KEYS_SECRET="${QUILL_DEVICE_KEYS_SECRET:-quill-device-keys}"
QUILL_TRUSTEDROUTER_INTERNAL_SECRET="${QUILL_TRUSTEDROUTER_INTERNAL_SECRET:-trustedrouter-internal-gateway-token}"
QUILL_ACME_CACHE_GCS_BUCKET="${QUILL_ACME_CACHE_GCS_BUCKET:-quill-acme-cache}"
TR_CONTROL_PLANE_BASE_URL="${TR_CONTROL_PLANE_BASE_URL:-https://trustedrouter.com}"
WORKLOAD_SA="${WORKLOAD_SA:-quill-workload@${PROJECT_ID}.iam.gserviceaccount.com}"
MACHINE_TYPE="${MACHINE_TYPE:-n2d-standard-2}"
# Confidential VM attestation flavor. Defaults to AMD SEV-SNP (n2d-* and
# c3d-* families). Override to TDX for Intel-CPU families (c3-* without
# the trailing d). Both flavors are supported by the same
# confidential-space-debug image and produce equivalent attestation
# tokens (the workload doesn't care which CPU vendor attested it,
# only that the attestation is valid). Useful when one CPU family is
# stocked-out across a region — switching escapes zone-resource
# exhaustion without leaving the region.
CONF_COMPUTE_TYPE="${CONF_COMPUTE_TYPE:-SEV_SNP}"
CSP_IMAGE_FAMILY="${CSP_IMAGE_FAMILY:-confidential-space-debug}"
CSP_IMAGE_PROJECT="${CSP_IMAGE_PROJECT:-confidential-space-images}"

log() { echo "[$(date +%H:%M:%S)] $*" >&2; }
gc() { gcloud --project "$PROJECT_ID" "$@"; }

# Pick the next template suffix by listing existing templates with our prefix.
next_template_name() {
  local existing
  existing=$(gc compute instance-templates list --filter="name~^${TEMPLATE_PREFIX}-[0-9]+\$" --format="value(name)" 2>/dev/null | sort | tail -1 || true)
  if [ -z "$existing" ]; then
    printf '%s-001' "$TEMPLATE_PREFIX"
  else
    local suffix=${existing##*-}
    # strip leading zeros and increment, then pad
    local n=$((10#$suffix + 1))
    printf '%s-%03d' "$TEMPLATE_PREFIX" "$n"
  fi
}

# 1. Reserve the static IP if it doesn't exist.
log "ensuring static IP $LB_IP_NAME"
if ! gc compute addresses describe "$LB_IP_NAME" --region="$REGION" >/dev/null 2>&1; then
  gc compute addresses create "$LB_IP_NAME" \
    --region="$REGION" \
    --network-tier=PREMIUM \
    --description="External IP for quill-enclave L4 TCP passthrough LB ($REGION)"
fi
LB_IP=$(gc compute addresses describe "$LB_IP_NAME" --region="$REGION" --format='value(address)')
log "  $LB_IP"

# 2. Health check (TCP:443 — see comment above).
if ! gc compute health-checks describe "$HC_NAME" --region="$REGION" >/dev/null 2>&1; then
  log "creating health check $HC_NAME"
  gc compute health-checks create tcp "$HC_NAME" \
    --region="$REGION" \
    --port=443 \
    --check-interval=10s --timeout=5s \
    --unhealthy-threshold=3 --healthy-threshold=2 \
    --description="TCP probe of in-enclave TLS listener; bare TCP because cert SAN is the public hostname not the LB IP."
fi

# 3. Instance template (always create new; rolling-replace handles the swap).
TEMPLATE=$(next_template_name)
log "creating instance template $TEMPLATE"
gc compute instance-templates create "$TEMPLATE" \
  --machine-type="$MACHINE_TYPE" \
  --image-family="$CSP_IMAGE_FAMILY" \
  --image-project="$CSP_IMAGE_PROJECT" \
  --boot-disk-size=11GB --boot-disk-type=pd-balanced \
  --network="$NETWORK" --subnet="$SUBNET" --region="$REGION" \
  --service-account="$WORKLOAD_SA" \
  --scopes=cloud-platform \
  --tags=quill-enclave \
  --confidential-compute-type="$CONF_COMPUTE_TYPE" \
  --maintenance-policy=TERMINATE \
  --shielded-secure-boot --shielded-vtpm --shielded-integrity-monitoring \
  --metadata="^|^tee-container-log-redirect=true|tee-env-QUILL_API_HOST=${API_HOST}|tee-env-QUILL_DEVICE_KEYS_SECRET=${QUILL_DEVICE_KEYS_SECRET}|tee-env-QUILL_GCP_PROJECT_ID=${PROJECT_ID}|tee-env-QUILL_GCP_REGION=${REGION}|tee-env-QUILL_GEMINI_VERTEX_REGION=${QUILL_GEMINI_VERTEX_REGION}|tee-env-QUILL_ANTHROPIC_SECRET=${QUILL_ANTHROPIC_SECRET}|tee-env-QUILL_OPENAI_SECRET=${QUILL_OPENAI_SECRET}|tee-env-QUILL_GEMINI_SECRET=${QUILL_GEMINI_SECRET}|tee-env-QUILL_CEREBRAS_SECRET=${QUILL_CEREBRAS_SECRET}|tee-env-QUILL_DEEPSEEK_SECRET=${QUILL_DEEPSEEK_SECRET}|tee-env-QUILL_MISTRAL_SECRET=${QUILL_MISTRAL_SECRET}|tee-env-QUILL_KIMI_SECRET=${QUILL_KIMI_SECRET}|tee-env-QUILL_ZAI_SECRET=${QUILL_ZAI_SECRET}|tee-env-QUILL_TOGETHER_SECRET=${QUILL_TOGETHER_SECRET}|tee-env-QUILL_GROK_SECRET=${QUILL_GROK_SECRET}|tee-env-QUILL_NOVITA_SECRET=${QUILL_NOVITA_SECRET}|tee-env-QUILL_PHALA_SECRET=${QUILL_PHALA_SECRET}|tee-env-QUILL_SILICONFLOW_SECRET=${QUILL_SILICONFLOW_SECRET}|tee-env-QUILL_TINFOIL_SECRET=${QUILL_TINFOIL_SECRET}|tee-env-QUILL_VENICE_SECRET=${QUILL_VENICE_SECRET}|tee-env-QUILL_PARASAIL_SECRET=${QUILL_PARASAIL_SECRET}|tee-env-QUILL_LIGHTNING_SECRET=${QUILL_LIGHTNING_SECRET}|tee-env-QUILL_GMI_SECRET=${QUILL_GMI_SECRET}|tee-env-QUILL_DEEPINFRA_SECRET=${QUILL_DEEPINFRA_SECRET}|tee-env-QUILL_ACME_CACHE_GCS_BUCKET=${QUILL_ACME_CACHE_GCS_BUCKET}|tee-env-QUILL_ACME_EMAIL=acme-${REGION}@trustedrouter.com|tee-env-QUILL_TRUSTEDROUTER_INTERNAL_SECRET=${QUILL_TRUSTEDROUTER_INTERNAL_SECRET}|tee-env-TR_CONTROL_PLANE_BASE_URL=${TR_CONTROL_PLANE_BASE_URL}|tee-image-reference=${IMAGE_REF}|tee-restart-policy=Always" \
  >/dev/null

# 4. Create or update the MIG.
HC_URI="projects/${PROJECT_ID}/regions/${REGION}/healthChecks/${HC_NAME}"
if gc compute instance-groups managed describe "$MIG_NAME" --region="$REGION" >/dev/null 2>&1; then
  log "updating MIG $MIG_NAME -> template $TEMPLATE"
  gc compute instance-groups managed set-instance-template "$MIG_NAME" \
    --region="$REGION" --template="$TEMPLATE" >/dev/null
  # Prefer a surge rollout so the regional gateway keeps serving while the
  # new attested image boots and passes health checks. Regional MIGs span
  # three zones, so the fixed surge default is 3.
  gc compute instance-groups managed rolling-action replace "$MIG_NAME" \
    --region="$REGION" \
    --max-unavailable="$MAX_UNAVAILABLE" \
    --max-surge="$MAX_SURGE" >/dev/null
else
  log "creating MIG $MIG_NAME (size=$TARGET_SIZE)"
  gc compute instance-groups managed create "$MIG_NAME" \
    --base-instance-name="$MIG_NAME" \
    --template="$TEMPLATE" \
    --size="$TARGET_SIZE" \
    --region="$REGION" \
    --health-check="$HC_URI" \
    --initial-delay=300 \
    --description="Autohealing MIG for quill enclave gateway in $REGION." >/dev/null
fi

# 5. Backend service (regional EXTERNAL TCP passthrough) attaching the MIG.
if ! gc compute backend-services describe "$BES_NAME" --region="$REGION" >/dev/null 2>&1; then
  log "creating backend service $BES_NAME"
  gc compute backend-services create "$BES_NAME" \
    --region="$REGION" \
    --load-balancing-scheme=EXTERNAL \
    --protocol=TCP \
    --health-checks="$HC_NAME" \
    --health-checks-region="$REGION" \
    --connection-draining-timeout=30 \
    --description="Regional external TCP passthrough backend for quill enclave gateway in $REGION."
  gc compute backend-services add-backend "$BES_NAME" \
    --region="$REGION" \
    --instance-group="$MIG_NAME" \
    --instance-group-region="$REGION" >/dev/null
fi

# 6. Forwarding rule on :443 binding the static IP to the backend service.
if ! gc compute forwarding-rules describe "$FR_NAME" --region="$REGION" >/dev/null 2>&1; then
  log "creating forwarding rule $FR_NAME"
  gc compute forwarding-rules create "$FR_NAME" \
    --region="$REGION" \
    --load-balancing-scheme=EXTERNAL \
    --address="$LB_IP_NAME" \
    --ip-protocol=TCP \
    --ports=443 \
    --backend-service="$BES_NAME" \
    --backend-service-region="$REGION" \
    --description="External TCP:443 passthrough to MIG; TLS terminates in-enclave."
fi

cat <<EOF

quill-enclave gateway in $REGION is provisioned.

  static IP:        $LB_IP   (point Cloudflare A record at this, DNS-only)
  hostname (SNI):   $API_HOST
  template:         $TEMPLATE
  image:            $IMAGE_REF
  MIG size:         $TARGET_SIZE

EOF
