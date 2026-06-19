#!/usr/bin/env bash
# Deploy (or refresh) one regional gateway MIG. NO load balancer.
#
# What this script provisions, idempotently, in $REGION:
#
#   - quill-enclave-tpl-${REGION}-NNN     instance template (confidential-space
#                                          production image, metadata wired to
#                                          the multi-provider workload)
#   - quill-enclave-mig-${REGION}          regional MIG, NO autohealing,
#                                          target size 2 (HA across zones)
#
# There is NO GCP load balancer. A GCP health check cannot usefully validate a
# Confidential Space enclave: an HTTP/L7 probe needs the in-VM TLS cert it can't
# get, and a bare-TCP:443 probe only proves the socket accepts, not that the
# instance attests (and us-central1 CVMs fail every GCP HC type regardless). An
# L4 LB was trialed and torn down 2026-06-19 — do NOT re-add it here. Fleet
# membership is owned by the attesting control-plane reconciler
# (tools/reconcile-enclave-dns.py), which attests every instance and publishes
# only the healthy ones into the api.trustedrouter.com / api.quillrouter.com A
# records. Each instance serves TLS directly on its own public IP:443 — TLS
# terminates *inside* the attested workload (autocert on :443), with the ACME
# cache shared across replicas via gs://quill-acme-cache so any replica can
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
# DNS for api{,-${REGION}}.{trustedrouter,quillrouter}.com is managed by the
# enclave-dns-reconciler (it publishes attested instance IPs). This deploy
# script does NOT modify DNS, and no longer reserves any static IP.
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
# The enclave binds a plaintext liveness listener on QUILL_HEALTH_PORT (image
# default 8081) for manual/internal checks only — nothing health-checks it (there
# is no LB). Fleet health is the reconciler's attestation, not a GCP HC.
HEALTH_PORT="${HEALTH_PORT:-8081}"
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
QUILL_FIREWORKS_SECRET="${QUILL_FIREWORKS_SECRET:-trustedrouter-fireworks-api-key}"
QUILL_GROK_SECRET="${QUILL_GROK_SECRET:-trustedrouter-grok-api-key}"
QUILL_NOVITA_SECRET="${QUILL_NOVITA_SECRET:-trustedrouter-novita-api-key}"
QUILL_PHALA_SECRET="${QUILL_PHALA_SECRET:-trustedrouter-phala-confidential-api-key}"
QUILL_SILICONFLOW_SECRET="${QUILL_SILICONFLOW_SECRET:-trustedrouter-siliconflow-api-key}"
QUILL_TINFOIL_SECRET="${QUILL_TINFOIL_SECRET:-trustedrouter-tinfoil-api-key}"
QUILL_VENICE_SECRET="${QUILL_VENICE_SECRET:-trustedrouter-venice-api-key}"
QUILL_PARASAIL_SECRET="${QUILL_PARASAIL_SECRET:-trustedrouter-parasail-api-key}"
QUILL_LIGHTNING_SECRET="${QUILL_LIGHTNING_SECRET:-trustedrouter-lightning-api-key}"
QUILL_GMI_SECRET="${QUILL_GMI_SECRET:-trustedrouter-gmi-api-key}"
QUILL_DEEPINFRA_SECRET="${QUILL_DEEPINFRA_SECRET:-trustedrouter-deepinfra-api-key}"
QUILL_NEBIUS_SECRET="${QUILL_NEBIUS_SECRET:-trustedrouter-nebius-api-key}"
QUILL_MINIMAX_SECRET="${QUILL_MINIMAX_SECRET:-trustedrouter-minimax-api-key}"
# Cohere — embeddings only (native /v2/embed). The secret
# trustedrouter-cohere-api-key was provisioned in Secret Manager on
# 2026-06-07, so the enclave can fetch it at boot. NOTE: the bootstrap
# HARD-FAILS if a named secret can't be fetched — keep this pointed only at
# a secret that actually exists (set to "" to disable if it's ever removed).
QUILL_COHERE_SECRET="${QUILL_COHERE_SECRET:-trustedrouter-cohere-api-key}"
# Optional tee-env segment: only injected when QUILL_COHERE_SECRET is set, so
# an empty value never produces a malformed/empty metadata entry.
COHERE_TEE_ENV=""
if [ -n "${QUILL_COHERE_SECRET}" ]; then
  COHERE_TEE_ENV="|tee-env-QUILL_COHERE_SECRET=${QUILL_COHERE_SECRET}"
fi
# Voyage AI — embeddings only (OpenAI-shaped /v1/embeddings). Provision
# trustedrouter-voyage-api-key in Secret Manager (scripts/deploy/secrets.sh)
# before pointing here; bootstrap HARD-FAILS on a named-but-missing secret.
QUILL_VOYAGE_SECRET="${QUILL_VOYAGE_SECRET:-trustedrouter-voyage-api-key}"
VOYAGE_TEE_ENV=""
if [ -n "${QUILL_VOYAGE_SECRET}" ]; then
  VOYAGE_TEE_ENV="|tee-env-QUILL_VOYAGE_SECRET=${QUILL_VOYAGE_SECRET}"
fi
# Xiaomi MiMo — OpenAI-compatible chat (api.xiaomimimo.com/v1). Provision
# trustedrouter-xiaomi-api-key + grant the workload SA accessor BEFORE pointing
# here; bootstrap HARD-FAILS on a named-but-missing secret. Set
# QUILL_XIAOMI_SECRET="" to skip until then.
QUILL_XIAOMI_SECRET="${QUILL_XIAOMI_SECRET:-trustedrouter-xiaomi-api-key}"
XIAOMI_TEE_ENV=""
if [ -n "${QUILL_XIAOMI_SECRET}" ]; then
  XIAOMI_TEE_ENV="|tee-env-QUILL_XIAOMI_SECRET=${QUILL_XIAOMI_SECRET}"
fi
QUILL_DEVICE_KEYS_SECRET="${QUILL_DEVICE_KEYS_SECRET:-quill-device-keys}"
QUILL_TRUSTEDROUTER_INTERNAL_SECRET="${QUILL_TRUSTEDROUTER_INTERNAL_SECRET:-trustedrouter-internal-gateway-token}"
QUILL_ACME_CACHE_GCS_BUCKET="${QUILL_ACME_CACHE_GCS_BUCKET:-quill-acme-cache}"
TR_CONTROL_PLANE_BASE_URL="${TR_CONTROL_PLANE_BASE_URL:-https://trustedrouter.com}"
# Time-to-first-byte budget per upstream attempt before the enclave cancels
# and fails over. Default bumped 8s -> 20s on 2026-06-04: ~16 real Novita
# models (baidu/ernie, deepseek-r1-distill, etc.) are served but cold-start
# slower than 8s to first token, and the 8s budget was killing them
# (err=ttfb_exceeded). 20s lets them through; the tradeoff is a dead provider
# now waits up to 20s before failover instead of 8s.
QUILL_FIRST_BYTE_TIMEOUT_SECONDS="${QUILL_FIRST_BYTE_TIMEOUT_SECONDS:-20}"
WORKLOAD_SA="${WORKLOAD_SA:-quill-workload@${PROJECT_ID}.iam.gserviceaccount.com}"
default_machine_type="n2d-standard-2"
default_conf_compute_type="SEV_SNP"
case "$REGION" in
  europe-west4|us-east4)
    # These regions have repeatedly failed or stocked out on AMD SEV-SNP n2d
    # for this workload. Intel TDX on c3 is the profile currently serving
    # us-east4 reliably, and europe-west4 has c3-standard-4 capacity in all
    # zones.
    default_machine_type="c3-standard-4"
    default_conf_compute_type="TDX"
    ;;
esac
MACHINE_TYPE="${MACHINE_TYPE:-$default_machine_type}"
# Confidential VM attestation flavor. Defaults to AMD SEV-SNP (n2d-* and
# c3d-* families). Override to TDX for Intel-CPU families (c3-* without
# the trailing d). Both flavors are supported by the same
# confidential-space image and produce equivalent attestation
# tokens (the workload doesn't care which CPU vendor attested it,
# only that the attestation is valid). Useful when one CPU family is
# stocked-out across a region — switching escapes zone-resource
# exhaustion without leaving the region.
CONF_COMPUTE_TYPE="${CONF_COMPUTE_TYPE:-$default_conf_compute_type}"
CSP_IMAGE_FAMILY="${CSP_IMAGE_FAMILY:-confidential-space}"
CSP_IMAGE_PROJECT="${CSP_IMAGE_PROJECT:-confidential-space-images}"
TEE_CONTAINER_LOG_REDIRECT="${TEE_CONTAINER_LOG_REDIRECT:-false}"

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

# 1. Instance template (always create new; rolling-replace handles the swap).
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
  --metadata="^|^tee-container-log-redirect=${TEE_CONTAINER_LOG_REDIRECT}|tee-env-QUILL_API_HOST=${API_HOST}|tee-env-QUILL_HEALTH_PORT=${HEALTH_PORT}|tee-env-QUILL_DEVICE_KEYS_SECRET=${QUILL_DEVICE_KEYS_SECRET}|tee-env-QUILL_GCP_PROJECT_ID=${PROJECT_ID}|tee-env-QUILL_GCP_REGION=${REGION}|tee-env-QUILL_GEMINI_VERTEX_REGION=${QUILL_GEMINI_VERTEX_REGION}|tee-env-QUILL_ANTHROPIC_SECRET=${QUILL_ANTHROPIC_SECRET}|tee-env-QUILL_OPENAI_SECRET=${QUILL_OPENAI_SECRET}|tee-env-QUILL_GEMINI_SECRET=${QUILL_GEMINI_SECRET}|tee-env-QUILL_CEREBRAS_SECRET=${QUILL_CEREBRAS_SECRET}|tee-env-QUILL_DEEPSEEK_SECRET=${QUILL_DEEPSEEK_SECRET}|tee-env-QUILL_MISTRAL_SECRET=${QUILL_MISTRAL_SECRET}|tee-env-QUILL_KIMI_SECRET=${QUILL_KIMI_SECRET}|tee-env-QUILL_ZAI_SECRET=${QUILL_ZAI_SECRET}|tee-env-QUILL_TOGETHER_SECRET=${QUILL_TOGETHER_SECRET}|tee-env-QUILL_FIREWORKS_SECRET=${QUILL_FIREWORKS_SECRET}${COHERE_TEE_ENV}${VOYAGE_TEE_ENV}${XIAOMI_TEE_ENV}|tee-env-QUILL_GROK_SECRET=${QUILL_GROK_SECRET}|tee-env-QUILL_NOVITA_SECRET=${QUILL_NOVITA_SECRET}|tee-env-QUILL_PHALA_SECRET=${QUILL_PHALA_SECRET}|tee-env-QUILL_SILICONFLOW_SECRET=${QUILL_SILICONFLOW_SECRET}|tee-env-QUILL_TINFOIL_SECRET=${QUILL_TINFOIL_SECRET}|tee-env-QUILL_VENICE_SECRET=${QUILL_VENICE_SECRET}|tee-env-QUILL_PARASAIL_SECRET=${QUILL_PARASAIL_SECRET}|tee-env-QUILL_LIGHTNING_SECRET=${QUILL_LIGHTNING_SECRET}|tee-env-QUILL_GMI_SECRET=${QUILL_GMI_SECRET}|tee-env-QUILL_DEEPINFRA_SECRET=${QUILL_DEEPINFRA_SECRET}|tee-env-QUILL_NEBIUS_SECRET=${QUILL_NEBIUS_SECRET}|tee-env-QUILL_MINIMAX_SECRET=${QUILL_MINIMAX_SECRET}|tee-env-QUILL_ACME_CACHE_GCS_BUCKET=${QUILL_ACME_CACHE_GCS_BUCKET}|tee-env-QUILL_ACME_EMAIL=acme-${REGION}@trustedrouter.com|tee-env-QUILL_TRUSTEDROUTER_INTERNAL_SECRET=${QUILL_TRUSTEDROUTER_INTERNAL_SECRET}|tee-env-TR_CONTROL_PLANE_BASE_URL=${TR_CONTROL_PLANE_BASE_URL}|tee-env-QUILL_FIRST_BYTE_TIMEOUT_SECONDS=${QUILL_FIRST_BYTE_TIMEOUT_SECONDS}|tee-image-reference=${IMAGE_REF}|tee-restart-policy=Always" \
  >/dev/null

# 2. Create or update the MIG.
if gc compute instance-groups managed describe "$MIG_NAME" --region="$REGION" >/dev/null 2>&1; then
  log "updating MIG $MIG_NAME -> template $TEMPLATE (target size $TARGET_SIZE)"
  gc compute instance-groups managed set-instance-template "$MIG_NAME" \
    --region="$REGION" --template="$TEMPLATE" >/dev/null
  # NO MIG autohealing. The GCP passthrough-NLB health check cannot pass
  # against the Confidential Space enclave (TLS terminates in-VM; both the
  # :443 and the dedicated :8081 probes read UNHEALTHY on serving instances —
  # see the ENCLAVE_LB_TEARDOWN findings). Fleet health is owned by the
  # control-plane reconciler (tools/reconcile-enclave-dns.py), which attests
  # every instance and publishes only healthy ones into api.quillrouter.com
  # DNS. Actively CLEAR any autohealing a prior deploy attached so the broken
  # HC can never kill-loop the (capacity-scarce) Confidential VMs.
  gc compute instance-groups managed update "$MIG_NAME" \
    --region="$REGION" --clear-autohealing >/dev/null
  # Reconcile size on every deploy — lets us raise TARGET_SIZE for a
  # region (e.g. eu went 2→3 to absorb the 2026-05-11 watchdog-flap
  # pattern) without a one-shot operator step.
  current_size=$(gc compute instance-groups managed describe "$MIG_NAME" \
    --region="$REGION" --format='value(targetSize)' 2>/dev/null || echo "")
  if [ "$current_size" != "$TARGET_SIZE" ]; then
    log "resizing MIG $MIG_NAME: ${current_size:-?} -> $TARGET_SIZE"
    gc compute instance-groups managed resize "$MIG_NAME" \
      --region="$REGION" --size="$TARGET_SIZE" >/dev/null
  fi
  # Prefer a surge rollout so the regional gateway keeps serving while the
  # new attested image boots and passes health checks. Regional MIGs span
  # three zones, so the fixed surge default is 3.
  # NOTE: `gcloud compute instance-groups managed rolling-action replace`
  # does NOT support --min-ready (the flag exists on `rolling-action
  # start-update` but not on `replace`). The TCP-vs-TLS readiness gap
  # is instead absorbed by the `wait-until --stable` step in the
  # workflow that runs before each per-region canary — the canary
  # measures POST-rolling steady state, not the mid-drain window.
  gc compute instance-groups managed rolling-action replace "$MIG_NAME" \
    --region="$REGION" \
    --max-unavailable="$MAX_UNAVAILABLE" \
    --max-surge="$MAX_SURGE" >/dev/null
else
  log "creating MIG $MIG_NAME (size=$TARGET_SIZE)"
  # No --health-check / autohealing on create — see the update branch above.
  # Health is owned by the attesting DNS reconciler, not the MIG.
  gc compute instance-groups managed create "$MIG_NAME" \
    --base-instance-name="$MIG_NAME" \
    --template="$TEMPLATE" \
    --size="$TARGET_SIZE" \
    --region="$REGION" \
    --description="quill enclave gateway in $REGION (no MIG autohealing; health owned by tools/reconcile-enclave-dns.py)." >/dev/null
fi

cat <<EOF

quill-enclave gateway in $REGION is provisioned (no LB; DNS via reconciler).

  hostname (SNI):   $API_HOST
  template:         $TEMPLATE
  image:            $IMAGE_REF
  MIG size:         $TARGET_SIZE

EOF
