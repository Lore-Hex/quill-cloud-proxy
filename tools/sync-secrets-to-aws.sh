#!/usr/bin/env bash
# Mirror provider API keys + the cross-cloud GCP service-account key
# from GCP Secret Manager into AWS Secrets Manager (us-west-2).
#
# Why
# ===
# The AWS-deployed Nitro enclave (Stage 4 of the multi-region expansion
# plan) reaches every LLM provider over the same direct public APIs
# the GCP enclave already uses (api.anthropic.com, api.openai.com, ...).
# It needs the same provider API keys at hand. AWS Secrets Manager is
# the AWS-native secret store; mirroring from GCP Secret Manager keeps
# GCP as the single source of truth and lets the AWS-side enclave's
# bootstrap consume secrets the same way the GCP-side enclave does.
#
# Idempotency
# ===========
# - For every secret we mirror, this script either creates the AWS
#   secret (if absent) or updates the existing version (if present).
# - The AWS region is fixed at us-west-2 (the failover compute region).
# - Re-running this script after a key rotation in GCP picks up the
#   new value and pushes the rotation to AWS within one run.
#
# Run as
# ======
#   bash tools/sync-secrets-to-aws.sh                     # dry-run
#   bash tools/sync-secrets-to-aws.sh --apply             # actually do it
#   bash tools/sync-secrets-to-aws.sh --apply --secret QUILL_ANTHROPIC_SECRET
#         (sync just one secret)

set -euo pipefail

GCP_PROJECT="${GCP_PROJECT:-quill-cloud-proxy}"
AWS_REGION="${AWS_REGION:-us-west-2}"
AWS_SECRET_PREFIX="${AWS_SECRET_PREFIX:-quill/}"   # AWS secret name = prefix + GCP secret id

# Provider API key secrets that the multi-provider enclave consumes.
# Each entry is the GCP Secret Manager secret name. The corresponding
# env-var name the enclave reads is keyed off the same id (e.g.
# QUILL_ANTHROPIC_SECRET → AWS secret quill/QUILL_ANTHROPIC_SECRET).
SECRETS=(
  trustedrouter-anthropic-api-key
  trustedrouter-openai-api-key
  trustedrouter-gemini-api-key
  trustedrouter-cerebras-api-key
  trustedrouter-deepseek-api-key
  trustedrouter-mistral-api-key
  trustedrouter-kimi-api-key
  trustedrouter-zai-api-key
  trustedrouter-together-api-key
  trustedrouter-grok-api-key
  trustedrouter-novita-api-key
  trustedrouter-phala-api-key
  # Phala's GPU-TEE-attested confidential AI tier (cloud.phala.com
  # dashboard issues this key, distinct from the upstream redpill
  # tier). This is the key the enclave actually uses since
  # 2026-05-13 — model ids ship as `phala/<bare>` per
  # docs.phala.com/phala-cloud/confidential-ai. Mirrored so the
  # AWS Nitro enclave's parent bootstrap can fetch the same key.
  trustedrouter-phala-confidential-api-key
  trustedrouter-siliconflow-api-key
  trustedrouter-tinfoil-api-key
  trustedrouter-venice-api-key
  # 2026-05-11 batch.
  trustedrouter-parasail-api-key
  trustedrouter-lightning-api-key
  trustedrouter-gmi-api-key
  trustedrouter-deepinfra-api-key
  trustedrouter-nebius-api-key
  trustedrouter-minimax-api-key
  # Voyage AI — embeddings only (OpenAI-shaped /v1/embeddings). Mirrored so the
  # AWS Nitro enclave's parent bootstrap can fetch the same key as GCP.
  trustedrouter-voyage-api-key
  trustedrouter-tr-api-key-for-self-heal
  # The internal gateway token authenticates enclave→TR control-plane
  # calls (x-trustedrouter-internal-token header on /v1/internal/*).
  # Distinct from tr-api-key-for-self-heal which is a customer-facing
  # API key used by TR's self-heal flow as a customer of itself.
  trustedrouter-internal-gateway-token
  # Cross-cloud GCP service-account key. The AWS enclave uses this to
  # authenticate to GCP Spanner + Bigtable + KMS + Secret Manager.
  # Granted only the minimum permissions needed (datastore.user,
  # cloudkms.cryptoKeyDecrypter on byok-envelope, secretmanager.secretAccessor
  # on the trustedrouter-* secrets). See deploy-aws-nitro.sh for IAM setup.
  trustedrouter-aws-cross-cloud-sa-key
  # Stage 4D — control-plane secrets the FastAPI app needs on AWS ECS.
  # These weren't in scope for the enclave-only sync but are required
  # once trustedrouter.com runs on Fargate behind ALB. Without them the
  # task can't pull execution-role secrets and never starts.
  trustedrouter-sentry-dsn
  trustedrouter-stripe-secret-key
  trustedrouter-stripe-webhook-secret
  trustedrouter-google-client-id
  trustedrouter-google-client-secret
  trustedrouter-github-client-id
  trustedrouter-github-client-secret
  trustedrouter-axiom-api-token
  trustedrouter-paypal-client-id
  trustedrouter-paypal-client-secret
  trustedrouter-paypal-webhook-id
  trustedrouter-synthetic-monitor-api-key
  # DNS-01 ACME fallback (enclave-go/internal/enclavetls/dns01.go).
  # The token is Cloudflare's Zone:DNS:Edit scoped to quillrouter.com;
  # the zone id is a stable 32-char hex string. Both are optional —
  # if either is missing, the DNS-01 renewer no-ops and TLS-ALPN-01
  # via the shared GCS cache remains the only renewal path.
  cloudflare-api-token
  cloudflare-zone-id
)

DRY_RUN=1
ONLY_SECRET=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --apply) DRY_RUN=0; shift ;;
    --secret) ONLY_SECRET="$2"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

log() { echo "[$(date +%H:%M:%S)] $*" >&2; }

# Sanity check both CLIs are configured.
if ! gcloud auth list --format='value(account)' --filter='status:ACTIVE' >/dev/null 2>&1; then
  log "FATAL: gcloud not authenticated. Run 'gcloud auth login'." >&2
  exit 1
fi
if ! aws sts get-caller-identity --region "$AWS_REGION" >/dev/null 2>&1; then
  log "FATAL: aws CLI not authenticated. Run 'aws configure' or set AWS_PROFILE." >&2
  exit 1
fi

aws_account=$(aws sts get-caller-identity --query Account --output text)
log "GCP project: $GCP_PROJECT"
log "AWS account: $aws_account region: $AWS_REGION"
log "Mode: $([ $DRY_RUN -eq 1 ] && echo DRY-RUN || echo APPLY)"

mirror_one() {
  local gcp_secret_name="$1"
  local aws_secret_name="${AWS_SECRET_PREFIX}${gcp_secret_name}"

  log "→ ${gcp_secret_name}"

  # Read the latest version from GCP. If the secret doesn't exist in GCP,
  # we don't create one in AWS — that would be a footgun (creating
  # phantom secrets in the failover store that don't have a source of
  # truth). Skip with a warning instead.
  local value
  if ! value=$(gcloud secrets versions access latest \
      --secret="$gcp_secret_name" \
      --project="$GCP_PROJECT" 2>/dev/null); then
    log "  WARN: GCP secret '$gcp_secret_name' not found; skipping"
    return
  fi

  if [ $DRY_RUN -eq 1 ]; then
    log "  would write to AWS Secrets Manager: $aws_secret_name (${#value} bytes)"
    return
  fi

  # AWS create-or-update pattern. Try create first; if it 409s, do an update.
  if aws secretsmanager describe-secret --secret-id "$aws_secret_name" \
       --region "$AWS_REGION" >/dev/null 2>&1; then
    log "  updating existing AWS secret"
    aws secretsmanager put-secret-value \
      --secret-id "$aws_secret_name" \
      --secret-string "$value" \
      --region "$AWS_REGION" >/dev/null
  else
    log "  creating new AWS secret"
    aws secretsmanager create-secret \
      --name "$aws_secret_name" \
      --description "Mirrored from GCP Secret Manager (project=${GCP_PROJECT}, secret=${gcp_secret_name}). Source of truth lives in GCP; this script keeps AWS in sync." \
      --secret-string "$value" \
      --region "$AWS_REGION" \
      --tags 'Key=Source,Value=gcp-secret-manager' \
             "Key=GcpSecretName,Value=${gcp_secret_name}" >/dev/null
  fi
}

if [ -n "$ONLY_SECRET" ]; then
  mirror_one "$ONLY_SECRET"
else
  for secret in "${SECRETS[@]}"; do
    mirror_one "$secret"
  done
fi

log "done"
