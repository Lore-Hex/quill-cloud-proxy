#!/usr/bin/env bash
# Publish provider API keys into AWS Secrets Manager, this cloud's own store.
#
# SOURCE (pick one)
#   --values FILE   a JSON object of {secret id: value}, supplied by the deploy.
#                   PREFERRED.
#   --from-gcp      read Google Secret Manager. How these secrets originally
#                   reached AWS, and still the right tool for a one-time
#                   migration or a reconcile against the historical source.
#
# Why the file is preferred
# =========================
# Reading from GCP makes GCP the hub every other cloud depends on to be
# PROVISIONED - the same coupling separate clouds exist to remove, moved one
# layer up. It also means a key rotation cannot reach any cloud until GCP is
# reachable. The deploy already holds these values in order to publish them
# anywhere, so handing them to each cloud directly keeps every cloud a peer and
# leaves no cloud able to block another's bring-up.
#
# Either way the ENCLAVE only ever reads AWS Secrets Manager; the source here is
# a provisioning-time question, not a runtime one.
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
  quill-openrouter-key
  trustedrouter-anthropic-api-key
  trustedrouter-openai-api-key
  trustedrouter-gemini-api-key
  trustedrouter-cerebras-api-key
  trustedrouter-deepseek-api-key
  trustedrouter-mistral-api-key
  trustedrouter-kimi-api-key
  trustedrouter-zai-api-key
  trustedrouter-together-api-key
  trustedrouter-fireworks-api-key
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
  trustedrouter-friendli-api-key
  trustedrouter-baseten-api-key
  trustedrouter-thinking-machines-api-key
  trustedrouter-wafer-api-key
  trustedrouter-crusoe-api-key
  trustedrouter-makora-api-key
  trustedrouter-nebius-api-key
  trustedrouter-minimax-api-key
  trustedrouter-synth-panel-prompt-v1
  trustedrouter-synth-synthesis-prompt-v1
  trustedrouter-synth-code-panel-prompt-v1
  trustedrouter-synth-code-synthesis-prompt-v1
  # Voyage AI — embeddings only (OpenAI-shaped /v1/embeddings). Mirrored so the
  # AWS Nitro enclave's parent bootstrap can fetch the same key as GCP.
  trustedrouter-voyage-api-key
  # Xiaomi MiMo — OpenAI-compatible chat (api.xiaomimimo.com/v1).
  trustedrouter-xiaomi-api-key
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
STANDALONE=0
# Where the values come from. A deploy-supplied JSON file of
# {secret id: value} is the DEFAULT SOURCE when given; --from-gcp reads Google
# Secret Manager instead.
#
# Why the file is the better default: reading from GCP makes GCP the hub every
# other cloud depends on for provisioning, which is the same coupling the
# separate clouds exist to remove, one layer up. It also means rotating a key
# requires GCP to be reachable before any other cloud can be brought up. The
# deploy already has to hold these values to put them anywhere; letting it hand
# them to each cloud directly keeps every cloud a peer.
#
# --from-gcp is kept because it is how these secrets originally reached AWS and
# is still the right tool for a one-time migration or a reconcile against the
# historical source. It is no longer the recommended path.
VALUES_FILE=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --apply) DRY_RUN=0; shift ;;
    --secret) ONLY_SECRET="$2"; shift 2 ;;
    --values)
      VALUES_FILE="$2"; shift 2; continue ;;
    --from-gcp)
      VALUES_FILE=""; shift; continue ;;
    --standalone) STANDALONE=1; shift ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

# Secrets that must NOT be mirrored into a STANDALONE regional deployment
# (aws.trustedrouter.com). Under the separation architecture such a region
# owns its own database, credits, and TLS identity, and holds no GCP
# credential: mirroring the cross-cloud SA key there would re-create
# exactly the cross-cloud coupling the separation removes, and hand a
# GDPR-scoped EU deployment a key to US-hosted GCP resources.
#
# The parent tolerates the absence (bootstrap_server._unwrap_gcp_sa_key
# returns None and logs bootstrap.gcp_sa_key_absent).
STANDALONE_EXCLUDE=(
  trustedrouter-aws-cross-cloud-sa-key
)

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
  if [ -n "$VALUES_FILE" ]; then
    # A deploy-supplied file. Absent here means the operator did not intend to
    # publish this secret, so skip it rather than reaching for another cloud —
    # a silent fallback is how a "deploy-sourced" sync quietly becomes a
    # GCP-sourced one again.
    if ! value=$(VALUES_FILE="$VALUES_FILE" SECRET_ID="$gcp_secret_name" python3 -c '
import json, os, sys
values = json.load(open(os.environ["VALUES_FILE"]))
v = values.get(os.environ["SECRET_ID"])
if v is None or not str(v).strip():
    sys.exit(1)
sys.stdout.write(str(v))
' 2>/dev/null); then
      log "  WARN: '$gcp_secret_name' absent from $VALUES_FILE; skipping"
      return
    fi
  elif ! value=$(gcloud secrets versions access latest \
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
      --description "$([ -n "$VALUES_FILE" ] \
        && echo "Published by the deploy (tools/sync-secrets-to-aws.sh --values). AWS Secrets Manager is this cloud's own store; no other cloud is read at runtime." \
        || echo "Mirrored from GCP Secret Manager (project=${GCP_PROJECT}, secret=${gcp_secret_name}) by a --from-gcp migration run.")" \
      --secret-string "$value" \
      --region "$AWS_REGION" \
      --tags "Key=Source,Value=$([ -n "$VALUES_FILE" ] && echo deploy || echo gcp-secret-manager)" \
             "Key=GcpSecretName,Value=${gcp_secret_name}" >/dev/null
  fi
}

skip_in_standalone() {
  local candidate="$1"
  [ "$STANDALONE" -eq 1 ] || return 1
  local excluded
  for excluded in "${STANDALONE_EXCLUDE[@]}"; do
    [ "$candidate" = "$excluded" ] && return 0
  done
  return 1
}

if [ -n "$ONLY_SECRET" ]; then
  if skip_in_standalone "$ONLY_SECRET"; then
    log "SKIP (standalone region): $ONLY_SECRET"
  else
    mirror_one "$ONLY_SECRET"
  fi
else
  for secret in "${SECRETS[@]}"; do
    if skip_in_standalone "$secret"; then
      log "SKIP (standalone region): $secret"
      continue
    fi
    mirror_one "$secret"
  done
fi

log "done"
