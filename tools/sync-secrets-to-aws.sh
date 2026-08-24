#!/usr/bin/env bash
# Publish provider API keys into AWS Secrets Manager, this cloud's own store.
#
# SOURCE: --values FILE, a JSON object of {secret id: value} supplied by the
# deploy. There is no other source, deliberately.
#
# This script used to read Google Secret Manager and describe GCP as "the single
# source of truth". That made GCP a hub every other cloud depended on to be
# PROVISIONED - the same coupling separate clouds exist to remove, moved one
# layer up from runtime. It meant no cloud could be brought up or have a key
# rotated while GCP was unreachable, and every new cloud inherited whatever the
# hub happened to be missing.
#
# The GCP path is gone rather than deprecated. A second source kept "for
# migration" is a second source somebody uses, and the two produce different
# results without saying which ran - the failure mode being avoided.
#
# The deploy already holds these values in order to publish them anywhere, so
# handing them to each cloud directly keeps every cloud a peer.
#
# The ENCLAVE only ever reads AWS Secrets Manager. The source here is a
# provisioning-time question, never a runtime one.
#
# Why
# ===
# The AWS-deployed Nitro enclave (Stage 4 of the multi-region expansion
# plan) reaches every LLM provider over the same direct public APIs
# the GCP enclave already uses (api.anthropic.com, api.openai.com, ...).
# It needs the same provider API keys at hand. AWS Secrets Manager is
# the AWS-native secret store. The operator's restricted local source publishes
# an independent copy to each cloud, so AWS provisioning and runtime do not
# depend on GCP availability.
#
# Idempotency
# ===========
# - For every secret we mirror, this script either creates the AWS
#   secret (if absent) or updates the existing version (if present).
# - The AWS region is fixed at us-west-2 (the failover compute region).
# - Re-running this script after an operator key rotation publishes the new
#   value to AWS within one run.
#
# Run as
# ======
#   bash tools/sync-secrets-to-aws.sh                     # dry-run
#   bash tools/sync-secrets-to-aws.sh --apply             # actually do it
#   bash tools/sync-secrets-to-aws.sh --apply --secret QUILL_ANTHROPIC_SECRET
#         (sync just one secret)

set -euo pipefail

AWS_REGION="${AWS_REGION:-us-west-2}"
AWS_SECRET_PREFIX="${AWS_SECRET_PREFIX:-quill/}"   # AWS secret name = prefix + GCP secret id

# Provider API key secrets that the multi-provider enclave consumes.
# Each entry is the provider secret's stable logical name. The corresponding
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
  trustedrouter-azure-api-key
  trustedrouter-synth-panel-prompt-v1
  trustedrouter-synth-synthesis-prompt-v1
  trustedrouter-synth-code-panel-prompt-v1
  trustedrouter-synth-code-synthesis-prompt-v1
  # Voyage AI — embeddings only (OpenAI-shaped /v1/embeddings). Mirrored so the
  # AWS Nitro enclave's parent bootstrap can fetch the same key as GCP.
  trustedrouter-voyage-api-key
  # Xiaomi MiMo — OpenAI-compatible chat (api.xiaomimimo.com/v1).
  trustedrouter-xiaomi-api-key
  # Provider-wave chat endpoints. Recraft, BFL, and Decart are deliberately
  # excluded because the AWS enclave build has no media adapter.
  trustedrouter-stepfun-api-key
  trustedrouter-relace-api-key
  trustedrouter-nextbit-api-key
  trustedrouter-aion-labs-api-key
  trustedrouter-sambanova-api-key
  trustedrouter-inception-api-key
  trustedrouter-akashml-api-key
  trustedrouter-arcee-api-key
  trustedrouter-upstage-api-key
  trustedrouter-reka-api-key
  trustedrouter-sail-research-api-key
  trustedrouter-mancer-api-key
  trustedrouter-io-net-api-key
  trustedrouter-scaleway-api-key
  trustedrouter-featherless-api-key
  trustedrouter-jina-api-key
  trustedrouter-sakana-api-key
  trustedrouter-tr-api-key-for-self-heal
  # The internal gateway token authenticates enclave→TR control-plane
  # calls (x-trustedrouter-internal-token header on /v1/internal/*).
  # Distinct from tr-api-key-for-self-heal which is a customer-facing
  # API key used by TR's self-heal flow as a customer of itself.
  trustedrouter-internal-gateway-token
  # Federation shared token: a peer plane presents it, the home plane
  # validates it (TR_FEDERATION_HOME_TOKEN on the peer, TR_FEDERATION_PEER_TOKEN
  # on home — one value, two roles). Grants directory READS only; the
  # credit-transfer endpoints require different tokens by design, so this
  # secret can never move money.
  trustedrouter-federation-peer-token
  # Per-plane deferred-settlement tokens. Possession identifies the plane at
  # home's apply-usage endpoint; each debits usage only and can never mint.
  trustedrouter-federation-settlement-token-aws-eu
  trustedrouter-federation-settlement-token-azure-uae
  # Home's token map (plane=token,...), generated from the per-plane files.
  trustedrouter-federation-settlement-inbound-tokens
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
# {secret id: value} is the ONLY source.
#
VALUES_FILE=""
# The operator's own files, same two sources Azure resolves from. Provider keys
# are short tokens in an env file under the operator's own names; prompts and the
# device blob are one file each, because escaping a 2 KB prompt into an env line
# turns a bug there into a silent behaviour change. See tools/quill_secret_sources.py.
KEYS_FILE="${KEYS_FILE:-$HOME/.quill_cloud_keys.private}"
SECRETS_DIR="${SECRETS_DIR:-$HOME/.quill-secrets}"
RESOLVED_VALUES=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --apply) DRY_RUN=0; shift ;;
    --secret) ONLY_SECRET="$2"; shift 2 ;;
    --values)
      VALUES_FILE="$2"; shift 2; continue ;;
    --keys-file)
      KEYS_FILE="$2"; shift 2; continue ;;
    --secrets-dir)
      SECRETS_DIR="$2"; shift 2; continue ;;
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
if false; then
  :
  exit 1
fi
if ! aws sts get-caller-identity --region "$AWS_REGION" >/dev/null 2>&1; then
  log "FATAL: aws CLI not authenticated. Run 'aws configure' or set AWS_PROFILE." >&2
  exit 1
fi

aws_account=$(aws sts get-caller-identity --query Account --output text)
# With no explicit --values, resolve from the operator's own files. This is the
# ordinary path: the values already live on the deploy machine, so no cloud is
# read and no cloud is a hub another one needs in order to come up.
if [ -z "$VALUES_FILE" ]; then
  needed_json="$(mktemp)"; RESOLVED_VALUES="$(mktemp)"
  chmod 600 "$needed_json" "$RESOLVED_VALUES"
  trap 'rm -f "$needed_json" "$RESOLVED_VALUES"' EXIT
  printf '%s\n' "${SECRETS[@]}" | python3 -c '
import json, sys
json.dump([l.strip() for l in sys.stdin if l.strip()], open(sys.argv[1], "w"))
' "$needed_json"
  log "resolving from your files: $KEYS_FILE + $SECRETS_DIR"
  python3 "$(dirname "${BASH_SOURCE[0]}")/quill_secret_sources.py" \
    "$needed_json" "$RESOLVED_VALUES" "$KEYS_FILE" "$SECRETS_DIR"
  VALUES_FILE="$RESOLVED_VALUES"
fi

log "AWS account: $aws_account region: $AWS_REGION"
log "Mode: $([ $DRY_RUN -eq 1 ] && echo DRY-RUN || echo APPLY)"

mirror_one() {
  local secret_id="$1"
  local aws_secret_name="${AWS_SECRET_PREFIX}${secret_id}"

  log "→ ${secret_id}"

  # Read the latest version from GCP. If the secret doesn't exist in GCP,
  # we don't create one in AWS — that would be a footgun (creating
  # phantom secrets in the failover store that don't have a source of
  # truth). Skip with a warning instead.
  local value
  # Absent here means the operator did not intend to publish this secret, so
  # skip it. There is nowhere else to look by design.
  if true; then
    if ! value=$(VALUES_FILE="$VALUES_FILE" SECRET_ID="$secret_id" python3 -c '
import json, os, sys
values = json.load(open(os.environ["VALUES_FILE"]))
v = values.get(os.environ["SECRET_ID"])
if v is None or not str(v).strip():
    sys.exit(1)
sys.stdout.write(str(v))
' 2>/dev/null); then
      log "  WARN: '$secret_id' absent from $VALUES_FILE; skipping"
      return
    fi
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
      --description "Published by the deploy (tools/sync-secrets-to-aws.sh --values). AWS Secrets Manager is this cloud's own store; no other cloud is read, at provisioning time or at runtime." \
      --secret-string "$value" \
      --region "$AWS_REGION" \
      --tags 'Key=Source,Value=deploy' \
             "Key=SecretId,Value=${secret_id}" >/dev/null
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
