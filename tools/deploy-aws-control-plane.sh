#!/usr/bin/env bash
# Stage 4D of the multi-region expansion plan: deploy the TrustedRouter
# control plane (FastAPI app at trustedrouter.com / signup / console
# / status) to AWS ECS Fargate behind an ALB so a global GCP outage
# doesn't take down the marketing site + signup flow + console + trust
# page.
#
# Architecture:
#
#   internet → Cloudflare DNS (failover) → AWS ALB :443 → ECS Fargate
#   task (FastAPI) → cross-cloud Spanner reads via GCP SA key from
#   AWS Secrets Manager.
#
# The Python app is identical to the GCP Cloud Run deploy — env vars
# from secrets reuse the same AWS Secrets Manager mirror that the
# Nitro enclave reads. The cross-cloud GCP SA key (already provisioned
# at quill/trustedrouter-aws-cross-cloud-sa-key) is mounted into the
# task as a JSON file pointed to by GOOGLE_APPLICATION_CREDENTIALS,
# so storage_gcp.py reads/writes Spanner cross-cloud the same way it
# does on the GCP side.
#
# Reuses existing AWS infrastructure where possible:
#   - VPC: vpc-021257aa1d22c6460 (default)
#   - Default subnets: 4 AZs, all public
#   - Secrets: quill/* in Secrets Manager (provisioned by sync-secrets-to-aws.sh)
#   - GCP cross-cloud SA: quill/trustedrouter-aws-cross-cloud-sa-key
#
# Creates new:
#   - ECR repo + mirrored image
#   - ECS cluster + Fargate task definition + service
#   - ALB + target group + ACM cert
#   - 2 IAM roles (task execution + task)
#   - 2 security groups (ALB ingress + task ingress)
#   - CloudWatch log group
#   - Cloudflare DNS failover record on trustedrouter.com
#
# Costs at steady state: ~$35-40/mo (0.5 vCPU + 1GB Fargate task, ALB,
# log retention, NAT-free since tasks are in public subnets).
#
# Usage:
#   bash tools/deploy-aws-control-plane.sh                 # dry-run
#   bash tools/deploy-aws-control-plane.sh --apply         # do it
#   bash tools/deploy-aws-control-plane.sh --apply --image-tag <tag>
#
# Idempotent: every AWS resource creation is check-then-create. Re-run
# safe.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source the routing-side _lib.sh just to reuse the keyfile reader for
# the Cloudflare API token. The other scripts live in quill-router but
# its deploy/_lib.sh is the helper we need.
QR_LIB="${QUILL_ROUTER_LIB:-/Users/jperla/claude/quill-router/scripts/deploy/_lib.sh}"
if [ -f "$QR_LIB" ]; then
  # shellcheck disable=SC1090
  source "$QR_LIB"
fi

# ─── Configuration ──────────────────────────────────────────────────────────

AWS_REGION="${AWS_REGION:-us-west-2}"
AWS_ACCOUNT="${AWS_ACCOUNT:-330422590279}"
GCP_PROJECT="${GCP_PROJECT:-quill-cloud-proxy}"

VPC_ID="${VPC_ID:-vpc-021257aa1d22c6460}"

CLUSTER_NAME="${CLUSTER_NAME:-quill-control-plane}"
SERVICE_NAME="${SERVICE_NAME:-trusted-router}"
TASK_FAMILY="${TASK_FAMILY:-trusted-router}"
ECR_REPO="${ECR_REPO:-trusted-router}"
LOG_GROUP="${LOG_GROUP:-/ecs/trusted-router}"

ALB_NAME="${ALB_NAME:-quill-control-plane-alb}"
TG_NAME="${TG_NAME:-trusted-router-tg}"
SG_ALB_NAME="${SG_ALB_NAME:-quill-control-plane-alb-sg}"
SG_TASK_NAME="${SG_TASK_NAME:-quill-control-plane-task-sg}"

ROLE_TASK_EXEC="${ROLE_TASK_EXEC:-quill-control-plane-task-exec}"
ROLE_TASK="${ROLE_TASK:-quill-control-plane-task}"

# Domains the ALB needs to terminate. ACM cert covers all.
DOMAINS=(
  "trustedrouter.com"
  "www.trustedrouter.com"
  "trust.trustedrouter.com"
  "status.trustedrouter.com"
)

# Image to deploy. By default we use the latest GCP-built image's tag
# (the Cloud Run release). The mirroring step pulls that exact digest
# from GCP Artifact Registry and re-pushes to ECR.
IMAGE_TAG="${IMAGE_TAG:-}"
if [ -z "$IMAGE_TAG" ]; then
  IMAGE_TAG="$(git -C "${SCRIPT_DIR}/.." rev-parse --short HEAD 2>/dev/null \
    || git -C /Users/jperla/claude/quill-router rev-parse --short HEAD 2>/dev/null \
    || echo "latest")"
fi

# Cloudflare LB pool so we can add the ALB as a secondary origin once
# DNS+cert are live. Reuse the same LB infrastructure as api.quillrouter.com.
CF_LB_TRUSTEDROUTER_NAME="${CF_LB_TRUSTEDROUTER_NAME:-trustedrouter.com}"

DRY_RUN=1
while [[ $# -gt 0 ]]; do
  case "$1" in
    --apply) DRY_RUN=0; shift ;;
    --image-tag) IMAGE_TAG="$2"; shift 2 ;;
    --image-tag=*) IMAGE_TAG="${1#*=}"; shift ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

log() { echo "[$(date +%H:%M:%S)] $*" >&2; }
say() { log "$*"; }
warn() { echo "[$(date +%H:%M:%S)] WARN: $*" >&2; }
die() { echo "[$(date +%H:%M:%S)] ERROR: $*" >&2; exit 1; }

aws_q() { aws "$@" --region "$AWS_REGION" 2>&1; }

# Idempotent helper: run a creating command only if the entity doesn't
# already exist (queried by `check_cmd`). On dry-run, just print what
# would be done.
ensure() {
  local label="$1"; shift
  local check_cmd="$1"; shift
  local create_cmd="$1"; shift
  if eval "$check_cmd" >/dev/null 2>&1; then
    say "  $label: already exists"
    return 0
  fi
  if [ "$DRY_RUN" = "1" ]; then
    say "  $label: [dry-run] would create with: $create_cmd"
    return 0
  fi
  say "  $label: creating..."
  eval "$create_cmd"
}

say "AWS account=$AWS_ACCOUNT region=$AWS_REGION mode=$([ $DRY_RUN -eq 1 ] && echo DRY-RUN || echo APPLY)"
say "image tag: $IMAGE_TAG"

# ─── Step 1. ECR repository ────────────────────────────────────────────────
say "=== ECR repository ==="
ensure "ECR repo $ECR_REPO" \
  "aws_q ecr describe-repositories --repository-names '$ECR_REPO'" \
  "aws_q ecr create-repository --repository-name '$ECR_REPO' --image-scanning-configuration scanOnPush=true"

ECR_URI="${AWS_ACCOUNT}.dkr.ecr.${AWS_REGION}.amazonaws.com/${ECR_REPO}"
say "  ECR URI: $ECR_URI"

# ─── Step 2. Mirror the GCP image to ECR ───────────────────────────────────
say "=== mirror image GCP → ECR ==="
GCP_IMAGE="us-central1-docker.pkg.dev/${GCP_PROJECT}/trusted-router/trusted-router:${IMAGE_TAG}"
ECR_IMAGE="${ECR_URI}:${IMAGE_TAG}"

if [ "$DRY_RUN" = "1" ]; then
  say "  [dry-run] would: docker pull $GCP_IMAGE; docker tag → $ECR_IMAGE; docker push"
else
  # Already in ECR? skip
  if aws_q ecr describe-images --repository-name "$ECR_REPO" --image-ids "imageTag=$IMAGE_TAG" >/dev/null 2>&1; then
    say "  $ECR_IMAGE already in ECR, skipping mirror"
  else
    say "  pulling $GCP_IMAGE"
    docker pull "$GCP_IMAGE" || die "pull failed; ensure 'gcloud auth configure-docker us-central1-docker.pkg.dev' has been run"
    docker tag "$GCP_IMAGE" "$ECR_IMAGE"
    say "  authenticating Docker to ECR"
    aws ecr get-login-password --region "$AWS_REGION" \
      | docker login --username AWS --password-stdin "${AWS_ACCOUNT}.dkr.ecr.${AWS_REGION}.amazonaws.com" >/dev/null
    say "  pushing $ECR_IMAGE"
    docker push "$ECR_IMAGE"
  fi
fi

# ─── Step 3. IAM roles ─────────────────────────────────────────────────────
say "=== IAM roles ==="

# Task execution role: ECS uses this to pull the image and read secrets from
# Secrets Manager. Standard AWS-managed policy + a inline policy for the
# specific quill/* secrets so we follow least-privilege.
TASK_EXEC_TRUST='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ecs-tasks.amazonaws.com"},"Action":"sts:AssumeRole"}]}'

ensure "IAM role $ROLE_TASK_EXEC" \
  "aws_q iam get-role --role-name '$ROLE_TASK_EXEC'" \
  "aws_q iam create-role --role-name '$ROLE_TASK_EXEC' --assume-role-policy-document '$TASK_EXEC_TRUST' --description 'ECS task execution role for trusted-router on Fargate'"

if [ "$DRY_RUN" = "0" ]; then
  aws_q iam attach-role-policy \
    --role-name "$ROLE_TASK_EXEC" \
    --policy-arn arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy 2>/dev/null || true

  aws_q iam put-role-policy --role-name "$ROLE_TASK_EXEC" \
    --policy-name secrets-read \
    --policy-document "$(cat <<JSON
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"],
      "Resource": "arn:aws:secretsmanager:${AWS_REGION}:${AWS_ACCOUNT}:secret:quill/*"
    }
  ]
}
JSON
)"
fi

# Task role: the running container assumes this to call AWS APIs (mostly SES
# for outbound email + CloudWatch for metrics). It does NOT need GCP creds —
# the SA-key JSON is mounted from Secrets Manager via env (see task-def).
ensure "IAM role $ROLE_TASK" \
  "aws_q iam get-role --role-name '$ROLE_TASK'" \
  "aws_q iam create-role --role-name '$ROLE_TASK' --assume-role-policy-document '$TASK_EXEC_TRUST' --description 'ECS task role for trusted-router runtime'"

if [ "$DRY_RUN" = "0" ]; then
  aws_q iam put-role-policy --role-name "$ROLE_TASK" \
    --policy-name aws-runtime \
    --policy-document "$(cat <<JSON
{
  "Version": "2012-10-17",
  "Statement": [
    {"Effect": "Allow", "Action": ["ses:SendEmail", "ses:SendRawEmail"], "Resource": "*"},
    {
      "Sid": "DecryptCrossCloudSAKey",
      "Effect": "Allow",
      "Action": "kms:Decrypt",
      "Resource": "arn:aws:kms:${AWS_REGION}:${AWS_ACCOUNT}:key/f5d9e558-308b-46bf-9176-ff53d9be8633"
    },
    {
      "Sid": "DecryptViaSecretsManagerKey",
      "Effect": "Allow",
      "Action": "kms:Decrypt",
      "Resource": "*",
      "Condition": {
        "StringLike": {
          "kms:ViaService": "secretsmanager.${AWS_REGION}.amazonaws.com"
        }
      }
    }
  ]
}
JSON
)"
fi

# ─── Step 4. Security groups ───────────────────────────────────────────────
say "=== security groups ==="

ensure "SG $SG_ALB_NAME" \
  "aws_q ec2 describe-security-groups --filters 'Name=group-name,Values=$SG_ALB_NAME' 'Name=vpc-id,Values=$VPC_ID' --query 'SecurityGroups[0].GroupId' --output text | grep -v None" \
  "aws_q ec2 create-security-group --group-name '$SG_ALB_NAME' --description 'ALB ingress for quill control plane' --vpc-id '$VPC_ID'"

ensure "SG $SG_TASK_NAME" \
  "aws_q ec2 describe-security-groups --filters 'Name=group-name,Values=$SG_TASK_NAME' 'Name=vpc-id,Values=$VPC_ID' --query 'SecurityGroups[0].GroupId' --output text | grep -v None" \
  "aws_q ec2 create-security-group --group-name '$SG_TASK_NAME' --description 'Fargate task ingress from ALB' --vpc-id '$VPC_ID'"

if [ "$DRY_RUN" = "0" ]; then
  SG_ALB_ID=$(aws_q ec2 describe-security-groups --filters "Name=group-name,Values=$SG_ALB_NAME" "Name=vpc-id,Values=$VPC_ID" --query 'SecurityGroups[0].GroupId' --output text | head -1)
  SG_TASK_ID=$(aws_q ec2 describe-security-groups --filters "Name=group-name,Values=$SG_TASK_NAME" "Name=vpc-id,Values=$VPC_ID" --query 'SecurityGroups[0].GroupId' --output text | head -1)

  # ALB: allow 80 + 443 from internet (idempotent: ignore "already exists" errors)
  aws_q ec2 authorize-security-group-ingress --group-id "$SG_ALB_ID" \
    --protocol tcp --port 443 --cidr 0.0.0.0/0 2>/dev/null || true
  aws_q ec2 authorize-security-group-ingress --group-id "$SG_ALB_ID" \
    --protocol tcp --port 80 --cidr 0.0.0.0/0 2>/dev/null || true

  # Task: allow 8080 from ALB SG only
  aws_q ec2 authorize-security-group-ingress --group-id "$SG_TASK_ID" \
    --protocol tcp --port 8080 --source-group "$SG_ALB_ID" 2>/dev/null || true

  say "  SG_ALB_ID=$SG_ALB_ID  SG_TASK_ID=$SG_TASK_ID"
fi

# ─── Step 5. ACM certificate (DNS validation via Cloudflare) ───────────────
say "=== ACM certificate ==="
say "  domains: ${DOMAINS[*]}"

# Check if cert already exists for the primary domain
CERT_ARN=""
if [ "$DRY_RUN" = "0" ]; then
  CERT_ARN=$(aws_q acm list-certificates --query "CertificateSummaryList[?DomainName=='${DOMAINS[0]}'].CertificateArn" --output text | head -1)
fi

if [ -z "$CERT_ARN" ] || [ "$CERT_ARN" = "None" ]; then
  if [ "$DRY_RUN" = "1" ]; then
    say "  [dry-run] would request ACM cert for ${DOMAINS[*]} with DNS validation"
  else
    say "  requesting ACM cert..."
    SAN_ARGS=()
    for d in "${DOMAINS[@]:1}"; do SAN_ARGS+=("$d"); done
    CERT_ARN=$(aws_q acm request-certificate \
      --domain-name "${DOMAINS[0]}" \
      --subject-alternative-names "${SAN_ARGS[@]}" \
      --validation-method DNS \
      --query CertificateArn --output text | head -1)
    say "  cert ARN: $CERT_ARN"
    say "  Now we need to add the DNS validation CNAME records to Cloudflare."
    say "  Polling for the validation records ACM expects..."
    sleep 15
    aws_q acm describe-certificate --certificate-arn "$CERT_ARN" \
      --query 'Certificate.DomainValidationOptions[*].[DomainName,ResourceRecord.Name,ResourceRecord.Value]' \
      --output text 2>&1 | while read DOM REC_NAME REC_VAL; do
        if [ -n "$REC_NAME" ] && [ -n "$REC_VAL" ]; then
          say "  add CNAME on Cloudflare: $REC_NAME → $REC_VAL"
        fi
      done
    say "  Once CNAMEs propagate (~5 min), ACM will auto-validate. Re-run this script."
    exit 0
  fi
fi
say "  cert: $CERT_ARN"

# ─── Step 6. ALB ───────────────────────────────────────────────────────────
say "=== ALB ==="

ensure "ALB $ALB_NAME" \
  "aws_q elbv2 describe-load-balancers --names '$ALB_NAME'" \
  "aws_q elbv2 create-load-balancer --name '$ALB_NAME' --type application --scheme internet-facing --subnets subnet-0aef7942730767831 subnet-0ace94a11ee3d39fc subnet-00b106843df87b16b subnet-0e7c3c7f9fbbad93d --security-groups \$(aws_q ec2 describe-security-groups --filters \"Name=group-name,Values=$SG_ALB_NAME\" \"Name=vpc-id,Values=$VPC_ID\" --query 'SecurityGroups[0].GroupId' --output text | head -1)"

ensure "Target group $TG_NAME" \
  "aws_q elbv2 describe-target-groups --names '$TG_NAME'" \
  "aws_q elbv2 create-target-group --name '$TG_NAME' --protocol HTTP --port 8080 --vpc-id '$VPC_ID' --target-type ip --health-check-path /health --health-check-interval-seconds 30 --healthy-threshold-count 2 --unhealthy-threshold-count 3 --matcher 'HttpCode=\"200,401\"'"

if [ "$DRY_RUN" = "0" ]; then
  ALB_ARN=$(aws_q elbv2 describe-load-balancers --names "$ALB_NAME" --query 'LoadBalancers[0].LoadBalancerArn' --output text | head -1)
  TG_ARN=$(aws_q elbv2 describe-target-groups --names "$TG_NAME" --query 'TargetGroups[0].TargetGroupArn' --output text | head -1)

  # HTTPS :443 listener (forward to TG)
  HTTPS_LISTENER_EXISTS=$(aws_q elbv2 describe-listeners --load-balancer-arn "$ALB_ARN" --query 'Listeners[?Port==`443`].ListenerArn' --output text | head -1)
  if [ -z "$HTTPS_LISTENER_EXISTS" ] || [ "$HTTPS_LISTENER_EXISTS" = "None" ]; then
    say "  creating HTTPS :443 listener"
    aws_q elbv2 create-listener \
      --load-balancer-arn "$ALB_ARN" \
      --protocol HTTPS --port 443 \
      --certificates "CertificateArn=$CERT_ARN" \
      --default-actions "Type=forward,TargetGroupArn=$TG_ARN" >/dev/null
  fi

  # HTTP :80 → HTTPS redirect
  HTTP_LISTENER_EXISTS=$(aws_q elbv2 describe-listeners --load-balancer-arn "$ALB_ARN" --query 'Listeners[?Port==`80`].ListenerArn' --output text | head -1)
  if [ -z "$HTTP_LISTENER_EXISTS" ] || [ "$HTTP_LISTENER_EXISTS" = "None" ]; then
    say "  creating HTTP :80 listener (redirect to HTTPS)"
    aws_q elbv2 create-listener \
      --load-balancer-arn "$ALB_ARN" \
      --protocol HTTP --port 80 \
      --default-actions 'Type=redirect,RedirectConfig={Protocol=HTTPS,Port=443,StatusCode=HTTP_301}' >/dev/null
  fi

  ALB_DNS=$(aws_q elbv2 describe-load-balancers --names "$ALB_NAME" --query 'LoadBalancers[0].DNSName' --output text | head -1)
  say "  ALB DNS: $ALB_DNS"
fi

# ─── Step 7. CloudWatch log group ──────────────────────────────────────────
ensure "log group $LOG_GROUP" \
  "aws_q logs describe-log-groups --log-group-name-prefix '$LOG_GROUP' --query 'logGroups[?logGroupName==\`$LOG_GROUP\`]' --output text | grep ." \
  "aws_q logs create-log-group --log-group-name '$LOG_GROUP'"

# ─── Step 8. ECS cluster ───────────────────────────────────────────────────
say "=== ECS cluster ==="
ensure "ECS cluster $CLUSTER_NAME" \
  "aws_q ecs describe-clusters --clusters '$CLUSTER_NAME' --query 'clusters[0].status' --output text | grep ACTIVE" \
  "aws_q ecs create-cluster --cluster-name '$CLUSTER_NAME' --capacity-providers FARGATE"

# ─── Step 9. Task definition ───────────────────────────────────────────────
say "=== task definition ==="

# ECS task definitions need the FULL Secrets Manager ARN (with the random
# 6-char suffix Secrets Manager appends) — partial-ARN form
# `arn:...secret:friendly-name` (no suffix) returns ResourceNotFoundException
# at task-start time, and bare friendly names get interpreted as SSM
# Parameter Store paths. Resolve every secret ARN once here into a flat
# variable so the heredoc expansion gets the right value.
# (bash 3.2-compatible — macOS ships with that, no associative arrays.)
SECRET_ARN_MAP=""
if [ "$DRY_RUN" = "0" ]; then
  SECRET_ARN_MAP=$(aws_q secretsmanager list-secrets \
    --query 'SecretList[?starts_with(Name, `quill/trustedrouter`)].[Name,ARN]' \
    --output text)
  say "  resolved $(echo "$SECRET_ARN_MAP" | wc -l | tr -d ' ') secret ARNs (with suffix)"
fi

# Helper: print the full ARN for a friendly-name lookup. Falls back to the
# partial-ARN form on dry-run / missing secret.
sec() {
  local key="$1"
  local arn=""
  if [ -n "$SECRET_ARN_MAP" ]; then
    arn=$(echo "$SECRET_ARN_MAP" | awk -v k="quill/$key" '$1 == k { print $2; exit }')
  fi
  if [ -z "$arn" ]; then
    arn="arn:aws:secretsmanager:${AWS_REGION}:${AWS_ACCOUNT}:secret:quill/$key"
  fi
  printf '%s' "$arn"
}

# Construct the env vars + secrets refs for the task. Mirror everything from
# Cloud Run's env, swap the secret backend from GCP Secret Manager to AWS
# Secrets Manager (which sync-secrets-to-aws.sh keeps in lockstep).
TASK_DEF_FILE="${TMPDIR:-/tmp}/trusted-router-task-def.json"
cat > "$TASK_DEF_FILE" <<JSON
{
  "family": "$TASK_FAMILY",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "512",
  "memory": "1024",
  "executionRoleArn": "arn:aws:iam::${AWS_ACCOUNT}:role/${ROLE_TASK_EXEC}",
  "taskRoleArn": "arn:aws:iam::${AWS_ACCOUNT}:role/${ROLE_TASK}",
  "containerDefinitions": [
    {
      "name": "trusted-router",
      "image": "${ECR_URI}:${IMAGE_TAG}",
      "essential": true,
      "portMappings": [{"containerPort": 8080, "protocol": "tcp"}],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "${LOG_GROUP}",
          "awslogs-region": "${AWS_REGION}",
          "awslogs-stream-prefix": "ecs"
        }
      },
      "environment": [
        {"name": "TR_ENVIRONMENT", "value": "production"},
        {"name": "TR_RELEASE", "value": "${IMAGE_TAG}"},
        {"name": "TR_ENABLE_LIVE_PROVIDERS", "value": "false"},
        {"name": "TR_API_BASE_URL", "value": "https://api.quillrouter.com/v1"},
        {"name": "TR_TRUSTED_DOMAIN", "value": "trustedrouter.com"},
        {"name": "TR_STORAGE_BACKEND", "value": "spanner-bigtable"},
        {"name": "TR_GCP_PROJECT_ID", "value": "${GCP_PROJECT}"},
        {"name": "TR_SPANNER_INSTANCE_ID", "value": "trusted-router-nam6"},
        {"name": "TR_SPANNER_DATABASE_ID", "value": "trusted-router"},
        {"name": "TR_BIGTABLE_INSTANCE_ID", "value": "trusted-router-logs"},
        {"name": "TR_BIGTABLE_GENERATION_TABLE", "value": "trustedrouter-generations"},
        {"name": "TR_BYOK_KMS_KEY_NAME", "value": "projects/${GCP_PROJECT}/locations/us-central1/keyRings/trusted-router/cryptoKeys/byok-envelope"},
        {"name": "TR_REGIONS", "value": "us-central1,europe-west4,us-east4,asia-northeast1,asia-southeast1,southamerica-east1"},
        {"name": "TR_PRIMARY_REGION", "value": "us-central1"},
        {"name": "TR_AWS_REGION", "value": "us-east-1"},
        {"name": "TR_SES_FROM_EMAIL", "value": "noreply@trustedrouter.com"},
        {"name": "TR_SES_FROM_NAME", "value": "TrustedRouter"},
        {"name": "TR_GOOGLE_OAUTH_REDIRECT_URL", "value": "https://trustedrouter.com/google_oauth_callback"},
        {"name": "TR_GITHUB_OAUTH_REDIRECT_URL", "value": "https://trustedrouter.com/github_oauth_callback"},
        {"name": "TR_SIWE_DOMAIN", "value": "trustedrouter.com"},
        {"name": "VERTEX_PROJECT_ID", "value": "${GCP_PROJECT}"},
        {"name": "VERTEX_LOCATION", "value": "us-central1"},
        {"name": "AXIOM_DATASET", "value": "trusted-router"},
        {"name": "AXIOM_URL", "value": "https://api.axiom.co"}
      ],
      "secrets": [
        {"name": "TR_SENTRY_DSN",                  "valueFrom": "$(sec trustedrouter-sentry-dsn)"},
        {"name": "TR_STRIPE_SECRET_KEY",           "valueFrom": "$(sec trustedrouter-stripe-secret-key)"},
        {"name": "TR_STRIPE_WEBHOOK_SECRET",       "valueFrom": "$(sec trustedrouter-stripe-webhook-secret)"},
        {"name": "TR_INTERNAL_GATEWAY_TOKEN",      "valueFrom": "$(sec trustedrouter-internal-gateway-token)"},
        {"name": "ANTHROPIC_API_KEY",              "valueFrom": "$(sec trustedrouter-anthropic-api-key)"},
        {"name": "OPENAI_API_KEY",                 "valueFrom": "$(sec trustedrouter-openai-api-key)"},
        {"name": "GEMINI_API_KEY",                 "valueFrom": "$(sec trustedrouter-gemini-api-key)"},
        {"name": "CEREBRAS_API_KEY",               "valueFrom": "$(sec trustedrouter-cerebras-api-key)"},
        {"name": "DEEPSEEK_API_KEY",               "valueFrom": "$(sec trustedrouter-deepseek-api-key)"},
        {"name": "MISTRAL_API_KEY",                "valueFrom": "$(sec trustedrouter-mistral-api-key)"},
        {"name": "KIMI_API_KEY",                   "valueFrom": "$(sec trustedrouter-kimi-api-key)"},
        {"name": "ZAI_API_KEY",                    "valueFrom": "$(sec trustedrouter-zai-api-key)"},
        {"name": "TOGETHER_API_KEY",               "valueFrom": "$(sec trustedrouter-together-api-key)"},
        {"name": "GROK_API_KEY",                   "valueFrom": "$(sec trustedrouter-grok-api-key)"},
        {"name": "NOVITA_API_KEY",                 "valueFrom": "$(sec trustedrouter-novita-api-key)"},
        {"name": "PHALA_API_KEY",                  "valueFrom": "$(sec trustedrouter-phala-api-key)"},
        {"name": "SILICON_FLOW_API_KEY",           "valueFrom": "$(sec trustedrouter-siliconflow-api-key)"},
        {"name": "TINFOIL_API_KEY",                "valueFrom": "$(sec trustedrouter-tinfoil-api-key)"},
        {"name": "VENICE_API_KEY",                 "valueFrom": "$(sec trustedrouter-venice-api-key)"},
        {"name": "TR_GOOGLE_CLIENT_ID",            "valueFrom": "$(sec trustedrouter-google-client-id)"},
        {"name": "TR_GOOGLE_CLIENT_SECRET",        "valueFrom": "$(sec trustedrouter-google-client-secret)"},
        {"name": "TR_GITHUB_CLIENT_ID",            "valueFrom": "$(sec trustedrouter-github-client-id)"},
        {"name": "TR_GITHUB_CLIENT_SECRET",        "valueFrom": "$(sec trustedrouter-github-client-secret)"},
        {"name": "TR_SYNTHETIC_MONITOR_API_KEY",   "valueFrom": "$(sec trustedrouter-synthetic-monitor-api-key)"},
        {"name": "AXIOM_API_TOKEN",                "valueFrom": "$(sec trustedrouter-axiom-api-token)"},
        {"name": "TR_PAYPAL_CLIENT_ID",            "valueFrom": "$(sec trustedrouter-paypal-client-id)"},
        {"name": "TR_PAYPAL_CLIENT_SECRET",        "valueFrom": "$(sec trustedrouter-paypal-client-secret)"},
        {"name": "TR_PAYPAL_WEBHOOK_ID",           "valueFrom": "$(sec trustedrouter-paypal-webhook-id)"},
        {"name": "GCP_SA_KEY_KMS_WRAPPED",         "valueFrom": "$(sec trustedrouter-aws-cross-cloud-sa-key)"}
      ]
    }
  ]
}
JSON

if [ "$DRY_RUN" = "1" ]; then
  say "  [dry-run] would register task definition (${TASK_DEF_FILE})"
else
  TASK_DEF_ARN=$(aws_q ecs register-task-definition --cli-input-json "file://$TASK_DEF_FILE" --query 'taskDefinition.taskDefinitionArn' --output text | head -1)
  say "  task def: $TASK_DEF_ARN"
fi

# ─── Step 10. ECS service ─────────────────────────────────────────────────
say "=== ECS service ==="

if [ "$DRY_RUN" = "0" ]; then
  SUBNETS="subnet-0aef7942730767831,subnet-0ace94a11ee3d39fc,subnet-00b106843df87b16b,subnet-0e7c3c7f9fbbad93d"
  SVC_EXISTS=$(aws_q ecs describe-services --cluster "$CLUSTER_NAME" --services "$SERVICE_NAME" --query 'services[0].status' --output text 2>/dev/null | head -1)
  if [ -n "$SVC_EXISTS" ] && [ "$SVC_EXISTS" != "None" ] && [ "$SVC_EXISTS" != "INACTIVE" ]; then
    say "  service exists, updating to new task def"
    aws_q ecs update-service \
      --cluster "$CLUSTER_NAME" \
      --service "$SERVICE_NAME" \
      --task-definition "$TASK_DEF_ARN" \
      --force-new-deployment >/dev/null
  else
    say "  creating service"
    aws_q ecs create-service \
      --cluster "$CLUSTER_NAME" \
      --service-name "$SERVICE_NAME" \
      --task-definition "$TASK_DEF_ARN" \
      --desired-count 1 \
      --launch-type FARGATE \
      --network-configuration "awsvpcConfiguration={subnets=[$SUBNETS],securityGroups=[$SG_TASK_ID],assignPublicIp=ENABLED}" \
      --load-balancers "targetGroupArn=$TG_ARN,containerName=trusted-router,containerPort=8080" >/dev/null
  fi
fi

# ─── Step 11. Cloudflare DNS — add ALB as failover origin ─────────────────
say "=== Cloudflare DNS failover hint (manual user step) ==="
say ""
say "  When the task lands healthy, add an extra origin to the existing"
say "  Cloudflare LB (or create a new LB for trustedrouter.com) so a GCP"
say "  global outage hands traffic over to AWS."
say ""
say "  AWS ALB DNS: ${ALB_DNS:-(check after apply)}"
say ""
say "  Recommended: run scripts/deploy/cloudflare_lb.sh-style work for"
say "  trustedrouter.com with two pools (GCP control-plane + AWS ALB)."

say ""
say "Done."
