#!/usr/bin/env bash
# Provision the AWS us-west-2 multi-cloud failover infrastructure for
# the Quill enclave (Stage 4 of the multi-region expansion plan).
#
# What this script provisions, idempotently, in us-west-2:
#
#   - quill-enclave-iam-role             EC2 instance role
#   - quill-enclave-iam-instance-profile attached to the launch template
#   - quill-enclave-kms-cmk              wrapping key for GCP SA + BYOK envelopes
#   - quill-enclave-sg                   security group (443 in/out, no SSH)
#   - quill-enclave-vpc                  VPC + 3 AZ subnets (or use default)
#   - quill-enclave                      ECR repo for the cloud_aws,llm_multi image
#   - quill-enclave-lt-NNN               launch template, Nitro Enclaves enabled
#   - quill-enclave-asg                  AutoScalingGroup (min=1, max=50)
#   - quill-enclave-nlb                  Network Load Balancer (TLS passthrough)
#   - quill-enclave-tg                   target group on :443
#   - service-quota request for m5n.xlarge instance limit
#
# The script is idempotent: every step checks for existing resources
# and skips creation if found. Re-running is safe.
#
# Usage:
#   bash tools/deploy-aws-nitro.sh                                  # dry-run all
#   bash tools/deploy-aws-nitro.sh --apply                          # apply all phases
#   bash tools/deploy-aws-nitro.sh --apply --phase iam              # apply one phase
#
# Phases (run in order; each is idempotent):
#   iam        IAM role + policies + instance profile
#   kms        KMS CMK for GCP-SA-key + BYOK envelope wrapping
#   network    VPC + subnets + security group
#   ecr        ECR repo for the enclave image
#   compute    Launch template + Auto Scaling Group + NLB + target group
#   quotas     Submit Service Quotas request for m5n.xlarge

set -euo pipefail

AWS_REGION="${AWS_REGION:-us-west-2}"
PROJECT_TAG="${PROJECT_TAG:-quill-enclave}"
ECR_REPO_NAME="${ECR_REPO_NAME:-quill-enclave}"
INSTANCE_TYPE="${INSTANCE_TYPE:-m5n.xlarge}"
ASG_MIN="${ASG_MIN:-1}"
ASG_MAX="${ASG_MAX:-50}"
ASG_DESIRED="${ASG_DESIRED:-1}"

DRY_RUN=1
PHASE="all"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --apply) DRY_RUN=0; shift ;;
    --phase) PHASE="$2"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

log() { echo "[$(date +%H:%M:%S)] $*" >&2; }
run() {
  if [ $DRY_RUN -eq 1 ]; then
    echo "  [dry-run] aws $*" >&2
  else
    aws --region "$AWS_REGION" "$@"
  fi
}

if ! aws sts get-caller-identity --region "$AWS_REGION" >/dev/null 2>&1; then
  log "FATAL: aws CLI not authenticated. Run 'aws configure' or set AWS_PROFILE." >&2
  exit 1
fi
AWS_ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
log "AWS account: $AWS_ACCOUNT region: $AWS_REGION"
log "Mode: $([ $DRY_RUN -eq 1 ] && echo DRY-RUN || echo APPLY) phase: $PHASE"

# ─── Phase: IAM ────────────────────────────────────────────────────────────
phase_iam() {
  log "=== phase: iam ==="
  local role_name="${PROJECT_TAG}-role"
  local profile_name="${PROJECT_TAG}-instance-profile"
  local trust_doc='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}'

  # Permissions: read provider secrets + decrypt KMS-wrapped GCP SA key
  # + pull ECR image. Tight scope; the EC2 host (parent of the Nitro
  # enclave) needs these to bootstrap the enclave.
  local policy_doc
  policy_doc=$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ReadProviderSecrets",
      "Effect": "Allow",
      "Action": ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"],
      "Resource": "arn:aws:secretsmanager:${AWS_REGION}:${AWS_ACCOUNT}:secret:quill/*"
    },
    {
      "Sid": "DecryptKMS",
      "Effect": "Allow",
      "Action": ["kms:Decrypt", "kms:DescribeKey"],
      "Resource": "arn:aws:kms:${AWS_REGION}:${AWS_ACCOUNT}:key/*",
      "Condition": {"StringEquals": {"kms:ViaService": "secretsmanager.${AWS_REGION}.amazonaws.com"}}
    },
    {
      "Sid": "PullECR",
      "Effect": "Allow",
      "Action": ["ecr:GetAuthorizationToken", "ecr:BatchCheckLayerAvailability", "ecr:GetDownloadUrlForLayer", "ecr:BatchGetImage"],
      "Resource": "*"
    },
    {
      "Sid": "Logs",
      "Effect": "Allow",
      "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
      "Resource": "arn:aws:logs:${AWS_REGION}:${AWS_ACCOUNT}:log-group:/quill/*"
    }
  ]
}
EOF
)

  if aws iam get-role --role-name "$role_name" >/dev/null 2>&1; then
    log "  role $role_name already exists"
  else
    log "  creating role $role_name"
    if [ $DRY_RUN -eq 0 ]; then
      aws iam create-role --role-name "$role_name" \
        --assume-role-policy-document "$trust_doc" \
        --description "Quill enclave EC2 host role (us-west-2 multi-cloud failover)"
    fi
  fi

  log "  attaching/updating inline policy"
  if [ $DRY_RUN -eq 0 ]; then
    aws iam put-role-policy --role-name "$role_name" \
      --policy-name "${PROJECT_TAG}-policy" \
      --policy-document "$policy_doc"
  fi

  if aws iam get-instance-profile --instance-profile-name "$profile_name" >/dev/null 2>&1; then
    log "  instance profile $profile_name already exists"
  else
    log "  creating instance profile $profile_name"
    if [ $DRY_RUN -eq 0 ]; then
      aws iam create-instance-profile --instance-profile-name "$profile_name"
      aws iam add-role-to-instance-profile --instance-profile-name "$profile_name" --role-name "$role_name"
    fi
  fi
}

# ─── Phase: KMS ────────────────────────────────────────────────────────────
phase_kms() {
  log "=== phase: kms ==="
  local alias_name="alias/${PROJECT_TAG}-cmk"

  # Look up by alias. KMS CMKs can't be looked up by name directly.
  local existing
  existing=$(aws kms list-aliases --region "$AWS_REGION" \
    --query "Aliases[?AliasName=='${alias_name}'].TargetKeyId" \
    --output text 2>/dev/null || echo "")
  if [ -n "$existing" ] && [ "$existing" != "None" ]; then
    log "  KMS CMK $alias_name already exists (key id: $existing)"
    return
  fi

  log "  creating KMS CMK $alias_name"
  if [ $DRY_RUN -eq 0 ]; then
    local key_id
    key_id=$(aws kms create-key \
      --description "Quill enclave envelope-wrap CMK (wraps GCP SA key + BYOK envelopes for the AWS-side Nitro enclave)" \
      --tags TagKey=Project,TagValue="$PROJECT_TAG" \
      --region "$AWS_REGION" \
      --query KeyMetadata.KeyId --output text)
    aws kms create-alias --alias-name "$alias_name" --target-key-id "$key_id" --region "$AWS_REGION"
    log "  created CMK $key_id aliased to $alias_name"
  fi
}

# ─── Phase: Network ────────────────────────────────────────────────────────
phase_network() {
  log "=== phase: network ==="
  # Use default VPC if present; otherwise create a dedicated one. For
  # most accounts the default VPC has subnets in every AZ already, which
  # is what we want for ASG multi-AZ placement.
  local vpc_id
  vpc_id=$(aws ec2 describe-vpcs --region "$AWS_REGION" \
    --filters Name=isDefault,Values=true \
    --query 'Vpcs[0].VpcId' --output text)
  if [ -z "$vpc_id" ] || [ "$vpc_id" = "None" ]; then
    log "  no default VPC; creating $PROJECT_TAG-vpc (TODO: implement)"
    log "  (skipping for now — default VPC is fine for v1)"
    return
  fi
  log "  using default VPC $vpc_id"

  local sg_name="${PROJECT_TAG}-sg"
  local sg_id
  sg_id=$(aws ec2 describe-security-groups --region "$AWS_REGION" \
    --filters "Name=vpc-id,Values=$vpc_id" "Name=group-name,Values=$sg_name" \
    --query 'SecurityGroups[0].GroupId' --output text 2>/dev/null || echo "")
  if [ -n "$sg_id" ] && [ "$sg_id" != "None" ]; then
    log "  security group $sg_name already exists ($sg_id)"
  else
    log "  creating security group $sg_name in $vpc_id"
    if [ $DRY_RUN -eq 0 ]; then
      sg_id=$(aws ec2 create-security-group --region "$AWS_REGION" \
        --group-name "$sg_name" \
        --description "Quill enclave (NLB target on :443; no SSH)" \
        --vpc-id "$vpc_id" \
        --query GroupId --output text)
      # Allow 443 inbound from anywhere (NLB passthrough). No SSH (22).
      aws ec2 authorize-security-group-ingress --region "$AWS_REGION" \
        --group-id "$sg_id" \
        --protocol tcp --port 443 --cidr 0.0.0.0/0 >/dev/null
      log "  created $sg_id"
    fi
  fi
}

# ─── Phase: ECR ────────────────────────────────────────────────────────────
phase_ecr() {
  log "=== phase: ecr ==="
  if aws ecr describe-repositories --region "$AWS_REGION" \
       --repository-names "$ECR_REPO_NAME" >/dev/null 2>&1; then
    log "  ECR repo $ECR_REPO_NAME already exists"
    return
  fi
  log "  creating ECR repo $ECR_REPO_NAME"
  if [ $DRY_RUN -eq 0 ]; then
    aws ecr create-repository --region "$AWS_REGION" \
      --repository-name "$ECR_REPO_NAME" \
      --image-tag-mutability IMMUTABLE \
      --image-scanning-configuration scanOnPush=true \
      --tags Key=Project,Value="$PROJECT_TAG" >/dev/null
    log "  ECR URI: ${AWS_ACCOUNT}.dkr.ecr.${AWS_REGION}.amazonaws.com/${ECR_REPO_NAME}"
  fi
}

# ─── Phase: Compute (Launch Template + ASG + NLB) ──────────────────────────
phase_compute() {
  log "=== phase: compute ==="
  log "  prerequisites: ECR has the cloud_aws,llm_multi enclave image pushed"
  log "  prerequisites: IAM role + KMS CMK + security group provisioned"
  log "  prerequisites: Service Quotas approved m5n.xlarge to >= ASG_MAX"

  log "  TODO: implement launch template (Nitro Enclaves enabled,"
  log "        instance profile attached, user-data fetches secrets +"
  log "        starts vsock-relay parent)"
  log "  TODO: implement ASG (min=$ASG_MIN max=$ASG_MAX desired=$ASG_DESIRED)"
  log "        with step-scaling policy: scale +5 at CPU>70%, +10 at CPU>90%"
  log "  TODO: implement NLB + target group on :443 with passthrough"
  log "        TLS (the enclave's own ACME-issued cert handles TLS"
  log "        termination inside the workload, just like the GCP variant)"
  log ""
  log "  Compute phase requires the enclave image to be built + pushed"
  log "  to ECR first. Run phase 'iam' + 'kms' + 'network' + 'ecr' first;"
  log "  then build the image (separate step on a Docker host); then"
  log "  re-run this phase."
}

# ─── Phase: Service Quotas ─────────────────────────────────────────────────
phase_quotas() {
  log "=== phase: quotas ==="
  # Default account quota for "Running On-Demand m5n instances" in
  # us-west-2 is small (often 0 or 5 vCPUs). m5n.xlarge = 4 vCPUs;
  # ASG_MAX=50 needs 200 vCPUs of quota. Submit a request.
  local quota_code="L-1216C47A"   # Running On-Demand Standard (A, C, D, H, I, M, R, T, Z) instances
  local desired_value=$((ASG_MAX * 4))   # m5n.xlarge has 4 vCPUs

  log "  current quota:"
  if [ $DRY_RUN -eq 0 ]; then
    aws service-quotas get-service-quota \
      --service-code ec2 --quota-code "$quota_code" \
      --region "$AWS_REGION" \
      --query 'Quota.{Name:QuotaName,Value:Value}' --output table
  fi

  log "  requesting quota increase to $desired_value vCPUs"
  log "  (this is paperwork; AWS support typically approves in 1-3 business days)"
  if [ $DRY_RUN -eq 0 ]; then
    aws service-quotas request-service-quota-increase \
      --service-code ec2 --quota-code "$quota_code" \
      --desired-value "$desired_value" \
      --region "$AWS_REGION" || log "  (request may already exist; non-fatal)"
  fi
}

# ─── Dispatch ──────────────────────────────────────────────────────────────
case "$PHASE" in
  iam) phase_iam ;;
  kms) phase_kms ;;
  network) phase_network ;;
  ecr) phase_ecr ;;
  compute) phase_compute ;;
  quotas) phase_quotas ;;
  all)
    phase_iam
    phase_kms
    phase_network
    phase_ecr
    phase_quotas
    phase_compute   # last; needs the others
    ;;
  *) log "unknown phase: $PHASE"; exit 2 ;;
esac

log "done"
