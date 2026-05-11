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
#   - service-quota request for m5.xlarge instance limit
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
#   iam        IAM role + policies + instance profile (for EC2 hosts)
#   oidc       GitHub Actions OIDC identity provider + deployer role
#   kms        KMS CMK for GCP-SA-key + BYOK envelope wrapping
#   network    VPC + subnets + security group
#   ecr        ECR repo for the enclave image
#   compute    Launch template + Auto Scaling Group + NLB + target group
#   quotas     Submit Service Quotas request for m5.xlarge
#   cross-cloud-key  Create GCP SA, mint a key, wrap with AWS KMS, store in
#                    AWS Secrets Manager. Re-running rotates the key.

set -euo pipefail

AWS_REGION="${AWS_REGION:-us-west-2}"
PROJECT_TAG="${PROJECT_TAG:-quill-enclave}"
ECR_REPO_NAME="${ECR_REPO_NAME:-quill-enclave}"
PARENT_ECR_REPO_NAME="${PARENT_ECR_REPO_NAME:-quill-parent}"
PARENT_PUMP_ECR_REPO_NAME="${PARENT_PUMP_ECR_REPO_NAME:-quill-parent-pump}"
# Nitro Enclaves require ≥2 vCPU for the enclave + ≥2 for the host, so
# *.xlarge (4 vCPU) is the practical floor; *.large (2 vCPU) can't run
# enclaves at all. Default is m5.xlarge — 4 vCPU + 16 GB at ~$138/mo,
# down from m5n.xlarge's ~$171/mo. The "n" variant gives 25 Gbps
# networking vs 10 Gbps; we don't need that for the LLM-proxy workload
# where the bottleneck is upstream provider RTT, not bandwidth.
# c6i.xlarge would shave another ~$16/mo but only has 8 GB RAM, which
# gets tight when the host runs parent Python + parent-pump Go +
# Docker + Nitro allocator after carving out 4 GB for the enclave.
INSTANCE_TYPE="${INSTANCE_TYPE:-m5.xlarge}"
ASG_MIN="${ASG_MIN:-0}"
ASG_MAX="${ASG_MAX:-50}"
# desired=0 lets the infra (launch template, ASG, NLB, target group)
# land WITHOUT spinning a real instance. Once the bootstrap script is
# observed working on a manually-launched test instance, bump to 1 for
# the steady-state warmup pattern (1% Cloudflare-LB trickle keeps the
# AWS path warmed under real traffic so its bugs surface in metrics
# rather than during an outage).
ASG_DESIRED="${ASG_DESIRED:-0}"

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
  #
  # The cross-cloud GCP SA key is wrapped with our CMK and then stored
  # in Secrets Manager. The bootstrap_server unwraps via direct
  # kms:Decrypt — NOT through Secrets Manager's auto-decrypt path.
  # IAM resource ARNs for KMS must reference the key by its UUID, not
  # by alias; resolve the CMK ID from the alias at apply time so the
  # policy stays scoped to the specific key rather than wildcarding
  # the whole region.
  local cmk_alias="alias/${PROJECT_TAG}-cmk"
  local cmk_arn
  cmk_arn=$(aws kms list-aliases --region "$AWS_REGION" \
    --query "Aliases[?AliasName=='${cmk_alias}'].TargetKeyId" \
    --output text 2>/dev/null || echo "")
  if [ -n "$cmk_arn" ] && [ "$cmk_arn" != "None" ]; then
    cmk_arn="arn:aws:kms:${AWS_REGION}:${AWS_ACCOUNT}:key/${cmk_arn}"
  else
    # CMK doesn't exist yet (first-time bootstrap, phase_kms hasn't
    # run). Fall back to a wildcard scoped to this account+region —
    # phase_kms creates exactly one CMK so this is bounded. The next
    # apply (after phase_kms lands) will tighten the resource to the
    # specific key.
    cmk_arn="arn:aws:kms:${AWS_REGION}:${AWS_ACCOUNT}:key/*"
    log "  WARN: ${cmk_alias} not yet provisioned; using wildcard for kms direct-decrypt"
  fi

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
      "Sid": "DecryptKMSViaSecretsManager",
      "Effect": "Allow",
      "Action": ["kms:Decrypt", "kms:DescribeKey"],
      "Resource": "arn:aws:kms:${AWS_REGION}:${AWS_ACCOUNT}:key/*",
      "Condition": {"StringEquals": {"kms:ViaService": "secretsmanager.${AWS_REGION}.amazonaws.com"}}
    },
    {
      "Sid": "DecryptCrossCloudSAKeyDirect",
      "Effect": "Allow",
      "Action": ["kms:Decrypt", "kms:DescribeKey"],
      "Resource": "${cmk_arn}"
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

  # Attach AmazonSSMManagedInstanceCore so SSM Session Manager + Run
  # Command work on the bootstrapped instances. Without this the SSM
  # agent (preinstalled on AL2023) can't register with the SSM
  # endpoint, and we can't tail /var/log/quill-bootstrap.log without
  # a key pair / EC2 Instance Connect dance. attach-role-policy is
  # idempotent; AWS no-ops if the policy is already attached.
  log "  attaching AmazonSSMManagedInstanceCore for SSM access"
  if [ $DRY_RUN -eq 0 ]; then
    aws iam attach-role-policy --role-name "$role_name" \
      --policy-arn arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore >/dev/null
  fi
}

# ─── Phase: OIDC (GitHub Actions deployer role) ────────────────────────────
# Lets .github/workflows/deploy-enclave-aws.yml authenticate to AWS via
# OIDC (no static keys checked into the repo / GHA secrets). Sets up:
#   1. The IAM OIDC identity provider for token.actions.githubusercontent.com
#   2. The role quill-enclave-github-deployer with a trust policy that
#      restricts AssumeRole to the Lore-Hex/quill-cloud-proxy repo on main.
#   3. An attached policy granting ECR push + ASG instance-refresh
#      (the workflow's only AWS responsibilities for now).
phase_oidc() {
  log "=== phase: oidc ==="
  local oidc_url="token.actions.githubusercontent.com"
  local oidc_provider_arn="arn:aws:iam::${AWS_ACCOUNT}:oidc-provider/${oidc_url}"
  local role_name="${PROJECT_TAG}-github-deployer"
  local repo_path="${GITHUB_REPO_PATH:-Lore-Hex/quill-cloud-proxy}"

  # 1. OIDC identity provider
  if aws iam get-open-id-connect-provider --open-id-connect-provider-arn "$oidc_provider_arn" \
       >/dev/null 2>&1; then
    log "  OIDC provider already exists"
  else
    log "  creating OIDC provider for $oidc_url"
    if [ $DRY_RUN -eq 0 ]; then
      # Thumbprint is GitHub's well-known cert thumbprint as of 2024.
      # If GitHub rotates, this needs updating; aws-actions/configure-aws-credentials
      # documents the current thumbprint.
      aws iam create-open-id-connect-provider \
        --url "https://${oidc_url}" \
        --client-id-list "sts.amazonaws.com" \
        --thumbprint-list "6938fd4d98bab03faadb97b34396831e3780aea1" \
                         "1c58a3a8518e8759bf075b76b750d4f2df264fcd"
    fi
  fi

  # 2. Role with GitHub-specific trust policy
  local trust_doc
  trust_doc=$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {"Federated": "${oidc_provider_arn}"},
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "${oidc_url}:aud": "sts.amazonaws.com"
        },
        "StringLike": {
          "${oidc_url}:sub": "repo:${repo_path}:ref:refs/heads/main"
        }
      }
    }
  ]
}
EOF
)

  # 3. Tight policy: only the operations the build+push workflow needs
  local policy_doc
  policy_doc=$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ECRPush",
      "Effect": "Allow",
      "Action": [
        "ecr:GetAuthorizationToken",
        "ecr:BatchCheckLayerAvailability",
        "ecr:BatchGetImage",
        "ecr:InitiateLayerUpload",
        "ecr:UploadLayerPart",
        "ecr:CompleteLayerUpload",
        "ecr:PutImage",
        "ecr:DescribeImages"
      ],
      "Resource": [
        "arn:aws:ecr:${AWS_REGION}:${AWS_ACCOUNT}:repository/${ECR_REPO_NAME}",
        "*"
      ]
    },
    {
      "Sid": "ASGRefresh",
      "Effect": "Allow",
      "Action": [
        "autoscaling:StartInstanceRefresh",
        "autoscaling:DescribeAutoScalingGroups",
        "autoscaling:DescribeInstanceRefreshes"
      ],
      "Resource": "*"
    }
  ]
}
EOF
)

  if aws iam get-role --role-name "$role_name" >/dev/null 2>&1; then
    log "  role $role_name already exists; refreshing trust + policy"
    if [ $DRY_RUN -eq 0 ]; then
      aws iam update-assume-role-policy --role-name "$role_name" \
        --policy-document "$trust_doc"
    fi
  else
    log "  creating role $role_name"
    if [ $DRY_RUN -eq 0 ]; then
      aws iam create-role --role-name "$role_name" \
        --assume-role-policy-document "$trust_doc" \
        --description "GitHub Actions deployer for the AWS Nitro enclave (OIDC-authenticated, restricted to ${repo_path}@main)"
    fi
  fi
  if [ $DRY_RUN -eq 0 ]; then
    aws iam put-role-policy --role-name "$role_name" \
      --policy-name "${PROJECT_TAG}-github-deployer-policy" \
      --policy-document "$policy_doc"
    log "  role ARN: arn:aws:iam::${AWS_ACCOUNT}:role/${role_name}"
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

  # NLB sends both health checks and (in instance-target mode with
  # preserve_client_ip=false) data-plane traffic FROM IPs in the VPC
  # CIDR. The TG health check probes :8443 (parent's FastAPI /health)
  # and the listener forwards :443 → :8444 (parent-pump's TCP→vsock
  # forwarder). Both ports have to be reachable from VPC CIDR or the
  # NLB sees the instance as unhealthy and drops it.
  #
  # We deliberately do NOT open these to 0.0.0.0/0 — the NLB is the
  # only thing that should ever speak to :8443/:8444 directly. Public
  # traffic terminates TLS inside the enclave via :443 → :8444 →
  # vsock, so opening :8444 publicly would skip TLS entirely.
  if [ -n "$sg_id" ] && [ "$sg_id" != "None" ] && [ $DRY_RUN -eq 0 ]; then
    local vpc_cidr
    vpc_cidr=$(aws ec2 describe-vpcs --region "$AWS_REGION" \
      --vpc-ids "$vpc_id" --query "Vpcs[0].CidrBlock" --output text)
    for port in 8443 8444; do
      if aws ec2 describe-security-groups --region "$AWS_REGION" \
           --group-ids "$sg_id" \
           --query "SecurityGroups[0].IpPermissions[?FromPort==\`$port\`].IpRanges[?CidrIp=='$vpc_cidr']" \
           --output text 2>/dev/null | grep -q "$vpc_cidr"; then
        log "  $sg_name already allows :$port from $vpc_cidr"
      else
        log "  authorizing :$port from $vpc_cidr (NLB health check + data plane)"
        aws ec2 authorize-security-group-ingress --region "$AWS_REGION" \
          --group-id "$sg_id" \
          --protocol tcp --port "$port" --cidr "$vpc_cidr" >/dev/null \
          || log "    (rule may already exist; non-fatal)"
      fi
    done
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

# ─── Phase: Compute (Launch Template + ASG + NLB + parent + enclave) ─────
phase_compute() {
  log "=== phase: compute ==="
  log "  prerequisites: ECR has the cloud_aws,llm_multi enclave image"
  log "  prerequisites: ECR has the parent image (parent/Dockerfile.parent)"
  log "  prerequisites: IAM role + KMS CMK + security group provisioned"
  log "  prerequisites: Service Quotas approved m5.xlarge to >= ASG_MAX"

  # Resolve everything we need from earlier phases. Each lookup fails
  # the run early if a prereq is missing — better than producing a
  # half-wired ASG.
  local enclave_repo_url="${AWS_ACCOUNT}.dkr.ecr.${AWS_REGION}.amazonaws.com/${ECR_REPO_NAME}"
  local parent_repo_url="${AWS_ACCOUNT}.dkr.ecr.${AWS_REGION}.amazonaws.com/${PARENT_ECR_REPO_NAME}"
  local enclave_tag parent_tag

  enclave_tag=$(aws ecr describe-images \
    --repository-name "$ECR_REPO_NAME" --region "$AWS_REGION" \
    --query "sort_by(imageDetails,&imagePushedAt)[-1].imageTags[0]" \
    --output text 2>/dev/null || echo "None")
  if [ "$enclave_tag" = "None" ] || [ -z "$enclave_tag" ]; then
    log "  ERROR: no enclave image found in ECR ${ECR_REPO_NAME}; build via deploy-enclave-aws.yml"
    return 1
  fi
  log "  enclave image: ${enclave_repo_url}:${enclave_tag}"

  parent_tag=$(aws ecr describe-images \
    --repository-name "$PARENT_ECR_REPO_NAME" --region "$AWS_REGION" \
    --query "sort_by(imageDetails,&imagePushedAt)[-1].imageTags[0]" \
    --output text 2>/dev/null || echo "None")
  if [ "$parent_tag" = "None" ] || [ -z "$parent_tag" ]; then
    log "  ERROR: no parent image found in ECR ${PARENT_ECR_REPO_NAME}; build via deploy-parent-aws.yml"
    return 1
  fi
  log "  parent image:  ${parent_repo_url}:${parent_tag}"

  # The parent-pump is the Go replacement for the Python TCP pump on
  # the data path. It runs as a separate small (~3.5 MB) container on
  # the host alongside the Python parent. The Python parent handles
  # /admin, /trust, /health, and the bootstrap RPC server (all off the
  # data path). The Go binary handles the TCP-to-vsock pump where
  # latency matters.
  local parent_pump_repo_url="${AWS_ACCOUNT}.dkr.ecr.${AWS_REGION}.amazonaws.com/${PARENT_PUMP_ECR_REPO_NAME}"
  local parent_pump_tag
  parent_pump_tag=$(aws ecr describe-images \
    --repository-name "$PARENT_PUMP_ECR_REPO_NAME" --region "$AWS_REGION" \
    --query "sort_by(imageDetails,&imagePushedAt)[-1].imageTags[0]" \
    --output text 2>/dev/null || echo "None")
  if [ "$parent_pump_tag" = "None" ] || [ -z "$parent_pump_tag" ]; then
    log "  ERROR: no parent-pump image in ECR ${PARENT_PUMP_ECR_REPO_NAME}; build via deploy-parent-pump-aws.yml"
    return 1
  fi
  log "  pump image:    ${parent_pump_repo_url}:${parent_pump_tag}"

  local sg_id
  sg_id=$(aws ec2 describe-security-groups --region "$AWS_REGION" \
    --filters "Name=group-name,Values=${PROJECT_TAG}-sg" \
    --query "SecurityGroups[0].GroupId" --output text 2>/dev/null)
  if [ -z "$sg_id" ] || [ "$sg_id" = "None" ]; then
    log "  ERROR: security group ${PROJECT_TAG}-sg not found; run phase network first"
    return 1
  fi

  local vpc_id subnet_ids
  vpc_id=$(aws ec2 describe-security-groups --region "$AWS_REGION" \
    --group-ids "$sg_id" --query "SecurityGroups[0].VpcId" --output text)
  subnet_ids=$(aws ec2 describe-subnets --region "$AWS_REGION" \
    --filters "Name=vpc-id,Values=${vpc_id}" \
    --query "Subnets[].SubnetId" --output text | tr '\t' ',')
  log "  VPC: $vpc_id  subnets: $subnet_ids"

  local instance_profile_name="${PROJECT_TAG}-instance-profile"
  if ! aws iam get-instance-profile --instance-profile-name "$instance_profile_name" \
       >/dev/null 2>&1; then
    log "  ERROR: instance profile $instance_profile_name not found; run phase iam first"
    return 1
  fi

  # Resolve a current Amazon Linux 2023 AMI for x86_64 in this region.
  # We use the SSM public parameter so the AMI ID stays current as AWS
  # publishes patches.
  local ami_id
  ami_id=$(aws ssm get-parameter \
    --name "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64" \
    --region "$AWS_REGION" --query "Parameter.Value" --output text)
  log "  AL2023 AMI: $ami_id"

  # Build the user-data script. This runs on every fresh EC2 boot.
  # The script:
  #   1. Installs Nitro Enclaves CLI + Docker
  #   2. Configures the enclave allocator (CPU + memory)
  #   3. Logs in to ECR
  #   4. Pulls + runs the parent container (FastAPI + TCP pump + bootstrap RPC)
  #   5. Pulls the enclave image, converts to .eif, runs the enclave
  #
  # The parent container is started with --network host so it can bind
  # 8443 (FastAPI) and 8444 (TCP pump) on the host's interfaces and reach
  # AF_VSOCK without a Docker bridge in the way.
  local user_data
  user_data=$(cat <<EOS
#!/bin/bash
set -euxo pipefail
exec > >(tee -a /var/log/quill-bootstrap.log) 2>&1

# 1. Nitro Enclaves CLI + Docker
dnf install -y aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel docker
usermod -aG ne ec2-user
usermod -aG docker ec2-user

# 2. Allocator: 2 vCPU + 4 GB for the enclave; rest stays with the host.
# m5.xlarge has 4 vCPU + 16 GiB so the host gets 2 vCPU + ~12 GiB.
sed -i 's/^cpu_count: .*/cpu_count: 2/' /etc/nitro_enclaves/allocator.yaml
sed -i 's/^memory_mib: .*/memory_mib: 4096/' /etc/nitro_enclaves/allocator.yaml

systemctl enable --now docker
systemctl enable --now nitro-enclaves-allocator.service

# 2b. vsock-proxy daemon — provides outbound network for the enclave.
# Nitro Enclaves have no NIC; every outbound HTTPS call from inside
# the enclave must travel via vsock to a parent-side proxy that does
# the real DNS+TCP. AWS ships `vsock-proxy` with aws-nitro-enclaves-cli
# (already installed above). It reads /etc/nitro_enclaves/vsock-proxy.yaml
# for the host allowlist; we need an entry per upstream the enclave
# dials.
#
# This list MUST stay in lockstep with awsProviderTunnels in
# enclave-go/internal/llm/http_client_aws.go. Adding a provider is
# a 2-line edit there + a 1-line yaml entry here. The enclave's
# vsockhttp.Transport fails closed for unlisted hosts, so a missing
# yaml entry surfaces as UnconfiguredHostError on the first request
# rather than a cryptic timeout.
cat > /etc/nitro_enclaves/vsock-proxy.yaml <<'YAML'
allowlist:
  # LLM provider direct-API endpoints (port assignments match
  # http_client_aws.go::awsProviderTunnels)
  - {address: api.anthropic.com,             port: 443}
  - {address: api.openai.com,                port: 443}
  - {address: api.cerebras.ai,               port: 443}
  - {address: api.deepseek.com,              port: 443}
  - {address: api.mistral.ai,                port: 443}
  - {address: api.moonshot.ai,               port: 443}
  - {address: generativelanguage.googleapis.com, port: 443}
  - {address: api.z.ai,                      port: 443}
  - {address: api.together.xyz,              port: 443}
  - {address: api.x.ai,                      port: 443}
  - {address: api.novita.ai,                 port: 443}
  - {address: api.red-pill.ai,               port: 443}
  - {address: api.siliconflow.com,           port: 443}
  - {address: inference.tinfoil.sh,          port: 443}
  - {address: api.venice.ai,                 port: 443}
  # GCP cross-cloud APIs — auth + Spanner + Bigtable + GCS (ACME cache)
  # + KMS (BYOK envelope-unwrap when an AWS-side request lands with a
  # customer-provided GCP-KMS-wrapped envelope).
  - {address: oauth2.googleapis.com,         port: 443}
  - {address: spanner.googleapis.com,        port: 443}
  - {address: bigtable.googleapis.com,       port: 443}
  - {address: bigtableadmin.googleapis.com,  port: 443}
  - {address: storage.googleapis.com,        port: 443}
  - {address: cloudkms.googleapis.com,       port: 443}
  # DNS-01 ACME fallback path. Cloudflare DNS API for TXT record
  # add/remove + Let's Encrypt ACME directories for the order flow.
  # Defense-in-depth: TLS-ALPN-01 via shared GCS cache is the primary,
  # DNS-01 is the fallback for sustained-outage edge cases.
  - {address: api.cloudflare.com,                 port: 443}
  - {address: acme-v02.api.letsencrypt.org,       port: 443}
  - {address: acme-staging-v02.api.letsencrypt.org, port: 443}
  # TR control plane (key lookup, settle, byok unwrap). Matches the
  # tunnel list in enclave-go/internal/trustedrouter/http_client_aws.go.
  - {address: trustedrouter.com,             port: 443}
YAML

# Start one vsock-proxy process per upstream port. Each listens on
# (CID 3, vsock_port) and forwards to (host, 443). We use a systemd
# template unit instance-per-port so each is independently restarted
# if it dies. Port assignments mirror awsProviderTunnels.
mkdir -p /etc/systemd/system

# Generate one static systemd unit per (port, host) pair so each is
# independently restartable. We avoid `@.service` template units
# because their ExecStart can't easily encode a per-instance
# upstream host without shell-parsing the instance name; static
# units keep the systemd journal output readable too.
write_vsock_unit() {
  local port="\$1"
  local host="\$2"
  local svc="quill-vsock-proxy-\${port}.service"
  cat > "/etc/systemd/system/\${svc}" <<UNIT
[Unit]
Description=Quill Nitro vsock-proxy: vsock CID-LOCAL:\${port} -> \${host}:443
After=nitro-enclaves-allocator.service network-online.target
Wants=nitro-enclaves-allocator.service network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/vsock-proxy \${port} \${host} 443 --config /etc/nitro_enclaves/vsock-proxy.yaml
Restart=on-failure
RestartSec=2
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
UNIT
  systemctl enable --now "\${svc}" || echo "  WARN: failed to start \${svc} (continuing)"
}

systemctl daemon-reload

# Pairs MUST match http_client_aws.go::awsProviderTunnels exactly.
# Adding a provider = 1 line here + 1 line in awsProviderTunnels.
write_vsock_unit 8003 api.anthropic.com
write_vsock_unit 8004 api.openai.com
write_vsock_unit 8005 api.cerebras.ai
write_vsock_unit 8006 api.deepseek.com
write_vsock_unit 8007 api.mistral.ai
write_vsock_unit 8008 api.moonshot.ai
write_vsock_unit 8009 generativelanguage.googleapis.com
write_vsock_unit 8010 api.z.ai
write_vsock_unit 8011 api.together.xyz
write_vsock_unit 8012 api.x.ai
write_vsock_unit 8013 api.novita.ai
write_vsock_unit 8014 api.red-pill.ai
write_vsock_unit 8015 api.siliconflow.com
write_vsock_unit 8016 inference.tinfoil.sh
write_vsock_unit 8017 api.venice.ai
write_vsock_unit 8030 oauth2.googleapis.com
write_vsock_unit 8031 spanner.googleapis.com
write_vsock_unit 8032 bigtable.googleapis.com
write_vsock_unit 8033 bigtableadmin.googleapis.com
write_vsock_unit 8034 storage.googleapis.com
write_vsock_unit 8035 cloudkms.googleapis.com
write_vsock_unit 8036 api.cloudflare.com
write_vsock_unit 8037 acme-v02.api.letsencrypt.org
write_vsock_unit 8038 acme-staging-v02.api.letsencrypt.org
# TR control plane (must match internal/trustedrouter/http_client_aws.go)
write_vsock_unit 8040 trustedrouter.com

systemctl daemon-reload

# 3. ECR login (uses the instance profile's IAM permissions)
aws ecr get-login-password --region ${AWS_REGION} \\
  | docker login --username AWS --password-stdin ${AWS_ACCOUNT}.dkr.ecr.${AWS_REGION}.amazonaws.com

# 4a. Parent container (Python) — FastAPI on :8443 (/health, /admin/usage,
# /trust) + bootstrap RPC server on vsock 9100. NOT the data-path pump.
#
# Env vars consumed by quill_parent.config.Settings (env_prefix=QUILL_):
#   QUILL_AWS_REGION             — Secrets Manager + KMS region (us-west-2)
#   QUILL_BOOTSTRAP_SERVER=true  — opt-in flag; off in dev/tests
#   QUILL_SECRET_PREFIX          — defaults to "quill/" (matches sync-secrets-to-aws.sh)
#   QUILL_GCP_SA_KMS_ALIAS       — wraps the cross-cloud SA key
#   QUILL_TR_CONTROL_PLANE_BASE_URL — empty here; only set when this
#                                    region serves control-plane callbacks
docker pull ${parent_repo_url}:${parent_tag}
docker run -d --restart=always --name=quill-parent \\
  --network=host \\
  --device=/dev/vsock \\
  --security-opt seccomp=unconfined \\
  -e QUILL_BOOTSTRAP_SERVER=true \\
  -e QUILL_AWS_REGION=${AWS_REGION} \\
  -e QUILL_SECRET_PREFIX=quill/ \\
  -e QUILL_GCP_SA_KMS_ALIAS=alias/${PROJECT_TAG}-cmk \\
  -e QUILL_TR_CONTROL_PLANE_BASE_URL=https://trustedrouter.com/v1 \\
  ${parent_repo_url}:${parent_tag}

# 4b. Parent-pump container (Go) — listens on TCP :8444 and forwards
# to the enclave's vsock listener (CID 16, port 8001). Replaces the
# Python tcp_relay.py on the data path: io.Copy between two net.Conns
# instead of asyncio buffer-copy + GIL overhead. Tiny scratch image.
docker pull ${parent_pump_repo_url}:${parent_pump_tag}
# --security-opt seccomp=unconfined is required for the Go vsock
# library: Docker's default seccomp profile rejects socket(AF_VSOCK)
# with EPERM in scratch-based images. (Python/glibc images get the
# same family allowed via libc internals, which is why the parent
# container — same default seccomp — binds vsock fine on the bootstrap
# server side.) Confirmed by stripping seccomp on a live instance:
# vsock.Dial then succeeded.
docker run -d --restart=always --name=quill-parent-pump \\
  --network=host \\
  --device=/dev/vsock \\
  --security-opt seccomp=unconfined \\
  -e QUILL_PUMP_LISTEN_ADDR=:8444 \\
  -e QUILL_PUMP_ENCLAVE_CID=16 \\
  -e QUILL_PUMP_ENCLAVE_PORT=8001 \\
  ${parent_pump_repo_url}:${parent_pump_tag}

# 5. Enclave image → .eif → run-enclave
#
# nitro-cli build-enclave fails with "[E51] Artifacts path environment
# variable not set" when run from cloud-init under root with no HOME-
# based config. Set NITRO_CLI_ARTIFACTS explicitly so the build can
# write its intermediate artifacts (typically a .img + manifest).
export NITRO_CLI_ARTIFACTS=/var/cache/nitro_enclaves
mkdir -p "\$NITRO_CLI_ARTIFACTS" /opt/quill
docker pull ${enclave_repo_url}:${enclave_tag}
nitro-cli build-enclave \\
  --docker-uri ${enclave_repo_url}:${enclave_tag} \\
  --output-file /opt/quill/enclave.eif

nitro-cli run-enclave \\
  --eif-path /opt/quill/enclave.eif \\
  --cpu-count 2 \\
  --memory 4096 \\
  --enclave-cid 16

# Liveness signal: the parent's /health endpoint exits 0 once the enclave
# vsock socket accepts a connect. The ASG health check polls 8443 on TCP.
EOS
)
  local user_data_b64
  user_data_b64=$(printf '%s' "$user_data" | base64)

  # Launch template
  local lt_name="${PROJECT_TAG}-lt"
  local existing_lt_id
  existing_lt_id=$(aws ec2 describe-launch-templates --region "$AWS_REGION" \
    --filters "Name=launch-template-name,Values=${lt_name}" \
    --query "LaunchTemplates[0].LaunchTemplateId" --output text 2>/dev/null)
  local lt_data
  lt_data=$(cat <<EOJ
{
  "ImageId": "${ami_id}",
  "InstanceType": "${INSTANCE_TYPE}",
  "EnclaveOptions": {"Enabled": true},
  "IamInstanceProfile": {"Name": "${instance_profile_name}"},
  "SecurityGroupIds": ["${sg_id}"],
  "MetadataOptions": {"HttpTokens": "required", "HttpEndpoint": "enabled"},
  "TagSpecifications": [{
    "ResourceType": "instance",
    "Tags": [
      {"Key": "Project", "Value": "${PROJECT_TAG}"},
      {"Key": "Name", "Value": "${PROJECT_TAG}"}
    ]
  }],
  "BlockDeviceMappings": [{
    "DeviceName": "/dev/xvda",
    "Ebs": {"VolumeSize": 30, "VolumeType": "gp3", "DeleteOnTermination": true}
  }],
  "UserData": "${user_data_b64}"
}
EOJ
)
  if [ -z "$existing_lt_id" ] || [ "$existing_lt_id" = "None" ]; then
    log "  creating launch template $lt_name"
    if [ $DRY_RUN -eq 0 ]; then
      aws ec2 create-launch-template --region "$AWS_REGION" \
        --launch-template-name "$lt_name" \
        --launch-template-data "$lt_data" \
        --tag-specifications "ResourceType=launch-template,Tags=[{Key=Project,Value=${PROJECT_TAG}}]" \
        >/dev/null
    fi
  else
    log "  launch template $lt_name already exists; creating new version"
    if [ $DRY_RUN -eq 0 ]; then
      aws ec2 create-launch-template-version --region "$AWS_REGION" \
        --launch-template-name "$lt_name" \
        --launch-template-data "$lt_data" \
        --source-version '$Latest' \
        >/dev/null
      aws ec2 modify-launch-template --region "$AWS_REGION" \
        --launch-template-name "$lt_name" \
        --default-version '$Latest' \
        >/dev/null
    fi
  fi

  # NLB
  local nlb_name="${PROJECT_TAG}-nlb"
  local nlb_arn
  nlb_arn=$(aws elbv2 describe-load-balancers --region "$AWS_REGION" \
    --names "$nlb_name" --query "LoadBalancers[0].LoadBalancerArn" \
    --output text 2>/dev/null || echo "")
  if [ -z "$nlb_arn" ] || [ "$nlb_arn" = "None" ]; then
    log "  creating NLB $nlb_name"
    if [ $DRY_RUN -eq 0 ]; then
      local subnets_args
      subnets_args=$(printf -- "--subnets %s" "$(echo "$subnet_ids" | tr ',' ' ')")
      # shellcheck disable=SC2086
      nlb_arn=$(aws elbv2 create-load-balancer --region "$AWS_REGION" \
        --name "$nlb_name" --type network --scheme internet-facing \
        $subnets_args \
        --tags Key=Project,Value="$PROJECT_TAG" \
        --query "LoadBalancers[0].LoadBalancerArn" --output text)
    fi
  else
    log "  NLB $nlb_name already exists ($nlb_arn)"
  fi

  # Target group on :8444 (parent's TCP pump). Health check on :8443
  # (parent's FastAPI /health) — distinct port for liveness vs the
  # ciphertext-only data path.
  local tg_name="${PROJECT_TAG}-tg"
  local tg_arn
  tg_arn=$(aws elbv2 describe-target-groups --region "$AWS_REGION" \
    --names "$tg_name" --query "TargetGroups[0].TargetGroupArn" \
    --output text 2>/dev/null || echo "")
  if [ -z "$tg_arn" ] || [ "$tg_arn" = "None" ]; then
    log "  creating target group $tg_name (port 8444, health-check 8443)"
    if [ $DRY_RUN -eq 0 ]; then
      tg_arn=$(aws elbv2 create-target-group --region "$AWS_REGION" \
        --name "$tg_name" \
        --protocol TCP --port 8444 \
        --vpc-id "$vpc_id" \
        --health-check-protocol HTTP \
        --health-check-port 8443 \
        --health-check-path "/health" \
        --health-check-interval-seconds 30 \
        --health-check-timeout-seconds 10 \
        --healthy-threshold-count 2 \
        --unhealthy-threshold-count 3 \
        --target-type instance \
        --tags Key=Project,Value="$PROJECT_TAG" \
        --query "TargetGroups[0].TargetGroupArn" --output text)
    fi
  else
    log "  target group $tg_name already exists ($tg_arn)"
  fi

  # Disable preserve_client_ip on the TG so the NLB rewrites the
  # source IP to its own private IP (in the VPC CIDR). With preserve
  # enabled (the NLB default for instance-target mode), data-plane
  # traffic arrives at the instance with the public client's IP as
  # the source — which the SG would only allow if we opened :8444
  # to 0.0.0.0/0, defeating the SG's purpose. With preserve disabled,
  # the SG's existing VPC-CIDR ingress rule is sufficient.
  #
  # Idempotent — modify-target-group-attributes upserts. The Reason
  # column on healthy targets stays empty either way.
  if [ -n "$tg_arn" ] && [ "$tg_arn" != "None" ] && [ $DRY_RUN -eq 0 ]; then
    aws elbv2 modify-target-group-attributes --region "$AWS_REGION" \
      --target-group-arn "$tg_arn" \
      --attributes Key=preserve_client_ip.enabled,Value=false >/dev/null
    log "  preserve_client_ip disabled (NLB rewrites source IP to VPC range)"
  fi

  # NLB listener :443 → target group port 8444 (TCP passthrough — TLS
  # terminates inside the enclave).
  if [ $DRY_RUN -eq 0 ] && [ -n "$nlb_arn" ] && [ -n "$tg_arn" ]; then
    local listener_arn
    listener_arn=$(aws elbv2 describe-listeners --region "$AWS_REGION" \
      --load-balancer-arn "$nlb_arn" \
      --query "Listeners[?Port==\`443\`].ListenerArn" --output text 2>/dev/null \
      | head -1)
    if [ -z "$listener_arn" ] || [ "$listener_arn" = "None" ]; then
      log "  creating NLB listener :443 → tg :8444"
      aws elbv2 create-listener --region "$AWS_REGION" \
        --load-balancer-arn "$nlb_arn" \
        --protocol TCP --port 443 \
        --default-actions "Type=forward,TargetGroupArn=${tg_arn}" \
        --tags Key=Project,Value="$PROJECT_TAG" >/dev/null
    else
      log "  NLB listener :443 already exists"
    fi
  fi

  # ASG. We launch with desired=ASG_DESIRED (default 1) so the AWS path
  # is continuously warmed by the 1% Cloudflare-LB trickle. Healthcheck
  # type ELB so unhealthy bootstraps get auto-replaced.
  local asg_name="${PROJECT_TAG}-asg"
  if aws autoscaling describe-auto-scaling-groups --region "$AWS_REGION" \
       --auto-scaling-group-names "$asg_name" \
       --query "AutoScalingGroups[0].AutoScalingGroupName" --output text 2>/dev/null \
       | grep -q "$asg_name"; then
    log "  ASG $asg_name already exists; updating to latest LT version"
    if [ $DRY_RUN -eq 0 ]; then
      aws autoscaling update-auto-scaling-group --region "$AWS_REGION" \
        --auto-scaling-group-name "$asg_name" \
        --launch-template "LaunchTemplateName=${lt_name},Version=\$Latest" \
        --min-size "$ASG_MIN" --max-size "$ASG_MAX" \
        --desired-capacity "$ASG_DESIRED" \
        --vpc-zone-identifier "$subnet_ids"
    fi
  else
    log "  creating ASG $asg_name (min=$ASG_MIN max=$ASG_MAX desired=$ASG_DESIRED)"
    if [ $DRY_RUN -eq 0 ]; then
      aws autoscaling create-auto-scaling-group --region "$AWS_REGION" \
        --auto-scaling-group-name "$asg_name" \
        --launch-template "LaunchTemplateName=${lt_name},Version=\$Latest" \
        --min-size "$ASG_MIN" --max-size "$ASG_MAX" \
        --desired-capacity "$ASG_DESIRED" \
        --vpc-zone-identifier "$subnet_ids" \
        --target-group-arns "$tg_arn" \
        --health-check-type ELB \
        --health-check-grace-period 300 \
        --tags "Key=Project,Value=${PROJECT_TAG},PropagateAtLaunch=true" \
               "Key=Name,Value=${PROJECT_TAG},PropagateAtLaunch=true"
    fi
  fi

  if [ $DRY_RUN -eq 0 ]; then
    local nlb_dns
    nlb_dns=$(aws elbv2 describe-load-balancers --region "$AWS_REGION" \
      --names "$nlb_name" --query "LoadBalancers[0].DNSName" --output text)
    log ""
    log "  Compute phase complete."
    log "  NLB DNS: $nlb_dns"
    log "  Point Cloudflare LB's AWS pool at this DNS (record stays raw IP via 'A,DNS-only')"
    log "  Watch ASG instance health: aws autoscaling describe-auto-scaling-groups"
    log "    --auto-scaling-group-names ${asg_name}"
  fi
}

# ─── Phase: Service Quotas ─────────────────────────────────────────────────
phase_quotas() {
  log "=== phase: quotas ==="
  # Default account quota for "Running On-Demand m5n instances" in
  # us-west-2 is small (often 0 or 5 vCPUs). m5.xlarge = 4 vCPUs;
  # ASG_MAX=50 needs 200 vCPUs of quota. Submit a request.
  local quota_code="L-1216C47A"   # Running On-Demand Standard (A, C, D, H, I, M, R, T, Z) instances
  local desired_value=$((ASG_MAX * 4))   # m5.xlarge has 4 vCPUs

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

# ─── Phase: cross-cloud-key (GCP SA → AWS KMS-wrapped → Secrets Manager) ─
phase_cross_cloud_key() {
  log "=== phase: cross-cloud-key ==="
  # The AWS-side enclave needs to talk to GCP Spanner + Bigtable + KMS +
  # Secret Manager (cross-cloud). It does that with a GCP service-account
  # JSON key, wrapped at rest by an AWS KMS CMK and stored in AWS Secrets
  # Manager. The Nitro enclave bootstrap unwraps the key inside the
  # measured enclave (KMS policy gates the decrypt on the enclave's
  # attestation document; setup of that policy happens on the enclave
  # side, not here).
  #
  # This phase is responsible for:
  #   1. GCP service account: tr-aws-cross-cloud@quill-cloud-proxy.iam.gserviceaccount.com
  #   2. Minimum IAM bindings (datastore.user for Spanner+Bigtable,
  #      cloudkms.cryptoKeyDecrypter on byok-envelope, secretmanager.secretAccessor
  #      on the trustedrouter-* secrets).
  #   3. Mint a fresh JSON key.
  #   4. Wrap with AWS KMS (alias/quill-enclave-cmk).
  #   5. Store in AWS Secrets Manager as quill/trustedrouter-aws-cross-cloud-sa-key.
  #   6. Wipe the local plaintext key file.
  #
  # Re-running this phase ROTATES the key: a new JSON key is minted, the
  # existing AWS secret is updated, and previous key versions are left
  # on the GCP SA for cleanup via a separate rotation policy.

  local gcp_project="${GCP_PROJECT:-quill-cloud-proxy}"
  local sa_email="tr-aws-cross-cloud@${gcp_project}.iam.gserviceaccount.com"
  local sa_id="tr-aws-cross-cloud"
  local kms_alias="alias/${PROJECT_TAG}-cmk"
  local aws_secret_name="quill/trustedrouter-aws-cross-cloud-sa-key"

  # Sanity check that gcloud is configured.
  if ! command -v gcloud >/dev/null 2>&1; then
    log "FATAL: gcloud CLI not installed. Need it to mint the SA key." >&2
    exit 1
  fi
  if ! gcloud auth list --format='value(account)' --filter='status:ACTIVE' >/dev/null 2>&1; then
    log "FATAL: gcloud not authenticated. Run 'gcloud auth login'." >&2
    exit 1
  fi

  # 1. Create the GCP service account if it doesn't exist.
  local sa_was_created=0
  if gcloud iam service-accounts describe "$sa_email" --project="$gcp_project" >/dev/null 2>&1; then
    log "  GCP SA $sa_email already exists"
  else
    log "  creating GCP SA $sa_email"
    if [ $DRY_RUN -eq 0 ]; then
      gcloud iam service-accounts create "$sa_id" \
        --project="$gcp_project" \
        --display-name="Quill AWS-side cross-cloud reader" \
        --description="Used by the AWS Nitro enclave to read GCP Spanner+Bigtable+KMS+Secrets cross-cloud. Key is wrapped by AWS KMS and stored in AWS Secrets Manager."
      sa_was_created=1
    fi
  fi

  # GCP IAM is eventually consistent — a freshly-created SA is visible to
  # the SA describe call immediately but takes 5-30s to be visible to
  # `projects.add-iam-policy-binding`. Poll until the SA shows up in the
  # project IAM context (or give up after 60s) before granting bindings.
  if [ $DRY_RUN -eq 0 ] && [ $sa_was_created -eq 1 ]; then
    log "  waiting for SA to propagate to project IAM (eventually-consistent)..."
    local waited=0
    until gcloud iam service-accounts get-iam-policy "$sa_email" \
            --project="$gcp_project" >/dev/null 2>&1; do
      sleep 3
      waited=$((waited + 3))
      if [ $waited -ge 60 ]; then
        log "  WARN: SA propagation took longer than 60s; proceeding anyway"
        break
      fi
    done
  fi

  # 2. IAM bindings. Each call is idempotent — gcloud add-iam-policy-binding
  #    no-ops if the binding already exists.
  log "  granting IAM bindings to $sa_email"
  for role in \
      roles/spanner.databaseUser \
      roles/bigtable.user \
      roles/secretmanager.secretAccessor; do
    if [ $DRY_RUN -eq 0 ]; then
      gcloud projects add-iam-policy-binding "$gcp_project" \
        --member="serviceAccount:${sa_email}" \
        --role="$role" \
        --condition=None \
        --quiet >/dev/null
      log "    + ${role}"
    else
      log "    [dry-run] would grant ${role}"
    fi
  done

  # KMS decrypt is granted on the specific BYOK envelope key, not project-wide.
  # The key was set up during the original GCP enclave provisioning and lives
  # in us-central1 (regional). The AWS enclave makes cross-region KMS calls
  # against this key from us-west-2 — KMS supports cross-region without
  # extra setup.
  local kms_keyring_loc="${BYOK_KMS_LOCATION:-us-central1}"
  local kms_keyring_name="${BYOK_KMS_KEYRING:-trusted-router}"
  local kms_key_name="${BYOK_KMS_KEY:-byok-envelope}"
  if [ $DRY_RUN -eq 0 ]; then
    if gcloud kms keys describe "$kms_key_name" \
         --keyring="$kms_keyring_name" --location="$kms_keyring_loc" \
         --project="$gcp_project" >/dev/null 2>&1; then
      gcloud kms keys add-iam-policy-binding "$kms_key_name" \
        --keyring="$kms_keyring_name" --location="$kms_keyring_loc" \
        --project="$gcp_project" \
        --member="serviceAccount:${sa_email}" \
        --role="roles/cloudkms.cryptoKeyDecrypter" \
        --quiet >/dev/null
      log "    + roles/cloudkms.cryptoKeyDecrypter on ${kms_keyring_loc}/${kms_keyring_name}/${kms_key_name}"
    else
      log "    WARN: BYOK envelope key not found at ${kms_keyring_loc}/${kms_keyring_name}/${kms_key_name} — skipping KMS binding"
    fi
  else
    log "    [dry-run] would grant cloudkms.cryptoKeyDecrypter on ${kms_keyring_loc}/${kms_keyring_name}/${kms_key_name}"
  fi

  # 3. Mint a JSON key and 4-5. wrap+store. We do this in a temp dir that
  # gets shredded on exit so the plaintext doesn't linger.
  local tmpdir
  tmpdir=$(mktemp -d)
  # shellcheck disable=SC2064
  trap "rm -rf '$tmpdir'" EXIT
  local plain_key="${tmpdir}/sa-key.json"
  local wrapped_key="${tmpdir}/sa-key.wrapped.b64"

  if [ $DRY_RUN -eq 1 ]; then
    log "  [dry-run] would mint a new JSON key for $sa_email"
    log "  [dry-run] would wrap it with AWS KMS $kms_alias"
    log "  [dry-run] would store wrapped blob in AWS Secrets Manager $aws_secret_name"
    return
  fi

  log "  minting fresh JSON key for $sa_email"
  gcloud iam service-accounts keys create "$plain_key" \
    --iam-account="$sa_email" \
    --project="$gcp_project" \
    --key-file-type=json >/dev/null

  log "  wrapping JSON key with AWS KMS $kms_alias"
  # Use --output text + base64-encoded ciphertext so the value is safe to
  # round-trip through Secrets Manager as a plain string. Decryption on the
  # enclave side base64-decodes and calls KMS Decrypt.
  aws kms encrypt \
    --key-id "$kms_alias" \
    --plaintext "fileb://${plain_key}" \
    --region "$AWS_REGION" \
    --output text \
    --query CiphertextBlob > "$wrapped_key"

  # 5. Create-or-update the AWS secret.
  if aws secretsmanager describe-secret --secret-id "$aws_secret_name" \
       --region "$AWS_REGION" >/dev/null 2>&1; then
    log "  updating existing AWS secret $aws_secret_name"
    aws secretsmanager put-secret-value \
      --secret-id "$aws_secret_name" \
      --secret-string "file://${wrapped_key}" \
      --region "$AWS_REGION" >/dev/null
  else
    log "  creating new AWS secret $aws_secret_name"
    aws secretsmanager create-secret \
      --name "$aws_secret_name" \
      --description "GCP service-account JSON key for ${sa_email}, wrapped by AWS KMS ${kms_alias}. The Nitro enclave unwraps inside the measured boundary." \
      --secret-string "file://${wrapped_key}" \
      --region "$AWS_REGION" \
      --tags 'Key=Source,Value=gcp-iam-sa-key' \
             "Key=GcpServiceAccount,Value=${sa_email}" \
             "Key=KmsCmkAlias,Value=${kms_alias}" >/dev/null
  fi

  # 6. Wipe plaintext (the temp dir auto-shreds via the EXIT trap, but
  #    overwrite first for paranoia).
  if command -v shred >/dev/null 2>&1; then
    shred -u "$plain_key" 2>/dev/null || rm -f "$plain_key"
  else
    rm -f "$plain_key"
  fi
  log "  cross-cloud-key phase complete; SA key wrapped + stored, plaintext shredded"
}

# ─── Dispatch ──────────────────────────────────────────────────────────────
case "$PHASE" in
  iam) phase_iam ;;
  oidc) phase_oidc ;;
  kms) phase_kms ;;
  network) phase_network ;;
  ecr) phase_ecr ;;
  compute) phase_compute ;;
  quotas) phase_quotas ;;
  cross-cloud-key) phase_cross_cloud_key ;;
  all)
    phase_iam
    phase_oidc
    phase_kms
    phase_network
    phase_ecr
    phase_quotas
    phase_cross_cloud_key  # depends on kms (CMK exists) + GCP project access
    phase_compute          # last; needs the others
    ;;
  *) log "unknown phase: $PHASE"; exit 2 ;;
esac

log "done"
