#!/usr/bin/env bash
# Teardown the AWS control-plane replica (RETIRED 2026-06-08).
#
# Why: the AWS Fargate control-plane was an internet-facing standby that was
# NOT in the production DNS (trustedrouter.com → GCP), ran a stale release, and
# held decrypt-only on the byok-envelope KMS key (couldn't register BYOK). It
# carried real attack surface (both 2026-06-08 prod 500s arrived via its public
# ALB) for zero production benefit. Resilience lives in the multi-cloud
# INFERENCE enclaves (GCP MIG + AWS Nitro), not a hot control-plane replica.
#
# This reverses tools/deploy-aws-control-plane.sh, in dependency order.
#
# PRESERVED (do NOT delete here):
#   * tr-aws-cross-cloud@ SA + its GCP IAM (Spanner/Bigtable/KMS-decrypt) — the
#     AWS *enclave* still uses it to unwrap BYOK keys at inference.
#   * Shared VPC / subnets.
#   * By default: ECR repo, IAM roles, CloudWatch log group, ACM cert
#     (re-creatable / hold history). Add --purge to remove those too.
#
# Usage:
#   bash tools/teardown-aws-control-plane.sh            # dry-run (default)
#   bash tools/teardown-aws-control-plane.sh --apply    # delete compute+network
#   bash tools/teardown-aws-control-plane.sh --apply --purge   # also IAM/ECR/logs
set -euo pipefail

AWS_REGION="${AWS_REGION:-us-west-2}"
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

DRY_RUN=1
PURGE=0
for arg in "$@"; do
  case "$arg" in
    --apply) DRY_RUN=0 ;;
    --purge) PURGE=1 ;;
    *) echo "unknown arg: $arg" >&2; exit 2 ;;
  esac
done

say() { echo "[teardown] $*"; }
aws_q() { aws "$@" --region "$AWS_REGION" 2>&1; }
# do <label> <command...> — run (or print in dry-run), tolerating not-found.
do_step() {
  local label="$1"; shift
  if [ "$DRY_RUN" = "1" ]; then
    say "[dry-run] would: $label"
    return 0
  fi
  say "$label"
  local out
  if out=$("$@" 2>&1); then
    [ -n "$out" ] && say "  ok: $(printf '%s' "$out" | head -1 | cut -c1-160)"
  else
    # Surface the REAL error (don't mask it as "already gone") — a genuine
    # NotFound is fine, but a permission / dependency error needs to be seen.
    say "  ⚠️ FAILED: $(printf '%s' "$out" | tail -1 | cut -c1-200)"
  fi
  # ALWAYS succeed: a successful command with EMPTY output (e.g. delete-listener)
  # would otherwise leave $? = 1 (from the `[ -n "$out" ]` test) and `set -e`
  # would kill the whole teardown mid-loop. do_step is best-effort by design.
  return 0
}

say "region=$AWS_REGION mode=$([ $DRY_RUN -eq 1 ] && echo DRY-RUN || echo APPLY) purge=$PURGE"

# ── 1. ECS service: drain to 0, then delete ────────────────────────────────
if aws_q ecs describe-services --cluster "$CLUSTER_NAME" --services "$SERVICE_NAME" \
     --query 'services[0].status' --output text 2>/dev/null | grep -qE 'ACTIVE|DRAINING'; then
  do_step "scale ECS service $SERVICE_NAME to 0" \
    aws ecs update-service --region "$AWS_REGION" --cluster "$CLUSTER_NAME" \
      --service "$SERVICE_NAME" --desired-count 0
  do_step "delete ECS service $SERVICE_NAME" \
    aws ecs delete-service --region "$AWS_REGION" --cluster "$CLUSTER_NAME" \
      --service "$SERVICE_NAME" --force
else
  say "ECS service $SERVICE_NAME not active — skip"
fi

# ── 2. ALB listeners + ALB (frees the SG ENIs) ─────────────────────────────
ALB_ARN=$(aws_q elbv2 describe-load-balancers --names "$ALB_NAME" \
  --query 'LoadBalancers[0].LoadBalancerArn' --output text 2>/dev/null | grep -v None || true)
if [ -n "${ALB_ARN:-}" ]; then
  for L_ARN in $(aws_q elbv2 describe-listeners --load-balancer-arn "$ALB_ARN" \
      --query 'Listeners[].ListenerArn' --output text 2>/dev/null); do
    do_step "delete ALB listener $L_ARN" \
      aws elbv2 delete-listener --region "$AWS_REGION" --listener-arn "$L_ARN"
  done
  do_step "delete ALB $ALB_NAME" \
    aws elbv2 delete-load-balancer --region "$AWS_REGION" --load-balancer-arn "$ALB_ARN"
  [ "$DRY_RUN" = "0" ] && { say "waiting for ALB to delete (frees SG ENIs)..."; \
    aws_q elbv2 wait load-balancers-deleted --load-balancer-arns "$ALB_ARN" || true; }
else
  say "ALB $ALB_NAME not found — skip"
fi

# ── 3. Target group ────────────────────────────────────────────────────────
TG_ARN=$(aws_q elbv2 describe-target-groups --names "$TG_NAME" \
  --query 'TargetGroups[0].TargetGroupArn' --output text 2>/dev/null | grep -v None || true)
[ -n "${TG_ARN:-}" ] && do_step "delete target group $TG_NAME" \
  aws elbv2 delete-target-group --region "$AWS_REGION" --target-group-arn "$TG_ARN" \
  || say "target group $TG_NAME not found — skip"

# ── 4. ECS cluster (dedicated to the control plane) ────────────────────────
do_step "delete ECS cluster $CLUSTER_NAME" \
  aws ecs delete-cluster --region "$AWS_REGION" --cluster "$CLUSTER_NAME"

# ── 5. Security groups (after the ALB's ENIs detach; retry) ────────────────
delete_sg() {
  local name="$1"
  local sg_id
  sg_id=$(aws_q ec2 describe-security-groups --filters "Name=group-name,Values=$name" \
    --query 'SecurityGroups[0].GroupId' --output text 2>/dev/null | grep -v None || true)
  [ -z "${sg_id:-}" ] && { say "SG $name not found — skip"; return 0; }
  if [ "$DRY_RUN" = "1" ]; then say "[dry-run] would delete SG $name ($sg_id)"; return 0; fi
  for attempt in 1 2 3 4 5 6; do
    if aws ec2 delete-security-group --region "$AWS_REGION" --group-id "$sg_id" 2>/dev/null; then
      say "deleted SG $name ($sg_id)"; return 0
    fi
    say "  SG $name still has dependencies (ENIs draining); retry $attempt/6 in 20s"; sleep 20
  done
  say "  WARN: could not delete SG $name ($sg_id) — delete manually once ENIs are gone"
}
delete_sg "$SG_TASK_NAME"
delete_sg "$SG_ALB_NAME"

# ── 6+. Optional purge: task defs, log group, IAM roles, ECR repo ──────────
if [ "$PURGE" = "1" ]; then
  for td in $(aws_q ecs list-task-definitions --family-prefix "$TASK_FAMILY" \
      --query 'taskDefinitionArns[]' --output text 2>/dev/null); do
    do_step "deregister task def $td" \
      aws ecs deregister-task-definition --region "$AWS_REGION" --task-definition "$td"
  done
  do_step "delete log group $LOG_GROUP" \
    aws logs delete-log-group --region "$AWS_REGION" --log-group-name "$LOG_GROUP"
  for role in "$ROLE_TASK_EXEC" "$ROLE_TASK"; do
    for pol in $(aws_q iam list-role-policies --role-name "$role" \
        --query 'PolicyNames[]' --output text 2>/dev/null); do
      do_step "delete inline policy $pol on $role" \
        aws iam delete-role-policy --role-name "$role" --policy-name "$pol"
    done
    # MANAGED policies must be DETACHED before the role can be deleted
    # (e.g. AmazonECSTaskExecutionRolePolicy on the task-exec role).
    for arn in $(aws_q iam list-attached-role-policies --role-name "$role" \
        --query 'AttachedPolicies[].PolicyArn' --output text 2>/dev/null); do
      do_step "detach managed policy $arn from $role" \
        aws iam detach-role-policy --role-name "$role" --policy-arn "$arn"
    done
    do_step "delete IAM role $role" aws iam delete-role --role-name "$role"
  done
  do_step "delete ECR repo $ECR_REPO (force)" \
    aws ecr delete-repository --region "$AWS_REGION" --repository-name "$ECR_REPO" --force
  say "NOTE: ACM cert left in place (cheap, DNS-validated) — delete manually if desired."
else
  say "kept (re-creatable / history): ECR repo, IAM roles, log group, ACM cert. Re-run with --purge to remove."
fi

say "PRESERVED: tr-aws-cross-cloud@ SA + GCP IAM (the AWS *enclave* needs decrypt at inference) and the shared VPC/subnets."
say "done. ($([ $DRY_RUN -eq 1 ] && echo 'dry-run — re-run with --apply' || echo 'applied'))"
