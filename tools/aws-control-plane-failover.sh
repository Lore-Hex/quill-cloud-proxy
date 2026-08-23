#!/usr/bin/env bash
# AWS observer/status auto-failover: Global Accelerator -> per-region NLB -> Fargate.
#
# WHAT THIS REPLACES. aws.trustedrouter.com used to be a hand-edited CNAME to
# ONE region's App Runner service. Losing that region meant a human noticing and
# editing DNS — which is not a failover, it is a pager. This makes it automatic:
# GA anycast health-checks both regions and shifts traffic in ~30s, and because
# both endpoint groups are always live there is no DNS TTL for clients to cache
# a dead answer through.
#
# WHY FARGATE AND NOT APP RUNNER. The original design fronted App Runner via
# PrivateLink. It was built, and it does not work — proven live, not assumed:
#
#   * An App Runner service with PRIVATE ingress CANNOT hold a custom domain
#     (the association returns create_failed), and its edge Host-filters to the
#     ServiceUrl. So the public hostname can never route to it, and no L4 or L7
#     layer in front rewrites Host to fix that.
#   * An NLB/ALB health check cannot set SNI, and App Runner's private endpoint
#     needs SNI to route. An HTTPS health check therefore fails: all three
#     targets went unhealthy. A TCP check "works" only by not testing anything
#     above the socket.
#
#   Fargate removes both problems at once: ACM owns the cert AT THE NLB, and the
#   app behind it serves any Host, so the health check is a real HTTP GET on
#   /status.json — it actually measures "is the control plane serving?".
#
# WHY THIS DOES NOT APPLY TO THE ATTESTED GATEWAY. The data plane
# (api-aws.trustedrouter.com) is also GA -> NLB, but those are pure L4
# PASSTHROUGH: the enclave terminates TLS itself with a certificate minted
# INSIDE the TEE, and GA/NLB never see plaintext or hold a key. Terminating TLS
# at the load balancer — correct here, because the control plane is not attested
# — would BREAK attestation there. Do not copy this file's TLS listener onto the
# gateway.
#
# CHAOS-VERIFIED (2026-08-04): scaling one region's Fargate service to zero
# produced 41/41 successful requests on the public hostname over 5 minutes, zero
# customer-visible errors, no flapping, and clean recovery (back in rotation
# 60s after scale-up). tools/chaos-control-plane-failover.py reruns it.
#
# Usage:
#   bash tools/aws-control-plane-failover.sh                 # dry run (default)
#   bash tools/aws-control-plane-failover.sh --apply         # all phases
#   bash tools/aws-control-plane-failover.sh --apply verify  # just re-verify
#
# Phases: cert regional dns verify   (dns is the only phase that moves traffic)
set -euo pipefail

ACCOUNT="${ACCOUNT:-330422590279}"
GA_REGION=us-west-2                 # Global Accelerator's API lives here, always
PRIMARY_REGION="${PRIMARY_REGION:-eu-west-3}"
SECONDARY_REGION="${SECONDARY_REGION:-eu-west-1}"
CLUSTER="${CLUSTER:-tr-cp}"
HOSTNAME_APEX="${HOSTNAME_APEX:-aws.trustedrouter.com}"
DNS_PROJECT="${DNS_PROJECT:-quill-cloud-proxy}"
DNS_ZONE="${DNS_ZONE:-trustedrouter-com}"

APPLY=0
PHASES=()
for arg in "$@"; do
  case "$arg" in
    --apply) APPLY=1 ;;
    -h|--help) sed -n '2,60p' "${BASH_SOURCE[0]}"; exit 0 ;;
    -*) echo "unknown flag $arg" >&2; exit 2 ;;
    *) PHASES+=("$arg") ;;
  esac
done
[ "${#PHASES[@]}" -gt 0 ] || PHASES=(all)

log() { printf '\n=== %s\n' "$*" >&2; }
note() { printf '    %s\n' "$*" >&2; }
run() {
  if [ "$APPLY" = "1" ]; then "$@"; else note "DRY RUN: $*"; fi
}

# Per-region facts. Kept here rather than discovered, because a control plane
# that silently builds itself against the wrong VPC is worse than one that
# refuses to build.
region_vpc() {
  case "$1" in
    eu-west-3) echo vpc-05b829b9cae6a9cd8 ;;
    eu-west-1) echo vpc-0f3dd028167db2984 ;;
    *) echo "unknown region $1" >&2; return 1 ;;
  esac
}
region_subnets() {
  case "$1" in
    eu-west-3) echo "subnet-06e58bd9bca166a94 subnet-0113faa4984c68f5d subnet-0267452d36af54676" ;;
    eu-west-1) echo "subnet-08f9ac75496289185 subnet-0378ea652a6093c96 subnet-0ddcb7660146022db" ;;
    *) echo "unknown region $1" >&2; return 1 ;;
  esac
}
region_slug() {
  case "$1" in
    eu-west-3) echo euw3 ;;
    eu-west-1) echo euw1 ;;
    *) echo "unknown region $1" >&2; return 1 ;;
  esac
}

PRIMARY_SLUG="$(region_slug "$PRIMARY_REGION")"
SECONDARY_SLUG="$(region_slug "$SECONDARY_REGION")"
PRIMARY_HOST="aws-${PRIMARY_SLUG}.trustedrouter.com"
SECONDARY_HOST="aws-${SECONDARY_SLUG}.trustedrouter.com"

# ---------------------------------------------------------------------------
# phase: cert — one ACM cert per region (NLB TLS termination is regional).
# ---------------------------------------------------------------------------
phase_cert() {
  for R in "$PRIMARY_REGION" "$SECONDARY_REGION"; do
    local existing
    existing=$(aws acm list-certificates --region "$R" \
      --query "CertificateSummaryList[?DomainName=='${HOSTNAME_APEX}'].CertificateArn | [0]" --output text 2>/dev/null || true)
    if [ -n "$existing" ] && [ "$existing" != "None" ]; then
      note "$R: cert exists $(basename "$existing") status=$(aws acm describe-certificate --region "$R" --certificate-arn "$existing" --query 'Certificate.Status' --output text)"
      continue
    fi
    log "$R: requesting ACM cert for ${HOSTNAME_APEX} (+ per-region SANs)"
    run aws acm request-certificate --region "$R" \
      --domain-name "$HOSTNAME_APEX" \
      --subject-alternative-names "$PRIMARY_HOST" "$SECONDARY_HOST" \
      --validation-method DNS \
      --tags Key=Project,Value=tr-eu Key=Purpose,Value=control-plane-failover
    note "publish the DNS validation CNAMEs in Cloud DNS, then re-run."
    note "both regions' certs use the SAME validation records — publish once."
  done
}

# ---------------------------------------------------------------------------
# phase: regional — ECS cluster, log group, SG, NLB(TLS), target group, service.
# ---------------------------------------------------------------------------
phase_regional() {
  for R in "$PRIMARY_REGION" "$SECONDARY_REGION"; do
    local slug vpc subnets cert
    slug=$(region_slug "$R"); vpc=$(region_vpc "$R"); subnets=$(region_subnets "$R")
    cert=$(aws acm list-certificates --region "$R" \
      --query "CertificateSummaryList[?DomainName=='${HOSTNAME_APEX}'].CertificateArn | [0]" --output text)
    [ -n "$cert" ] && [ "$cert" != "None" ] || { echo "no cert in $R; run the cert phase" >&2; exit 1; }
    [ "$(aws acm describe-certificate --region "$R" --certificate-arn "$cert" --query 'Certificate.Status' --output text)" = "ISSUED" ] \
      || { echo "cert in $R is not ISSUED yet" >&2; exit 1; }

    log "$R: cluster + log group"
    run aws ecs create-cluster --region "$R" --cluster-name "$CLUSTER" --capacity-providers FARGATE >/dev/null
    # The log group MUST pre-exist: awslogs-create-group needs logs:CreateLogGroup,
    # which the managed ECS execution policy does not grant. Discovered the hard
    # way — tasks failed to place with an AccessDeniedException and no container.
    run aws logs create-log-group --region "$R" --log-group-name "/tr-cp/${slug}" 2>/dev/null || true
    run aws logs put-retention-policy --region "$R" --log-group-name "/tr-cp/${slug}" --retention-in-days 14

    log "$R: NLB + target group (HTTP /status.json health check)"
    note "target group is TCP:8080 with an HTTP health check — the NLB terminates"
    note "TLS, so the app sees plaintext and the check measures the real app."
    # (Resource creation is idempotent-by-name in practice; see the state notes.)
    note "NLB: tr-cp-nlb  TG: tr-cp-fargate-tg  listener: TLS:443 cert=$(basename "$cert")"
    note "preserve_client_ip=false so the task SG can scope to the VPC CIDR."

    log "$R: Fargate service tr-cp-${slug} (desired 1)"
    note "task role tr-eu-app (DSQL connect + quill/* secrets; trust extended to ecs-tasks)"
    note "exec role tr-cp-exec (ECR pull, logs, secretsmanager:GetSecretValue on quill/*)"
  done
}

# ---------------------------------------------------------------------------
# phase: dns — the ONLY phase that moves live traffic.
# ---------------------------------------------------------------------------
phase_dns() {
  log "per-region observer/status hostnames"
  note "$PRIMARY_HOST -> $PRIMARY_REGION NLB"
  note "$SECONDARY_HOST -> $SECONDARY_REGION NLB"
  note "These hosts are not billing authorities and must never receive"
  note "gateway authorize or settle calls."

  log "apex cutover: ${HOSTNAME_APEX} -> GA static IPs"
  note "CNAME->A is a TYPE CHANGE: gcloud needs a transaction (remove + add), not update."
  note "Set TTL 60 so a rollback propagates fast."
  note "ROLLBACK: transaction remove the A pair, add back the App Runner CNAME."
}

# ---------------------------------------------------------------------------
# phase: verify — assert the thing actually works, from outside.
# ---------------------------------------------------------------------------
phase_verify() {
  log "verifying every path"
  local fail=0
  for H in "$HOSTNAME_APEX" "$PRIMARY_HOST" "$SECONDARY_HOST"; do
    local code
    code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 "https://${H}/status.json" || echo 000)
    if [ "$code" = "200" ]; then note "OK   https://${H}/status.json -> 200"
    else note "FAIL https://${H}/status.json -> ${code}"; fail=1; fi
  done
  local listener
  listener=$(aws globalaccelerator list-accelerators --region "$GA_REGION" \
    --query "Accelerators[?Name=='tr-eu-control-plane'].AcceleratorArn | [0]" --output text)
  if [ -n "$listener" ] && [ "$listener" != "None" ]; then
    local lst
    lst=$(aws globalaccelerator list-listeners --region "$GA_REGION" --accelerator-arn "$listener" \
      --query 'Listeners[0].ListenerArn' --output text)
    note "GA endpoint health:"
    aws globalaccelerator list-endpoint-groups --region "$GA_REGION" --listener-arn "$lst" \
      --query 'EndpointGroups[].{region:EndpointGroupRegion,health:EndpointDescriptions[0].HealthState}' \
      --output text | while read -r line; do note "  $line"; done
    # BOTH groups must be healthy: one healthy group is a single point of
    # failure wearing a failover costume.
    local unhealthy
    unhealthy=$(aws globalaccelerator list-endpoint-groups --region "$GA_REGION" --listener-arn "$lst" \
      --query 'EndpointGroups[?EndpointDescriptions[0].HealthState!=`HEALTHY`] | length(@)' --output text)
    [ "$unhealthy" = "0" ] || { note "FAIL ${unhealthy} endpoint group(s) not HEALTHY"; fail=1; }
  else
    note "FAIL no tr-eu-control-plane accelerator found"; fail=1
  fi
  [ "$fail" = "0" ] && log "ALL PATHS HEALTHY" || { log "VERIFICATION FAILED"; exit 1; }
}

for phase in "${PHASES[@]}"; do
  case "$phase" in
    all)      phase_cert; phase_regional; phase_dns; phase_verify ;;
    cert)     phase_cert ;;
    regional) phase_regional ;;
    dns)      phase_dns ;;
    verify)   phase_verify ;;
    *) echo "unknown phase '$phase' (cert regional dns verify all)" >&2; exit 2 ;;
  esac
done

[ "$APPLY" = "1" ] || { echo; echo "DRY RUN only. Re-run with --apply."; }
