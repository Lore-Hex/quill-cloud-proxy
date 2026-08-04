#!/usr/bin/env bash
# Private subnets + per-AZ NAT so an App Runner service can reach a
# VPC-private ClickHouse WITHOUT losing its internet egress.
#
# Why this exists at all:
#
#   App Runner egress is all-or-nothing. Switch a service to VPC egress and
#   EVERY outbound call leaves through the connector's ENIs -- not just the
#   ClickHouse ones. Those ENIs get no public IP, so an internet-gateway
#   route does NOT give them internet: IGW only translates for addresses
#   that are public to begin with. Attaching a connector on the default
#   (public) subnets therefore looks correct, provisions cleanly, and
#   silently severs the control plane's calls to the attested gateway and
#   the home plane. NAT is what actually carries that traffic.
#
# Why TWO NAT gateways:
#
#   Moving tr-eu to VPC egress makes NAT the path for all of its outbound
#   traffic, so NAT inherits the control plane's availability target -- it
#   is no longer just the analytics path. A NAT gateway is redundant WITHIN
#   its AZ but dies WITH its AZ. One shared gateway would mean a single AZ
#   failure takes out egress from both subnets, i.e. a brand-new
#   single-AZ dependency in front of a service we are trying to make
#   four-nines. One NAT per AZ, each private subnet routed to the gateway
#   in its OWN AZ, keeps an AZ failure confined to that AZ.
#
#   That costs roughly $33/month per gateway plus data. It buys removing a
#   region-wide egress SPOF, which is the whole point of the second region.
#
# Idempotent: every step looks for an existing resource first.
set -euo pipefail

REGION="${REGION:-eu-west-3}"
VPC_ID="${VPC_ID:-vpc-05b829b9cae6a9cd8}"
# az:public-subnet:new-private-cidr
PAIRS="${PAIRS:-eu-west-3a:subnet-06e58bd9bca166a94:172.31.48.0/20 eu-west-3b:subnet-0113faa4984c68f5d:172.31.64.0/20}"
CONNECTOR_NAME="${CONNECTOR_NAME:-tr-eu-vpc-private}"
SG_NAME="${SG_NAME:-tr-eu-clickhouse-sg}"

log(){ printf '\n=== %s\n' "$*" >&2; }

SG_ID="$(aws ec2 describe-security-groups --region "$REGION" \
  --filters "Name=group-name,Values=$SG_NAME" "Name=vpc-id,Values=$VPC_ID" \
  --query 'SecurityGroups[0].GroupId' --output text)"
log "security group: $SG_ID"

PRIVATE_SUBNETS=""
for pair in $PAIRS; do
  AZ="${pair%%:*}"; rest="${pair#*:}"
  PUB_SUBNET="${rest%%:*}"; CIDR="${rest#*:}"
  NAME="tr-eu-private-${AZ}"

  # --- private subnet -------------------------------------------------
  SUBNET_ID="$(aws ec2 describe-subnets --region "$REGION" \
    --filters "Name=tag:Name,Values=$NAME" "Name=vpc-id,Values=$VPC_ID" \
    --query 'Subnets[0].SubnetId' --output text 2>/dev/null || true)"
  if [ -z "$SUBNET_ID" ] || [ "$SUBNET_ID" = "None" ]; then
    log "creating private subnet $NAME ($CIDR in $AZ)"
    SUBNET_ID="$(aws ec2 create-subnet --region "$REGION" --vpc-id "$VPC_ID" \
      --cidr-block "$CIDR" --availability-zone "$AZ" \
      --tag-specifications "ResourceType=subnet,Tags=[{Key=Name,Value=$NAME}]" \
      --query 'Subnet.SubnetId' --output text)"
  fi
  log "private subnet $AZ: $SUBNET_ID"

  # --- NAT gateway in the PUBLIC subnet of the SAME AZ ----------------
  NAT_ID="$(aws ec2 describe-nat-gateways --region "$REGION" \
    --filter "Name=subnet-id,Values=$PUB_SUBNET" "Name=state,Values=available,pending" \
    --query 'NatGateways[0].NatGatewayId' --output text 2>/dev/null || true)"
  if [ -z "$NAT_ID" ] || [ "$NAT_ID" = "None" ]; then
    log "allocating EIP + NAT gateway in $AZ"
    EIP="$(aws ec2 allocate-address --region "$REGION" --domain vpc \
      --tag-specifications "ResourceType=elastic-ip,Tags=[{Key=Name,Value=tr-eu-nat-$AZ}]" \
      --query AllocationId --output text)"
    NAT_ID="$(aws ec2 create-nat-gateway --region "$REGION" \
      --subnet-id "$PUB_SUBNET" --allocation-id "$EIP" \
      --tag-specifications "ResourceType=natgateway,Tags=[{Key=Name,Value=tr-eu-nat-$AZ}]" \
      --query 'NatGateway.NatGatewayId' --output text)"
  fi
  log "NAT $AZ: $NAT_ID (waiting for available)"
  aws ec2 wait nat-gateway-available --region "$REGION" --nat-gateway-ids "$NAT_ID"

  # --- route table: this private subnet -> the NAT in its OWN AZ ------
  RT_NAME="tr-eu-private-rt-${AZ}"
  RT_ID="$(aws ec2 describe-route-tables --region "$REGION" \
    --filters "Name=tag:Name,Values=$RT_NAME" "Name=vpc-id,Values=$VPC_ID" \
    --query 'RouteTables[0].RouteTableId' --output text 2>/dev/null || true)"
  if [ -z "$RT_ID" ] || [ "$RT_ID" = "None" ]; then
    RT_ID="$(aws ec2 create-route-table --region "$REGION" --vpc-id "$VPC_ID" \
      --tag-specifications "ResourceType=route-table,Tags=[{Key=Name,Value=$RT_NAME}]" \
      --query 'RouteTable.RouteTableId' --output text)"
  fi
  aws ec2 create-route --region "$REGION" --route-table-id "$RT_ID" \
    --destination-cidr-block 0.0.0.0/0 --nat-gateway-id "$NAT_ID" >/dev/null 2>&1 || \
  aws ec2 replace-route --region "$REGION" --route-table-id "$RT_ID" \
    --destination-cidr-block 0.0.0.0/0 --nat-gateway-id "$NAT_ID" >/dev/null
  aws ec2 associate-route-table --region "$REGION" \
    --route-table-id "$RT_ID" --subnet-id "$SUBNET_ID" >/dev/null 2>&1 || true
  log "route table $RT_ID: $SUBNET_ID -> $NAT_ID"

  PRIVATE_SUBNETS="${PRIVATE_SUBNETS}${SUBNET_ID} "
done

# --- App Runner connector on the PRIVATE subnets ------------------------
# A connector's subnets are immutable, so this is a NEW connector rather
# than an edit of the public-subnet one the ClickHouse script created.
CONNECTOR_ARN="$(aws apprunner list-vpc-connectors --region "$REGION" \
  --query "VpcConnectors[?VpcConnectorName=='$CONNECTOR_NAME' && Status=='ACTIVE'].VpcConnectorArn | [0]" \
  --output text 2>/dev/null || true)"
if [ -z "$CONNECTOR_ARN" ] || [ "$CONNECTOR_ARN" = "None" ]; then
  log "creating VPC connector $CONNECTOR_NAME on private subnets"
  # shellcheck disable=SC2086
  CONNECTOR_ARN="$(aws apprunner create-vpc-connector --region "$REGION" \
    --vpc-connector-name "$CONNECTOR_NAME" \
    --subnets $PRIVATE_SUBNETS --security-groups "$SG_ID" \
    --query 'VpcConnector.VpcConnectorArn' --output text)"
fi

echo
echo "PRIVATE_SUBNETS=${PRIVATE_SUBNETS}"
echo "VPC_CONNECTOR_ARN=${CONNECTOR_ARN}"
echo
echo "Before switching tr-eu to VPC egress, prove the NAT path works."
echo "Losing control-plane internet is the failure this guards against, and"
echo "it is invisible until a request needs the gateway or the home plane."
