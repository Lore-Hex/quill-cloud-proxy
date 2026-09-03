#!/usr/bin/env bash
# Trim the AWS EU plane to the "two regions, one host each" shape (~$700-800/mo).
# Every phase is idempotent and checks its preconditions. Run one phase at a time:
#   bash aws-trim-to-800.sh <phase> [DRY_RUN=1]
# Phases (in the order they should run):
#   status            print the live state of everything this script touches
#   asg-ireland       quill-enclave-asg eu-west-1 desired 2 -> 1
#   asg-paris         quill-enclave-asg eu-west-3 desired 2 -> 1, subnets -> the 3 public ones, instance refresh
#   secrets-usw2      schedule deletion (7-day recovery) of the 93 standalone quill/* secrets in us-west-2
#   orphans-use1      us-east-1: NAT with 0 bytes/7d + its EIP + the Bedrock endpoint in an empty VPC
#   ses-pool          delete the MANAGED dedicated-IP pool no configuration set uses ($15/mo)
#   fargate-size      tr-cp-euw1 / tr-cp-euw3 task defs 1 vCPU/2 GB -> 0.5 vCPU/1 GB (the script default)
#   synthetic-fargate point the EventBridge API destination at the Fargate control plane, then watch it
#   apprunner-retire  delete tr-eu, tr-eu-standby, both VPC connectors, the eu-west-1 apprunner endpoint,
#                     the cp.fo failover records + health checks, the orphan tr-cp-tg
#   nat-paris         delete the two Paris NATs + EIPs (only after asg-paris refresh done AND apprunner gone)
#   drain-resize      tr-eu-clickhouse-1 m5.large -> t3.medium (stop/modify/start; private IP is kept)
set -euo pipefail
PHASE="${1:-status}"
DRY_RUN="${DRY_RUN:-0}"
ACCT=330422590279
run() { if [ "$DRY_RUN" = 1 ]; then echo "DRY: $*"; else echo "+ $*"; "$@"; fi; }
log() { printf '\n=== %s\n' "$*"; }

PARIS_PUBLIC_SUBNETS="subnet-06e58bd9bca166a94,subnet-0113faa4984c68f5d,subnet-0267452d36af54676"
PARIS_PRIVATE_SUBNETS="subnet-02c00be7f803c5ec9 subnet-02bf657680a20cc32"
PARIS_NATS="nat-06614416dccc023f1 nat-051784e31ad83f502"
PARIS_NAT_EIPS="eipalloc-0e246f8eaab27e746 eipalloc-0813c5d2b3f91ef49"
PARIS_PRIVATE_RTS="rtb-05f0437c1f4aa06b9 rtb-08bfb8c72acabeb3a"
USE1_NAT=nat-047001b20d4b84949; USE1_NAT_EIP=eipalloc-0e9268994a4470ae6; USE1_RT=rtb-0d7f804bbf04e5850; USE1_VPCE=vpce-037398e939d76818f
EUW1_APPRUNNER_VPCE=vpce-0e867579412a628b1
FO_ZONE=Z094735111ETLEH17Z120
HC_PARIS=7b382578-d576-4dfd-82dc-be4971db2fab; HC_IRELAND=af62c28d-3995-4b67-96d8-37830bc8c03f
DRAIN_INSTANCE=i-025ed1c1766f61290
TASKDEF_DIR="$(cd "$(dirname "$0")" && pwd)"

asg_desired() { aws autoscaling describe-auto-scaling-groups --region "$1" --auto-scaling-group-names quill-enclave-asg --query 'AutoScalingGroups[0].[DesiredCapacity,length(Instances),VPCZoneIdentifier]' --output text; }

case "$PHASE" in
status)
  for R in eu-west-1 eu-west-3; do log "ASG $R (desired, instances, subnets)"; asg_desired $R; aws ec2 describe-instances --region $R --filters Name=tag:Name,Values=quill-enclave Name=instance-state-name,Values=running --query 'Reservations[].Instances[].[InstanceId,SubnetId,PublicIpAddress]' --output text; done
  log "Paris instance refresh"; aws autoscaling describe-instance-refreshes --region eu-west-3 --auto-scaling-group-name quill-enclave-asg --max-records 1 --query 'InstanceRefreshes[0].[Status,PercentageComplete,StatusReason]' --output text 2>/dev/null || true
  log "Paris NATs"; aws ec2 describe-nat-gateways --region eu-west-3 --query 'NatGateways[].[NatGatewayId,State]' --output text
  log "us-east-1 NAT / endpoint"; aws ec2 describe-nat-gateways --region us-east-1 --query 'NatGateways[].[NatGatewayId,State]' --output text; aws ec2 describe-vpc-endpoints --region us-east-1 --query 'VpcEndpoints[].[VpcEndpointId,State]' --output text
  log "us-west-2 secrets"; aws secretsmanager list-secrets --region us-west-2 --max-items 300 --query 'length(SecretList)' --output text
  log "SES pools"; aws sesv2 list-dedicated-ip-pools --region us-east-1 --output text
  log "Fargate task sizes"; for R in eu-west-1 eu-west-3; do TD=$(aws ecs describe-services --region $R --cluster tr-cp --services tr-cp-${R/eu-west-/euw} --query 'services[0].taskDefinition' --output text); aws ecs describe-task-definition --region $R --task-definition $TD --query 'taskDefinition.[family,revision,cpu,memory]' --output text; done
  log "API destination"; aws events describe-api-destination --region eu-west-3 --name tr-eu-synthetic-run --query 'InvocationEndpoint' --output text
  log "App Runner"; for R in eu-west-1 eu-west-3; do aws apprunner list-services --region $R --query 'ServiceSummaryList[].[ServiceName,Status]' --output text; done
  log "drain host"; aws ec2 describe-instances --region eu-west-3 --instance-ids $DRAIN_INSTANCE --query 'Reservations[0].Instances[0].[InstanceType,State.Name,PrivateIpAddress]' --output text
  ;;

asg-ireland)
  log "eu-west-1 before"; asg_desired eu-west-1
  run aws autoscaling update-auto-scaling-group --region eu-west-1 --auto-scaling-group-name quill-enclave-asg --desired-capacity 1
  log "eu-west-1 after"; asg_desired eu-west-1
  ;;

asg-paris)
  log "eu-west-3 before"; asg_desired eu-west-3
  run aws autoscaling update-auto-scaling-group --region eu-west-3 --auto-scaling-group-name quill-enclave-asg --desired-capacity 1 --vpc-zone-identifier "$PARIS_PUBLIC_SUBNETS"
  log "instance refresh so the surviving host relaunches in a public subnet (replacement launched first)"
  run aws autoscaling start-instance-refresh --region eu-west-3 --auto-scaling-group-name quill-enclave-asg --preferences '{"MinHealthyPercentage":100,"MaxHealthyPercentage":200,"InstanceWarmup":300}'
  log "eu-west-3 after"; asg_desired eu-west-3
  ;;

secrets-usw2)
  names=$(aws secretsmanager list-secrets --region us-west-2 --max-items 300 --query 'SecretList[?PrimaryRegion==null && starts_with(Name,`quill/`)].Name' --output text | tr '\t' '\n')
  log "$(echo "$names" | grep -c .) standalone quill/* secrets in us-west-2 (7-day recovery window)"
  for n in $names; do run aws secretsmanager delete-secret --region us-west-2 --secret-id "$n" --recovery-window-in-days 7 --query 'DeletionDate' --output text; done
  ;;

orphans-use1)
  log "us-east-1: route -> NAT -> EIP -> Bedrock endpoint"
  run aws ec2 delete-route --region us-east-1 --route-table-id $USE1_RT --destination-cidr-block 0.0.0.0/0 || true
  run aws ec2 delete-nat-gateway --region us-east-1 --nat-gateway-id $USE1_NAT
  if [ "$DRY_RUN" != 1 ]; then for i in $(seq 1 30); do s=$(aws ec2 describe-nat-gateways --region us-east-1 --nat-gateway-ids $USE1_NAT --query 'NatGateways[0].State' --output text); echo "  nat state: $s"; [ "$s" = deleted ] && break; sleep 10; done; fi
  run aws ec2 release-address --region us-east-1 --allocation-id $USE1_NAT_EIP
  run aws ec2 delete-vpc-endpoints --region us-east-1 --vpc-endpoint-ids $USE1_VPCE
  ;;

ses-pool)
  used=$(for cs in $(aws sesv2 list-configuration-sets --region us-east-1 --query 'ConfigurationSets' --output text); do aws sesv2 get-configuration-set --region us-east-1 --configuration-set-name $cs --query 'DeliveryOptions.SendingPoolName' --output text; done | grep -vc None || true)
  log "configuration sets using a dedicated pool: $used (must be 0)"; [ "$used" = 0 ]
  run aws sesv2 delete-dedicated-ip-pool --region us-east-1 --pool-name defaultpool
  ;;

fargate-size)
  WORK="${TMPDIR:-/tmp}/aws-trim-taskdefs"; mkdir -p "$WORK"
  for R in eu-west-1 eu-west-3; do
    SVC=tr-cp-${R/eu-west-/euw}
    CUR=$(aws ecs describe-services --region $R --cluster tr-cp --services $SVC --query 'services[0].taskDefinition' --output text)
    aws ecs describe-task-definition --region $R --task-definition "$CUR" --query 'taskDefinition' --output json > "$WORK/taskdef-$R.json"
    log "$R $SVC: $(basename $CUR) is $(python3 -c "import json;d=json.load(open('$WORK/taskdef-$R.json'));print(d['cpu'],'/',d['memory'])") -> register 512 / 1024 (deploy-aws-control-plane.sh's own default; live tasks use 6.5% of 2 GB)"
    python3 - "$WORK/taskdef-$R.json" > "$WORK/taskdef-$R-new.json" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))
for k in ("taskDefinitionArn","revision","status","requiresAttributes","compatibilities","registeredAt","registeredBy","deregisteredAt"): d.pop(k,None)
d["cpu"]="512"; d["memory"]="1024"
print(json.dumps(d))
PY
    if [ "$DRY_RUN" = 1 ]; then echo "DRY: register-task-definition from $WORK/taskdef-$R-new.json, then update-service $SVC"; continue; fi
    NEW=$(aws ecs register-task-definition --region $R --cli-input-json "file://$WORK/taskdef-$R-new.json" --query 'taskDefinition.taskDefinitionArn' --output text); echo "  registered $(basename $NEW)"
    run aws ecs update-service --region $R --cluster tr-cp --service $SVC --task-definition "$NEW" --query 'service.[serviceName,taskDefinition]' --output text
    aws ecs wait services-stable --region $R --cluster tr-cp --services $SVC && echo "  $SVC stable on $(basename $NEW)"
  done
  ;;

synthetic-fargate)
  log "repoint tr-eu-synthetic-run -> Fargate control plane (via Global Accelerator)"
  run aws events update-api-destination --region eu-west-3 --name tr-eu-synthetic-run --invocation-endpoint https://aws.trustedrouter.com/internal/synthetic/run --query 'ApiDestinationArn' --output text
  [ "$DRY_RUN" = 1 ] && exit 0
  log "watching 4 minutes: Fargate access log for /internal/synthetic/run + EventBridge failures"
  sleep 240
  START=$(( ($(date +%s) - 300) * 1000 ))
  aws logs filter-log-events --region eu-west-3 --log-group-name /tr-cp/euw3 --start-time $START --filter-pattern '"synthetic/run"' --query 'events[].message' --output text | cut -c1-160 | tail -6
  END=$(date -u +%Y-%m-%dT%H:%M:%SZ); S5=$(date -u -v-5M +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '5 minutes ago' +%Y-%m-%dT%H:%M:%SZ)
  for M in Invocations FailedInvocations; do echo "$M(5m): $(aws cloudwatch get-metric-statistics --region eu-west-3 --namespace AWS/Events --metric-name $M --dimensions Name=RuleName,Value=tr-eu-synthetic-1min --start-time $S5 --end-time $END --period 300 --statistics Sum --output text --query 'Datapoints[0].Sum')"; done
  ;;

apprunner-retire)
  log "Route 53: cp.fo failover records + health checks"
  for rec in "paris-primary PRIMARY $HC_PARIS gchircrcif.eu-west-3.awsapprunner.com" "ireland-secondary SECONDARY $HC_IRELAND wypciuidrp.eu-west-1.awsapprunner.com"; do set -- $rec
    run aws route53 change-resource-record-sets --hosted-zone-id $FO_ZONE --change-batch "{\"Changes\":[{\"Action\":\"DELETE\",\"ResourceRecordSet\":{\"Name\":\"cp.fo.trustedrouter.com.\",\"Type\":\"CNAME\",\"SetIdentifier\":\"$1\",\"Failover\":\"$2\",\"HealthCheckId\":\"$3\",\"TTL\":60,\"ResourceRecords\":[{\"Value\":\"$4\"}]}}]}" --query 'ChangeInfo.Status' --output text || true
  done
  run aws route53 delete-health-check --health-check-id $HC_PARIS || true
  run aws route53 delete-health-check --health-check-id $HC_IRELAND || true
  log "VPC ingress connections (a service with an AVAILABLE one refuses to delete)"
  for R in eu-west-1 eu-west-3; do
    for VIC in $(aws apprunner list-vpc-ingress-connections --region $R --query 'VpcIngressConnectionSummaryList[].VpcIngressConnectionArn' --output text); do
      run aws apprunner delete-vpc-ingress-connection --region $R --vpc-ingress-connection-arn "$VIC" --query 'VpcIngressConnection.Status' --output text || true
      if [ "$DRY_RUN" != 1 ]; then for i in $(seq 1 30); do s=$(aws apprunner describe-vpc-ingress-connection --region $R --vpc-ingress-connection-arn "$VIC" --query 'VpcIngressConnection.Status' --output text 2>/dev/null || echo GONE); echo "  ingress status: $s"; case "$s" in DELETED|GONE) break;; esac; sleep 10; done; fi
    done
  done
  log "App Runner services"
  for R in eu-west-3 eu-west-1; do for ARN in $(aws apprunner list-services --region $R --query 'ServiceSummaryList[?Status!=`DELETED`].ServiceArn' --output text); do run aws apprunner delete-service --region $R --service-arn "$ARN" --query 'Service.Status' --output text || true; done; done
  if [ "$DRY_RUN" != 1 ]; then for i in $(seq 1 30); do n=0; for R in eu-west-1 eu-west-3; do n=$(( n + $(aws apprunner list-services --region $R --query 'length(ServiceSummaryList[?Status!=`DELETED`])' --output text) )); done; echo "  services not yet deleted (both regions): $n"; if [ "$n" = 0 ]; then break; fi; sleep 20; done; fi
  log "VPC connectors (both), eu-west-1 apprunner endpoint, orphan target group"
  for ARN in $(aws apprunner list-vpc-connectors --region eu-west-3 --query 'VpcConnectors[?Status==`ACTIVE`].VpcConnectorArn' --output text); do run aws apprunner delete-vpc-connector --region eu-west-3 --vpc-connector-arn "$ARN" --query 'VpcConnector.Status' --output text || true; done
  run aws ec2 delete-vpc-endpoints --region eu-west-1 --vpc-endpoint-ids $EUW1_APPRUNNER_VPCE
  TG=$(aws elbv2 describe-target-groups --region eu-west-1 --names tr-cp-tg --query 'TargetGroups[0].TargetGroupArn' --output text 2>/dev/null || true); [ -n "$TG" ] && [ "$TG" != None ] && run aws elbv2 delete-target-group --region eu-west-1 --target-group-arn "$TG"
  ;;

nat-paris)
  log "preconditions: no enclave host in a private subnet; no App Runner service left"
  inpriv=$(aws ec2 describe-instances --region eu-west-3 --filters Name=tag:Name,Values=quill-enclave Name=instance-state-name,Values=running,pending --query "length(Reservations[].Instances[?SubnetId=='subnet-02c00be7f803c5ec9' || SubnetId=='subnet-02bf657680a20cc32'][])" --output text)
  ar=$(aws apprunner list-services --region eu-west-3 --query 'length(ServiceSummaryList[?Status!=`DELETED`])' --output text)
  echo "  hosts in private subnets: $inpriv   app runner services: $ar"; [ "$inpriv" = 0 ] && [ "$ar" = 0 ]
  for rt in $PARIS_PRIVATE_RTS; do run aws ec2 delete-route --region eu-west-3 --route-table-id $rt --destination-cidr-block 0.0.0.0/0 || true; done
  for n in $PARIS_NATS; do run aws ec2 delete-nat-gateway --region eu-west-3 --nat-gateway-id $n; done
  if [ "$DRY_RUN" != 1 ]; then for i in $(seq 1 30); do s=$(aws ec2 describe-nat-gateways --region eu-west-3 --nat-gateway-ids $PARIS_NATS --query 'NatGateways[].State' --output text | tr '\t' ' '); echo "  nat states: $s"; [ "$s" = "deleted deleted" ] && break; sleep 10; done; fi
  for e in $PARIS_NAT_EIPS; do run aws ec2 release-address --region eu-west-3 --allocation-id $e; done
  ;;

drain-resize)
  log "tr-eu-clickhouse-1: stop -> t3.medium -> start (private IP 172.31.10.143 is kept; public IP will change, nothing references it)"
  run aws ec2 stop-instances --region eu-west-3 --instance-ids $DRAIN_INSTANCE --query 'StoppingInstances[0].CurrentState.Name' --output text
  [ "$DRY_RUN" != 1 ] && aws ec2 wait instance-stopped --region eu-west-3 --instance-ids $DRAIN_INSTANCE
  run aws ec2 modify-instance-attribute --region eu-west-3 --instance-id $DRAIN_INSTANCE --instance-type '{"Value":"t3.medium"}'
  run aws ec2 start-instances --region eu-west-3 --instance-ids $DRAIN_INSTANCE --query 'StartingInstances[0].CurrentState.Name' --output text
  [ "$DRY_RUN" != 1 ] && aws ec2 wait instance-running --region eu-west-3 --instance-ids $DRAIN_INSTANCE && sleep 45 && aws ec2 describe-instances --region eu-west-3 --instance-ids $DRAIN_INSTANCE --query 'Reservations[0].Instances[0].[InstanceType,PrivateIpAddress,State.Name]' --output text
  ;;
*) echo "unknown phase: $PHASE"; exit 2;;
esac
