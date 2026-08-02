#!/usr/bin/env bash
# Replicate the enclave's provider secrets from the primary AWS region to a
# new one, so a second region can boot enclaves that actually serve traffic.
#
# REPLICATION, not copy. A copy is a snapshot that drifts: rotate an upstream
# provider key in the primary region and the second region keeps presenting
# the revoked one until somebody remembers to re-copy. Secrets Manager
# replicas track the source, so a rotation propagates on its own. The replica
# is read-only in the target region, which is all an enclave host needs.
#
# Every secret here uses the AWS-managed KMS key, so there is no customer CMK
# envelope to re-wrap. If that ever changes, a replicated secret encrypted
# under a region-local CMK will NOT be decryptable in the target region, and
# this script must grow a re-wrap step.
#
# Usage:
#   bash tools/replicate-secrets-to-region.sh                 # dry-run
#   bash tools/replicate-secrets-to-region.sh --apply
#   SRC_REGION=eu-west-1 DST_REGION=eu-north-1 bash ... --apply
set -euo pipefail

SRC_REGION="${SRC_REGION:-eu-west-1}"
DST_REGION="${DST_REGION:-eu-west-3}"

# Secrets that already exist INDEPENDENTLY in the target region. Replicating
# onto an existing name fails, and forcing it would replace a secret the
# target region's own control plane owns. Verify the value matches first:
#   aws secretsmanager get-secret-value --region R --secret-id N \
#     --query SecretString --output text | shasum -a 256
# (eu-west-3's internal-gateway-token was hash-verified identical to
# eu-west-1's on 2026-08-02 before being skipped here.)
SKIP_DEFAULT="quill/trustedrouter-internal-gateway-token"
SKIP="${SKIP:-$SKIP_DEFAULT}"

APPLY=0
[ "${1:-}" = "--apply" ] && APPLY=1

echo "src=$SRC_REGION dst=$DST_REGION apply=$APPLY"

names_file="$(mktemp)"
trap 'rm -f "$names_file"' EXIT
# One name per line. NOT `for N in $(...)`: under zsh an unquoted expansion
# does not word-split, so the whole tab-separated list arrives as a single
# SecretId and the call fails with "SecretId exceeds size limit".
aws secretsmanager list-secrets --region "$SRC_REGION" \
  --query 'SecretList[].Name' --output text | tr '\t' '\n' > "$names_file"

ok=0; skipped=0; failed=0
while IFS= read -r name; do
  [ -z "$name" ] && continue
  case " $SKIP " in *" $name "*)
    echo "  skip     $name"; skipped=$((skipped+1)); continue ;;
  esac

  if [ $APPLY -eq 0 ]; then
    echo "  [dry-run] replicate $name -> $DST_REGION"
    ok=$((ok+1))
    continue
  fi

  status="$(aws secretsmanager replicate-secret-to-regions \
    --region "$SRC_REGION" --secret-id "$name" \
    --add-replica-regions "Region=$DST_REGION" \
    --query 'ReplicationStatus[0].Status' --output text 2>&1 | tail -1)"
  case "$status" in
    InProgress|InSync) echo "  ok       $name ($status)"; ok=$((ok+1)) ;;
    *)                 echo "  FAILED   $name -> $status"; failed=$((failed+1)) ;;
  esac
done < "$names_file"

echo "replicated=$ok skipped=$skipped failed=$failed"

if [ $APPLY -eq 1 ]; then
  echo
  echo "Verifying the target region can actually READ them --"
  echo "a replica stuck in InProgress or Failed is the failure this catches."
  sleep 10
  present="$(aws secretsmanager list-secrets --region "$DST_REGION" \
    --query 'length(SecretList)' --output text)"
  echo "  secrets visible in $DST_REGION: $present"
  aws secretsmanager list-secrets --region "$SRC_REGION" \
    --query "SecretList[?ReplicationStatus[?Region=='$DST_REGION' && Status!='InSync']].Name" \
    --output text | tr '\t' '\n' | sed '/^$/d' | while IFS= read -r n; do
      echo "  NOT IN SYNC: $n"
    done
fi

[ $failed -eq 0 ]
