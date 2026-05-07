#!/usr/bin/env bash
# Fetch attested enclave workload logs from Cloud Logging.
#
# The Confidential Space launcher redirects the enclave binary's
# stdout/stderr to a specific log stream:
#   logName=projects/<project>/logs/confidential-space-launcher
#
# Filtering on resource.type="gce_instance" alone returns only the GCE
# Guest Agent (the VM-level metadata daemon) — NOT the workload. The
# right filter is the logName above. This wrapper applies it.
#
# USAGE:
#   tools/dx/enclave-logs.sh                                  # last 1h, all regions
#   tools/dx/enclave-logs.sh --since 30m                      # last 30 min
#   tools/dx/enclave-logs.sh --since 2h                       # last 2h
#   tools/dx/enclave-logs.sh --since 2026-05-06T03:00:00Z \
#                            --until 2026-05-06T04:00:00Z     # explicit window
#   tools/dx/enclave-logs.sh --region us-central1
#   tools/dx/enclave-logs.sh --grep "error|panic|denied"
#   tools/dx/enclave-logs.sh --top                            # top messages by frequency
#
# DEPENDENCIES: gcloud, awk, sort, uniq, grep.

set -euo pipefail

PROJECT_ID="${PROJECT_ID:-quill-cloud-proxy}"
SINCE="1h"
UNTIL=""
REGION=""
GREP_PATTERN=""
TOP_MODE=0
LIMIT="${LIMIT:-200}"

usage() {
  cat <<EOF
Usage: $0 [options]
  --since <duration|timestamp>   default: 1h. Either Go-style duration (30m, 2h, 1d)
                                 or RFC3339 timestamp (2026-05-06T03:00:00Z).
  --until <timestamp>            optional end of window (default: now)
  --region <us-central1|europe-west4>
  --grep <regex>                 case-insensitive grep applied to the message field
  --top                          print top message lines by count, instead of chronological
  --limit <n>                    default: $LIMIT
  --project <id>                 default: $PROJECT_ID

EXAMPLES:
  # First-response: what was the workload saying in the last 30 min?
  $0 --since 30m

  # Post-mortem: 5/6 03:00 UTC outage
  $0 --since 2026-05-06T03:00:00Z --until 2026-05-06T04:00:00Z --top

  # Recent errors only
  $0 --since 2h --grep "error|panic|denied|failed"

  # Single region
  $0 --region us-central1 --since 1h
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --since) SINCE="$2"; shift 2 ;;
    --until) UNTIL="$2"; shift 2 ;;
    --region) REGION="$2"; shift 2 ;;
    --grep) GREP_PATTERN="$2"; shift 2 ;;
    --top) TOP_MODE=1; shift ;;
    --limit) LIMIT="$2"; shift 2 ;;
    --project) PROJECT_ID="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown arg: $1" >&2; usage >&2; exit 2 ;;
  esac
done

# Resolve --since to an RFC3339 timestamp. If it's already a timestamp,
# pass through; otherwise treat it as a Go-style duration ("now - X").
if [[ "$SINCE" =~ ^[0-9]+(s|m|h|d)$ ]]; then
  count="${SINCE%[smhd]}"
  unit="${SINCE: -1}"
  case "$unit" in
    s) seconds="$count" ;;
    m) seconds=$((count * 60)) ;;
    h) seconds=$((count * 3600)) ;;
    d) seconds=$((count * 86400)) ;;
  esac
  if date -u -v -1S +%s >/dev/null 2>&1; then
    # macOS / BSD date
    SINCE_TS=$(date -u -v "-${seconds}S" +%Y-%m-%dT%H:%M:%SZ)
  else
    # GNU date
    SINCE_TS=$(date -u -d "-${seconds} seconds" +%Y-%m-%dT%H:%M:%SZ)
  fi
else
  SINCE_TS="$SINCE"
fi

filter="logName=projects/${PROJECT_ID}/logs/confidential-space-launcher"
filter+=" AND timestamp>=\"${SINCE_TS}\""
if [ -n "$UNTIL" ]; then
  filter+=" AND timestamp<=\"${UNTIL}\""
fi
if [ -n "$REGION" ]; then
  # MIG-managed instances carry a region label.
  filter+=" AND labels.\"compute.googleapis.com/instance_group_manager/region\"=\"${REGION}\""
fi

echo "filter: ${filter}" >&2
echo "limit:  ${LIMIT}" >&2

raw=$(gcloud logging read "$filter" \
  --project="$PROJECT_ID" \
  --limit="$LIMIT" \
  --format='value(timestamp,labels."compute.googleapis.com/instance_group_manager/region",resource.labels.instance_id,textPayload,jsonPayload.MESSAGE,jsonPayload.message)' \
  2>/dev/null)

if [ -z "$raw" ]; then
  echo "(no log entries matched)" >&2
  exit 0
fi

# Each line is: <ts>\t<region>\t<instance_id>\t<message>...
# Some entries duplicate the message in multiple JSON fields; collapse
# to the first non-empty message column.

collapsed=$(echo "$raw" | /usr/bin/awk -F'\t' '{
  msg = $4; if (msg == "") msg = $5; if (msg == "") msg = $6;
  if (msg == "") next;
  printf "%s  [%s]  %s\n", $1, ($2 == "" ? "global" : $2), msg;
}')

if [ -n "$GREP_PATTERN" ]; then
  collapsed=$(echo "$collapsed" | /usr/bin/grep -iE "$GREP_PATTERN" || true)
fi

if [ "$TOP_MODE" -eq 1 ]; then
  # Strip the timestamp+region prefix to count by raw message.
  echo "$collapsed" | /usr/bin/sed -E 's|^[^[]+\[[a-z0-9-]+\][[:space:]]+||' \
    | /usr/bin/sort | /usr/bin/uniq -c | /usr/bin/sort -rn | /usr/bin/head -30
else
  echo "$collapsed"
fi
