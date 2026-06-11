#!/usr/bin/env bash
# Ensure an extra trustedrouter.com control-plane hostname has a Google-managed
# HTTPS certificate and is attached to the existing global HTTPS proxy.
#
# Usage:
#   tools/ensure-trustedrouter-control-host-cert.sh eu.trustedrouter.com
#
# Requires an account with:
#   compute.sslCertificates.create
#   compute.targetHttpsProxies.update

set -euo pipefail

PROJECT="${PROJECT:-quill-cloud-proxy}"
ACCOUNT="${GCLOUD_ACCOUNT:-${CLOUDSDK_CORE_ACCOUNT:-}}"
PROXY="${PROXY:-trusted-router-control-https-proxy}"
CERT_PREFIX="${CERT_PREFIX:-trusted-router}"

HOST="${1:-}"
if [ -z "$HOST" ]; then
  echo "usage: $0 <hostname>" >&2
  exit 2
fi

gc() {
  if [ -n "$ACCOUNT" ]; then
    gcloud --account="$ACCOUNT" "$@"
  else
    gcloud "$@"
  fi
}

cert_slug="$(printf '%s' "$HOST" | tr '.[:upper:]' '-[:lower:]' | sed 's/[^a-z0-9-]/-/g')"
cert_name="${CERT_PREFIX}-${cert_slug}-cert"

if ! gc compute ssl-certificates describe "$cert_name" \
  --project="$PROJECT" --global >/dev/null 2>&1; then
  echo "creating managed certificate $cert_name for $HOST"
  gc compute ssl-certificates create "$cert_name" \
    --project="$PROJECT" \
    --global \
    --domains="$HOST"
else
  echo "managed certificate $cert_name already exists"
fi

existing="$(
  gc compute target-https-proxies describe "$PROXY" \
    --project="$PROJECT" \
    --global \
    --format='value(sslCertificates.basename())'
)"

certs=()
while IFS= read -r cert; do
  [ -n "$cert" ] && certs+=("$cert")
done < <(printf '%s\n' "$existing" | tr ';' '\n')

found=0
for cert in "${certs[@]}"; do
  if [ "$cert" = "$cert_name" ]; then
    found=1
    break
  fi
done
if [ "$found" = "0" ]; then
  certs+=("$cert_name")
fi

joined="$(IFS=,; echo "${certs[*]}")"
echo "updating $PROXY certs: $joined"
gc compute target-https-proxies update "$PROXY" \
  --project="$PROJECT" \
  --global \
  --ssl-certificates="$joined"

echo "waiting for $cert_name to become ACTIVE"
for _ in $(seq 1 60); do
  status="$(
    gc compute ssl-certificates describe "$cert_name" \
      --project="$PROJECT" \
      --global \
      --format='value(managed.status)' || true
  )"
  echo "status=$status"
  if [ "$status" = "ACTIVE" ]; then
    exit 0
  fi
  sleep 10
done

echo "certificate is not ACTIVE yet; Google-managed cert provisioning may still be running" >&2
exit 1
