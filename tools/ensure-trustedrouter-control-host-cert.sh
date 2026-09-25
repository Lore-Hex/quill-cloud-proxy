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
#
# When the proxy has a Certificate Manager certificate map (quill-router
# infra/control_lb_certificate_map.tf), the account needs
# compute.targetHttpsProxies.get, certificatemanager.certmapentries.list and
# certificatemanager.certs.list instead.

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

# A proxy with a certificate map serves the map's certificates and ignores its
# classic ones. Then this script creates and attaches none: it succeeds when
# $HOST has an ACTIVE map entry with an ACTIVE certificate and fails otherwise.
certificate_map="$(gc compute target-https-proxies describe "$PROXY" \
  --project="$PROJECT" \
  --global \
  --format='value(certificateMap)')"
if [ -n "$certificate_map" ]; then
  map_entries="$(gc certificate-manager maps entries list \
    --map="${certificate_map##*/}" \
    --location=global \
    --project="$PROJECT" \
    --format=json)"
  map_certificates="$(gc certificate-manager certificates list \
    --location=global \
    --project="$PROJECT" \
    --format=json)"
  # Certificate Manager serves a host from the entry for that exact name, or
  # else from the entry for *.<its parent domain>. An entry is PENDING while it
  # propagates to the load balancer's frontends. The two lists reach python3
  # on stdin, separated by an ASCII record separator, not through the
  # environment: Linux limits one environment string to 128 KiB, and the
  # certificate list, which carries PEM chains, was 233 KiB on 2026-09-25.
  if printf '%s\n\036\n%s' "$map_entries" "$map_certificates" | HOST="$HOST" python3 -c '
import json, os, sys
entries_json, certificates_json = sys.stdin.read().split("\n\x1e\n")
entries = {e["hostname"]: e for e in json.loads(entries_json) if e.get("hostname")}
active = {c["name"] for c in json.loads(certificates_json) if c.get("managed", {}).get("state") == "ACTIVE"}
host = os.environ["HOST"]
entry = entries[host] if host in entries else entries.get("*." + host.split(".", 1)[-1], {})
sys.exit(0 if entry.get("state") == "ACTIVE" and any(c in active for c in entry.get("certificates", [])) else 1)
'; then
    echo "$PROXY uses certificate map ${certificate_map##*/}; $HOST has an ACTIVE entry and certificate there."
    exit 0
  fi
  echo "$PROXY uses certificate map ${certificate_map##*/}, which has no ACTIVE entry with an ACTIVE certificate for $HOST." >&2
  echo "Add it to the certificate map in quill-router infra/ instead of creating a classic certificate." >&2
  exit 1
fi

cert_slug="$(printf '%s' "$HOST" | tr '.[:upper:]' '-[:lower:]' | sed 's/[^a-z0-9-]/-/g')"
if [ "$HOST" = "trustedrouter.com" ]; then
  # Keep the apex certificate independent from trust.trustedrouter.com. The
  # trust site is hosted separately, so a shared certificate cannot renew.
  cert_name="${CERT_NAME:-trusted-router-apex-cert-v2}"
else
  cert_name="${CERT_NAME:-${CERT_PREFIX}-${cert_slug}-cert}"
fi

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

domains="$(
  gc compute ssl-certificates describe "$cert_name" \
    --project="$PROJECT" \
    --global \
    --format='value(managed.domains)' | tr ';' '\n' | sed '/^$/d'
)"
if [ "$domains" != "$HOST" ]; then
  echo "$cert_name must contain only $HOST; found: $domains" >&2
  echo "Use a separate certificate for every independently hosted hostname." >&2
  exit 1
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
