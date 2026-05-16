#!/usr/bin/env bash
# One-shot DNS fix for the quillrouter.com multi-vendor split
# (2026-05-16). Same shape as fix-trustedrouter-dns.sh but for the
# sister zone — Cloudflare emailed that quillrouter.com had drifted
# off their nameservers, and inventory showed Cloud DNS only has
# api.quillrouter.com while Cloudflare has the full 7-endpoint
# regional fan-out.
#
# Specifically, Cloud DNS was MISSING (resolvers caching Google NS
# get NXDOMAIN on these):
#   - api-europe-west4.quillrouter.com  A   → 34.13.202.2
#   - api-us-east4.quillrouter.com      A   → 34.11.96.117
#   - api-us-central1.quillrouter.com   CNAME → api.quillrouter.com.
#   - api-asia-northeast1.quillrouter.com    CNAME → api.quillrouter.com.
#   - api-asia-southeast1.quillrouter.com    CNAME → api.quillrouter.com.
#   - api-southamerica-east1.quillrouter.com CNAME → api.quillrouter.com.
#
# Plus apex NS list needs all 6 nameservers so Cloud-DNS-cached
# resolvers can rotate to Cloudflare during a Cloud DNS outage.
#
# Auth: gcloud as a Cloud-DNS-admin (your personal account, since
# tr-deploy@ only has DNS read).
#
# Idempotency: re-running after success errors on the first
# `transaction add` for an already-present record. Clean "already
# done" signal.
#
# Verification after running:
#   for ep in api api-europe-west4 api-us-east4 api-us-central1 \
#             api-asia-northeast1 api-asia-southeast1 api-southamerica-east1; do
#     echo "  $ep.quillrouter.com:"
#     for ns in ns-cloud-d1.googledomains.com brynne.ns.cloudflare.com; do
#       echo "    via $ns → $(dig +short $ep.quillrouter.com @$ns)"
#     done
#   done

set -euo pipefail

PROJECT="quill-cloud-proxy"
ZONE="quillrouter-com"
TMP=$(mktemp -d)
cd "$TMP"
echo "[$(date +%H:%M:%S)] transaction workspace: $TMP"

gcloud dns record-sets transaction start --zone="$ZONE" --project="$PROJECT"

# 1. Regional A records — direct enclave LB IPs per region.
gcloud dns record-sets transaction add \
  --zone="$ZONE" --project="$PROJECT" \
  --name="api-europe-west4.quillrouter.com." --type=A --ttl=300 \
  "34.13.202.2"

gcloud dns record-sets transaction add \
  --zone="$ZONE" --project="$PROJECT" \
  --name="api-us-east4.quillrouter.com." --type=A --ttl=300 \
  "34.11.96.117"

# 2. Regional CNAMEs — alias to the canonical api endpoint. Used for
#    routing-by-region without baking the underlying IP into a
#    separate A record (the IP can change; the alias remains stable).
for region in us-central1 asia-northeast1 asia-southeast1 southamerica-east1; do
  gcloud dns record-sets transaction add \
    --zone="$ZONE" --project="$PROJECT" \
    --name="api-${region}.quillrouter.com." --type=CNAME --ttl=300 \
    "api.quillrouter.com."
done

# 3. Apex NS list: replace the Google-only 4-NS set with all 6 so
#    Cloud-DNS-cached resolvers learn about Cloudflare's NS too.
#    Same asymmetric multi-vendor advertisement as trustedrouter.com —
#    Cloudflare-side mirror not done (free/pro tier auto-injects).
gcloud dns record-sets transaction remove \
  --zone="$ZONE" --project="$PROJECT" \
  --name="quillrouter.com." --type=NS --ttl=21600 \
  "ns-cloud-d1.googledomains.com." \
  "ns-cloud-d2.googledomains.com." \
  "ns-cloud-d3.googledomains.com." \
  "ns-cloud-d4.googledomains.com."
gcloud dns record-sets transaction add \
  --zone="$ZONE" --project="$PROJECT" \
  --name="quillrouter.com." --type=NS --ttl=21600 \
  "ns-cloud-d1.googledomains.com." \
  "ns-cloud-d2.googledomains.com." \
  "ns-cloud-d3.googledomains.com." \
  "ns-cloud-d4.googledomains.com." \
  "brynne.ns.cloudflare.com." \
  "keaton.ns.cloudflare.com."

echo "[$(date +%H:%M:%S)] transaction file:"
cat transaction.yaml
echo
echo "[$(date +%H:%M:%S)] executing..."
gcloud dns record-sets transaction execute --zone="$ZONE" --project="$PROJECT"
echo "[$(date +%H:%M:%S)] done"

echo
echo "Verification (5-second wait for propagation):"
sleep 5
for ep in api api-europe-west4 api-us-east4 api-us-central1 \
          api-asia-northeast1 api-asia-southeast1 api-southamerica-east1; do
  echo "  $ep.quillrouter.com:"
  for ns in ns-cloud-d1.googledomains.com brynne.ns.cloudflare.com; do
    answer=$(dig +short "$ep.quillrouter.com" "@$ns" | head -3 | tr '\n' ' ')
    echo "    via $ns → ${answer:-NXDOMAIN}"
  done
done
echo
echo "Apex NS via Cloud DNS:"
dig +short NS quillrouter.com @ns-cloud-d1.googledomains.com
