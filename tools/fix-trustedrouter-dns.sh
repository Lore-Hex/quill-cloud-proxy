#!/usr/bin/env bash
# One-shot DNS fix for the trustedrouter.com multi-vendor split
# (2026-05-14). Run this ONCE to bring Cloud DNS into sync with what
# Cloudflare has been correctly serving for months.
#
# Symptoms it fixes:
#  - Quad9 / Cloud-DNS-cached resolvers see `trust.trustedrouter.com`
#    pointing at a Cloud Run IP that doesn't serve the trust page
#    (Cloudflare correctly CNAMEs to lore-hex.github.io for GitHub
#    Pages).
#  - Google's site-verification check fails for Cloud-DNS-cached
#    resolvers because the verification TXT record is absent.
#  - www.trustedrouter.com is an A record on Cloud DNS but a CNAME on
#    Cloudflare; semantic mismatch (currently functional but
#    inconsistent).
#
# What it does, atomically (a single Cloud DNS transaction):
#  1. Replace `trust.trustedrouter.com A 35.241.14.18`
#                  with `trust.trustedrouter.com CNAME lore-hex.github.io.`
#  2. Add the missing google-site-verification TXT record
#  3. Replace `www.trustedrouter.com A 35.241.14.18`
#                  with `www.trustedrouter.com CNAME trustedrouter.com.`
#
# Auth: gcloud as a Cloud-DNS-admin (your personal account, since the
# tr-deploy@ SA only has DNS read). Run from any shell with that
# account active.
#
# Idempotency: each transaction step asserts the record's current
# value before changing it; running this twice after success yields
# "Record removal failed: not found" on the second run, which is
# how you confirm step-by-step the previous run took.
#
# Verification after running:
#   for r in 1.1.1.1 8.8.8.8 9.9.9.9; do
#     echo "  $r: $(dig +short trust.trustedrouter.com @$r)"
#   done
# All three should now agree (CNAME to lore-hex.github.io.).

set -euo pipefail

PROJECT="quill-cloud-proxy"
ZONE="trustedrouter-com"
TMP=$(mktemp -d)
cd "$TMP"
echo "[$(date +%H:%M:%S)] transaction workspace: $TMP"

gcloud dns record-sets transaction start --zone="$ZONE" --project="$PROJECT"

# 1. trust subdomain: drop bad A, add correct CNAME.
gcloud dns record-sets transaction remove \
  --zone="$ZONE" --project="$PROJECT" \
  --name="trust.trustedrouter.com." --type=A --ttl=300 \
  "35.241.14.18"
gcloud dns record-sets transaction add \
  --zone="$ZONE" --project="$PROJECT" \
  --name="trust.trustedrouter.com." --type=CNAME --ttl=300 \
  "lore-hex.github.io."

# 2. Google site-verification TXT (currently only on Cloudflare).
gcloud dns record-sets transaction add \
  --zone="$ZONE" --project="$PROJECT" \
  --name="trustedrouter.com." --type=TXT --ttl=300 \
  '"google-site-verification=n2y7GA2FN8RxHA1aO7r_JueOsymAgBjhqWgwRn7G8cU"'

# 3. www: replace A with CNAME for semantic parity with Cloudflare.
gcloud dns record-sets transaction remove \
  --zone="$ZONE" --project="$PROJECT" \
  --name="www.trustedrouter.com." --type=A --ttl=300 \
  "35.241.14.18"
gcloud dns record-sets transaction add \
  --zone="$ZONE" --project="$PROJECT" \
  --name="www.trustedrouter.com." --type=CNAME --ttl=300 \
  "trustedrouter.com."

echo "[$(date +%H:%M:%S)] transaction file:"
cat transaction.yaml
echo
echo "[$(date +%H:%M:%S)] executing..."
gcloud dns record-sets transaction execute --zone="$ZONE" --project="$PROJECT"
echo "[$(date +%H:%M:%S)] done"

echo
echo "Verification (5-second wait for propagation through Google's NS):"
sleep 5
for ns in ns-cloud-b1.googledomains.com dom.ns.cloudflare.com; do
  echo "  via $ns:"
  echo "    trust  → $(dig +short trust.trustedrouter.com @$ns)"
  echo "    www    → $(dig +short www.trustedrouter.com @$ns)"
  echo "    TXT    → $(dig +short TXT trustedrouter.com @$ns)"
done
