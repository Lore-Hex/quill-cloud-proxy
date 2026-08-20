#!/usr/bin/env bash
set -euo pipefail

source_dir="${1:-trust-page}"
bucket="${TRUST_S3_BUCKET:-trust.quill.lorehex.co}"

for required in \
  index.html \
  trust/gcp-release.json \
  trust/aws-release.json \
  trust/azure-release.json \
  trust/pcr0-aws.txt \
  trust/hostdata-azure.txt \
  pcr0.txt
do
  test -f "${source_dir}/${required}"
done

# Let the AWS CLI infer each MIME type. The legacy deploy forced every object
# to text/html, including JSON and measurement files. --delete makes the mirror
# an exact copy while the exclusion keeps the local build helper out of public
# storage.
aws s3 sync "${source_dir}/" "s3://${bucket}/" \
  --exclude "build.sh" \
  --delete \
  --cache-control "max-age=60, public"
