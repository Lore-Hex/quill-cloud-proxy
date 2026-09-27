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
python3 "$(dirname "$0")/check-trust-copies.py" "${source_dir}"
python3 "$(dirname "$0")/check-trust-signatures.py" "${source_dir}"

# Let the AWS CLI infer each MIME type. The legacy deploy forced every object
# to text/html, including JSON and measurement files. --delete makes the mirror
# an exact copy.
#
# publish-trust-s3.yml is the mirror's one publisher: it runs this script, one
# run at a time, from a fresh checkout of main. aws s3 sync skips a same-size
# file whose local copy is older than the S3 copy, so a sync from an older
# checkout, or one racing another writer, can upload a file's root copy and
# skip its trust/ copy.
aws s3 sync "${source_dir}/" "s3://${bucket}/" \
  --delete \
  --cache-control "max-age=60, public"
