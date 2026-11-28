#!/usr/bin/env bash
# Copies the qualified archive without converting the manifest or recompressing layers.
set -euo pipefail
plane=${1:?} source=${2:?} expected=${3:?} archive=${4:?}
[[ "$source" =~ ^[0-9a-f]{40}$ && "$expected" =~ ^sha256:[0-9a-f]{64}$ ]]
case "$plane" in
  gcp) registry=us-central1-docker.pkg.dev; repository=quill-cloud-proxy/quill/enclave-multi ;;
  azure) registry=trquillacr.azurecr.io; repository=quill-enclave-azure ;;
  *) exit 2 ;;
esac
umask 077
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
printf '{"containerimage.digest":"%s"}\n' "$expected" > "$tmp/expected.json"
python3 "$(dirname "$0")/verify_release_oci.py" "$archive" "$tmp/expected.json" "$plane" "$source" > "$tmp/record.json"
command -v skopeo >/dev/null
if [[ "$plane" == gcp ]]; then
  gcloud auth print-access-token | skopeo login --authfile "$tmp/auth.json" \
    --username oauth2accesstoken --password-stdin "$registry" >/dev/null
else
  az acr login --name trquillacr --expose-token --query accessToken -o tsv | \
    skopeo login --authfile "$tmp/auth.json" --username 00000000-0000-0000-0000-000000000000 \
      --password-stdin "$registry" >/dev/null
fi
# Content-named staging tags never replace a serving release tag.
base="$registry/$repository"
skopeo copy --authfile "$tmp/auth.json" --preserve-digests "oci-archive:$archive" \
  "docker://$base:repro-${expected#sha256:}" >&2
skopeo inspect --authfile "$tmp/auth.json" --raw "docker://$base@$expected" > "$tmp/manifest"
actual=$(sha256sum "$tmp/manifest")
[[ "sha256:${actual%% *}" == "$expected" ]]
jq --arg image "$base@$expected" '. + {registry_image:$image}' "$tmp/record.json"
