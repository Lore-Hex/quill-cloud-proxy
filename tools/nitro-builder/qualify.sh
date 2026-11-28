#!/usr/bin/env bash
# Qualification only. No cloud credentials, key release, or mutable serving state.
set -euo pipefail
source_commit=0b89178764b10ec6e19d2e2072b226b1c589f781
legacy_eif=c91d2272459f68f8155590a6a3f4e9724a2b82bc54e4ca6fd0232d28490e9f3b
root=$(git rev-parse --show-toplevel)
recipe=$(git rev-parse HEAD:tools/nitro-builder)
tmp=${RUNNER_TEMP:?}
git merge-base --is-ancestor "$source_commit" origin/main
file="trust-page/trust/eif/$source_commit/$legacy_eif/manifest.json"
git show "origin/main:$file" > "$tmp/approved.json"
git show "origin/main:$file.bundle" > "$tmp/approved.bundle"
git worktree add --detach "$tmp/approved-source" "$source_commit"
cd "$tmp/approved-source"
python3 -m tools.aws_eif_manifest verify --manifest "$tmp/approved.json" \
  --signature "$tmp/approved.bundle" --expected-source "$source_commit"
jq -e --arg hash "$legacy_eif" '.eif_sha256 == $hash' "$tmp/approved.json" >/dev/null
tag="quill-enclave:eif-$source_commit"
bash tools/build-aws-eif-image.sh --platform linux/amd64 --file enclave-go/Dockerfile.enclave \
  --build-arg "SOURCE_REVISION=$source_commit" --build-arg BUILD_TAGS=cloud_aws,llm_multi \
  --build-arg QUILL_TLS_MODE=acme --build-arg QUILL_API_HOST=api-aws.trustedrouter.com \
  --build-arg QUILL_ACME_DNS_GCP_PROJECT=quill-cloud-proxy \
  --build-arg QUILL_ACME_DNS_MANAGED_ZONE=trustedrouter-com --tag "$tag" enclave-go
image=$(docker image inspect --format '{{.Id}}' "$tag")
printf 'Rebuilt image %s; signed image %s\n' "$image" "$(jq -r '.enclave_image_id' "$tmp/approved.json")"
jq -e --arg image "$image" '.enclave_image_id == $image' "$tmp/approved.json" >/dev/null
builder="nitro-qualification:$recipe"
docker build --no-cache --platform linux/amd64 -t "$builder" "$root/tools/nitro-builder"
docker run --rm "$builder" --version | grep -Fx 'Nitro CLI 1.5.3'
mkdir "$tmp/qualification"
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v "$tmp/qualification:/output" \
  "$builder" build-enclave --docker-uri "$tag" --output-file /output/candidate.eif > "$tmp/build.json"
docker run --rm -v "$tmp/qualification:/output:ro" "$builder" describe-eif \
  --eif-path /output/candidate.eif > "$tmp/readback.json"
diff -u <(jq -S '.Measurements' "$tmp/build.json") <(jq -S '.Measurements' "$tmp/readback.json")
jq -e --slurpfile approved "$tmp/approved.json" \
  '.CheckCRC == true and .EifVersion == 4 and
   ((.Measurements.HashAlgorithm == "Sha384") or (.Measurements.HashAlgorithm == "Sha512_48 { .. }")) and
   ((.Measurements | {PCR0,PCR1,PCR2}) == $approved[0].measurements)' "$tmp/readback.json" >/dev/null
candidate="$tmp/qualification/candidate.eif"
sha=$(sha256sum "$candidate" | cut -d' ' -f1)
jq -nS --arg sha "$sha" --argjson bytes "$(stat -c %s "$candidate")" \
  --arg recipe "$recipe" --slurpfile m "$tmp/approved.json" \
  '{source:$m[0].source_commit, converter_recipe:$recipe, image:$m[0].enclave_image_id,
    pcrs:$m[0].measurements, eif_sha256:$sha, eif_size_bytes:$bytes}' > "$tmp/candidate.json"
