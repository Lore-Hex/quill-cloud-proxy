#!/usr/bin/env bash
# Independent production-source build, from public inputs on a fresh native runner.
set -euo pipefail
sha=${GITHUB_SHA:?}
[[ "$sha" =~ ^[a-f0-9]{40}$ && "$(git rev-parse HEAD)" == "$sha" ]]
tmp=${RUNNER_TEMP:?}
app="quill-enclave:eif-$sha"
builder="nitro-rebuild:$(git rev-parse HEAD:tools/nitro-builder)"
bash tools/build-aws-eif-image.sh --platform linux/amd64 --file enclave-go/Dockerfile.enclave \
  --build-arg "SOURCE_REVISION=$sha" --build-arg BUILD_TAGS=cloud_aws,llm_multi \
  --build-arg QUILL_TLS_MODE=acme --build-arg QUILL_API_HOST=api-aws.trustedrouter.com \
  --build-arg QUILL_ACME_DNS_GCP_PROJECT=quill-cloud-proxy \
  --build-arg QUILL_ACME_DNS_MANAGED_ZONE=trustedrouter-com --tag "$app" enclave-go
docker build --no-cache --platform linux/amd64 -t "$builder" tools/nitro-builder
docker run --rm "$builder" --version | grep -Fx 'Nitro CLI 1.5.3'
mkdir "$tmp/independent"
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v "$tmp/independent:/output" \
  "$builder" build-enclave --docker-uri "$app" --output-file /output/enclave.eif > "$tmp/created.json"
docker run --rm -v "$tmp/independent:/output:ro" "$builder" describe-eif \
  --eif-path /output/enclave.eif > "$tmp/readback.json"
diff -u <(jq -S .Measurements "$tmp/created.json") <(jq -S .Measurements "$tmp/readback.json")
jq -e '.CheckCRC == true and .EifVersion == 4 and
  (.Measurements.HashAlgorithm == "Sha384" or .Measurements.HashAlgorithm == "Sha512_48 { .. }")' \
  "$tmp/readback.json" >/dev/null
file="$tmp/independent/enclave.eif"
digest=$(sha256sum "$file")
jq -nS --arg sha "$sha" --arg image "$(docker image inspect --format '{{.Id}}' "$app")" \
  --arg digest "${digest%% *}" --argjson bytes "$(stat -c %s "$file")" --slurpfile evidence "$tmp/readback.json" \
  '{source_commit:$sha,enclave_image_id:$image,eif_sha256:$digest,eif_size_bytes:$bytes,
    measurements:($evidence[0].Measurements | {PCR0,PCR1,PCR2})}' > "$tmp/independent.json"
