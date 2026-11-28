#!/usr/bin/env bash
# Input is the manifest already verified by fetch-release under the CI signing identity.
set -euo pipefail
source_sha=$1
manifest=$2
[[ "$source_sha" =~ ^[0-9a-f]{40}$ ]]
test "$(jq -er .source_commit "$manifest")" = "$source_sha"
# Old signed releases must remain available for a gated rollback. This fixed
# ancestry boundary never grows when new releases are published.
historic=bb108edc8b839675fbfabcc4c9de4fba66d69618
git cat-file -e "$historic^{commit}"
if git merge-base --is-ancestor "$source_sha" "$historic"; then
  echo "Historical release predates SLSA: existing signed-manifest and hardware gates still apply."
  exit 0
fi
repo=Lore-Hex/quill-cloud-proxy
manifest_hash=$(sha256sum "$manifest" | cut -d' ' -f1)
eif_hash=$(jq -er .eif_sha256 "$manifest")
[[ "$eif_hash" =~ ^[0-9a-f]{64}$ ]]
gh attestation verify "$manifest" --repo "$repo" --source-digest "$source_sha" \
  --signer-workflow "$repo/.github/workflows/publish-aws-eif.yml" --source-ref refs/heads/main \
  --predicate-type https://slsa.dev/provenance/v1 --deny-self-hosted-runners --format json \
  | jq -e --arg manifest "$manifest_hash" --arg eif "$eif_hash" '
      any(.[]; .verificationResult.statement.subject |
        any(.[]; .name == "manifest.json" and .digest.sha256 == $manifest) and
        any(.[]; .name == "enclave.eif" and .digest.sha256 == $eif))' >/dev/null
echo "Verified protected-build provenance binds this manifest and exact EIF."
