#!/usr/bin/env bash
# Build and publish the AWS Nitro enclave image, reproducibly.
#
# WHY THIS EXISTS
#
# The running AWS fleet was launched from `quill-enclave:aws-release-20260801-apiaws`,
# and nothing in the repo recorded how that image had been built. The build
# tags were not in the layer history, there was no release script, and the one
# workflow that builds an enclave image (.github/workflows/deploy.yml) targets
# linux/arm64 while the fleet runs x86_64 m5.xlarge — so it demonstrably did
# not produce the live image either.
#
# That mattered because BUILD_TAGS selects the PROVIDER BACKEND. Rebuilding
# with the wrong one would have silently changed which providers the enclave
# can route to, on an image about to be rolled to every instance. And because
# the tags are compiled in, the mistake would also have been baked into PCR0.
#
# BUILD_TAGS=cloud_aws,llm_multi — DETERMINED FROM EVIDENCE, NOT ASSUMED
#
# tools/deploy-aws-nitro.sh provisions 47 vsock-proxy tunnels for the enclave,
# including api.anthropic.com, api.openai.com, api.cerebras.ai, api.deepseek.com,
# api.mistral.ai, api.moonshot.ai, api.z.ai and api.together.xyz. In
# enclave-go/internal/llm, `aws.go` is `//go:build llm_bedrock` while
# anthropic.go, cohere.go, ai_studio_gemini.go, kimi.go and multi.go are all
# `llm_multi`. A Bedrock-only enclave could not dial a single one of those 47
# hosts, so the tunnels would be dead config. `llm_multi` is the only tag set
# consistent with the infrastructure that is actually deployed.
#
# `cloud_aws,llm_multi` was NOT in the CI matrix, which is precisely how an
# untested combination ended up in production. It is now.
#
# ALL OTHER BUILD ARGS are read off the live image and pinned below, so a
# rebuild changes ONLY what this release intends to change. They are part of
# the measurement: QUILL_API_HOST and QUILL_TLS_MODE are baked into the image
# and therefore into PCR0.
#
# Usage:
#   bash tools/release-aws-enclave.sh                    # dry run, prints the plan
#   bash tools/release-aws-enclave.sh --apply            # build + push
#   RELEASE_TAG=aws-release-20260806-cp bash tools/release-aws-enclave.sh --apply
#
# This script does NOT roll the fleet. Publishing an image is additive and
# reversible; replacing instances is neither, and it needs the PCR0 bind window
# in docs/runbook-aws-enclave-release.md.

set -euo pipefail

APPLY=0
[ "${1:-}" = "--apply" ] && APPLY=1

ACCOUNT="${ACCOUNT:-330422590279}"
REGIONS="${REGIONS:-eu-west-1 eu-west-3}"
REPO="${REPO:-quill-enclave}"
RELEASE_TAG="${RELEASE_TAG:-aws-release-$(date -u +%Y%m%d-%H%M)}"

# --- the measured build configuration --------------------------------------
# Changing any of these changes PCR0 and requires the bind-window procedure.
PLATFORM="linux/amd64"                      # fleet is x86_64 m5.xlarge
BUILD_TAGS="cloud_aws,llm_multi"            # see the header for the evidence
# acme, not self-signed, since 2026-08-23. The self-signed pin was honest
# documentation of the live image when it was written (64a18a3 "read off the
# live image"), but it froze a bring-up compromise into policy: the entire
# ACME path -- the GCS cert cache, the storage/LE/Cloudflare vsock tunnels,
# the DNS-01 renewer -- was already built, provisioned and running idle under
# it. Attestation-only TLS also kept api-aws outside canonical failover:
# every CA-verifying client (browsers, plain SDKs, the alias-failover pool)
# fails the handshake by design.
#
# The trust model is unchanged where it matters: the attestation document
# binds the leaf certificate minted inside the TEE regardless of who signed
# it. Let's Encrypt makes that same leaf ALSO verify for clients that cannot
# read an attestation -- exactly the posture GCP and Azure already ship.
QUILL_TLS_MODE="acme"
QUILL_API_HOST="api-aws.trustedrouter.com"
# These are measured configuration too: changing either changes PCR0. They
# make renewal instance-independent because the DNS-01 TXT record lives in
# trustedrouter.com's authoritative Cloud DNS zone, not on whichever one of
# the fleet's backends Let's Encrypt happens to dial.
QUILL_ACME_DNS_GCP_PROJECT="quill-cloud-proxy"
QUILL_ACME_DNS_MANAGED_ZONE="trustedrouter-com"
# ---------------------------------------------------------------------------

say() { printf '%s\n' "$*"; }
run() {
  if [ "$APPLY" -eq 1 ]; then "$@"; else say "  DRY-RUN: $*"; fi
}

cd "$(dirname "$0")/.."

say "AWS enclave release"
say "  tag        : ${RELEASE_TAG}"
say "  platform   : ${PLATFORM}"
say "  build tags : ${BUILD_TAGS}"
say "  tls mode   : ${QUILL_TLS_MODE}"
say "  api host   : ${QUILL_API_HOST}"
say "  dns project: ${QUILL_ACME_DNS_GCP_PROJECT}"
say "  dns zone   : ${QUILL_ACME_DNS_MANAGED_ZONE}"
say "  regions    : ${REGIONS}"
say ""

# Refuse to build from a dirty tree: the image would not correspond to any
# commit, and PCR0 would be unreproducible — which is the exact problem this
# script exists to end.
if [ -n "$(git status --porcelain -- enclave-go)" ]; then
  say "FATAL: enclave-go has uncommitted changes."
  say "  PCR0 must be reproducible from a commit. Commit or stash first."
  exit 1
fi
COMMIT="$(git rev-parse --short HEAD)"
say "  commit     : ${COMMIT}"
say ""

for region in $REGIONS; do
  registry="${ACCOUNT}.dkr.ecr.${region}.amazonaws.com"
  image="${registry}/${REPO}:${RELEASE_TAG}"
  say "--- ${region}"

  run aws ecr get-login-password --region "$region" \
    --output text >/dev/null

  if [ "$APPLY" -eq 1 ]; then
    aws ecr get-login-password --region "$region" \
      | docker login --username AWS --password-stdin "$registry" >/dev/null
  fi

  run docker buildx build \
    --platform "$PLATFORM" \
    --file enclave-go/Dockerfile.enclave \
    --build-arg "BUILD_TAGS=${BUILD_TAGS}" \
    --build-arg "QUILL_TLS_MODE=${QUILL_TLS_MODE}" \
    --build-arg "QUILL_ACME_DNS_GCP_PROJECT=${QUILL_ACME_DNS_GCP_PROJECT}" \
    --build-arg "QUILL_ACME_DNS_MANAGED_ZONE=${QUILL_ACME_DNS_MANAGED_ZONE}" \
    --build-arg "QUILL_API_HOST=${QUILL_API_HOST}" \
    --tag "$image" \
    --provenance=false \
    --push \
    enclave-go

  say "  published: ${image}"
done

say ""
say "NOT DONE YET. Publishing an image changes nothing on its own."
say "PCR0 does not exist until an instance runs nitro-cli build-enclave, so the"
say "roll must follow docs/runbook-aws-enclave-release.md:"
say "  1. point quill-enclave-lt at ${RELEASE_TAG}"
say "  2. refresh ONE eu-west-3 instance"
say "  3. read its PCR0 from a live attestation"
say "  4. publish old+new PCR0 (the pin is a SET — qcp#112 / router#459)"
say "  5. refresh the rest, verify, then narrow the pin to the new value"
say ""
say "Step 4 is the one that got skipped for months, and it is skippable because"
say "it lives in a runbook rather than in this script. Capture it here instead:"
say ""
say "    python3 tools/capture-plane-measurements.py --write --keep-accepted"
say "    # then commit trust-page/, which fires publish-trust-aws.yml"
say ""
say "--keep-accepted during the roll, so the outgoing PCR0 stays acceptable"
say "while instances are still serving it. Narrow only after the last one is"
say "refreshed. Running it WITHOUT --keep-accepted mid-roll publishes a set that"
say "rejects the instances that have not rolled yet."

# Refuse to exit 0 while the published measurement disagrees with what is
# running. An operator-run release whose publish step lives only in prose is
# the most likely rot vector in this whole arrangement — that is precisely how
# trust-page/pcr0.txt kept a value matching no running enclave from the initial
# commit onward. Exiting non-zero here does not undo the image push; it just
# refuses to call the release finished while the public record is wrong.
say ""
say "checking the published AWS measurement against a live attestation..."
if python3 "$(dirname "$0")/../tools/capture-plane-measurements.py" >/dev/null 2>&1; then
  published="$(cat "$(dirname "$0")/../trust-page/trust/accepted-pcr0s-aws.txt" 2>/dev/null || echo "")"
  running="$(python3 - <<'PY' 2>/dev/null || true
import subprocess, re, sys, pathlib
out = subprocess.run(
    [sys.executable, str(pathlib.Path(__file__).parent / "capture-plane-measurements.py")],
    capture_output=True, text=True,
).stdout
match = re.search(r"AWS   PCR0     ([0-9a-f]{96})", out)
print(match.group(1) if match else "")
PY
)"
  if [ -n "$running" ] && [ -n "$published" ] && [[ ",$published," != *",$running,"* ]]; then
    say ""
    say "RELEASE NOT COMPLETE: the running AWS enclave measures"
    say "  $running"
    say "which is not in the published set"
    say "  $published"
    say ""
    say "Publish it before calling this done:"
    say "  python3 tools/capture-plane-measurements.py --write --keep-accepted"
    exit 1
  fi
fi
