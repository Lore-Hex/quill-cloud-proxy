#!/usr/bin/env bash
# Build, measure, re-bind and deploy the Quill enclave as an Azure confidential
# container group (AMD SEV-SNP, ACI), then PROVE the deployed workload is the
# one the Key Vault release policy trusts.
#
# ============================================================================
# THE ORDERING TRAP. READ THIS BEFORE EDITING ANY PHASE.
# ============================================================================
# The SKR key that opens the bootstrap bundle is released only to a workload
# whose x-ms-sevsnpvm-hostdata equals the CCE policy hash named in the key's
# release policy. That hash is a function of the ENTIRE container-group
# definition: image digest, command, every env var name AND value, resources,
# the sidecar, all of it. So it changes on essentially every deploy.
#
# A deploy that builds a new image and does not RE-BIND the key's release
# policy produces an enclave that starts, attests perfectly, and then gets 403
# from Key Vault and cannot boot. Nothing about the failure points at the
# release policy; the container just exits.
#
# The order is therefore load-bearing, and it is why this script has phases:
#
#     build     ->  image digest
#     template  ->  ARM template pinned to that digest
#     policy    ->  CCE policy generated from that template + its hash
#     bind      ->  the key's release policy WIDENED to {old, new}   <-- BEFORE
#     deploy    ->  create the container group                       <-- THIS
#     verify    ->  fetch a real attestation and check hostdata against the
#                   hash the KEY expects, not the one we think we generated
#     narrow    ->  the key's release policy narrowed to {new}
#
# `verify` is not a formality. It reads the pin out of Key Vault and compares it
# to the live attestation, so a hash we derived incorrectly, a bind that silently
# no-oped, or a container group that drifted from the template all fail LOUDLY
# instead of turning into a 403 nobody can explain.
#
# WHY bind WIDENS INSTEAD OF REPLACING
# ------------------------------------
# Replacing the pin in one step destroys the only record of what the CURRENTLY
# RUNNING enclave is allowed to be, at the exact moment the deploy is most
# likely to fail. `deploy` has to delete the old group before it can create the
# new one (a confidential group's measured surface is fixed at creation), so an
# ARM create that fails for an ordinary reason — ACR pull, region capacity,
# quota — leaves no group AND no way back: the old measurement is reconstructible
# only by reproducing the previous image bit for bit.
#
# So `bind` emits an anyOf with BOTH hostdata values and records the old set in
# $WORKDIR/previous-hostdata.txt. During the window the old enclave can still
# re-acquire its key (an ACI host maintenance event or an operator restart in
# that window would otherwise be unrecoverable), `rollback` can put the pin back,
# and `narrow` closes the window once `verify` has proved the new workload.
# verify-attestation.py's --expected-hostdata takes a comma-separated set for
# precisely this reason.
#
# ============================================================================
# THE OTHER ORDERING: the bundle is measured too
# ============================================================================
# QUILL_AZURE_BUNDLE_VERSION pins one immutable Key Vault secret version, and it
# is an env var, so it is part of the measurement. Seal and upload the bundle
# FIRST, then set the version, then run this script:
#
#   1. ./tools/deploy-azure-aci.sh print-env > /tmp/aci-env.json
#   2. ./tools/azure-seal-bundle.py --deploy-env /tmp/aci-env.json \
#          --values secrets.json --value-file "$SA_KEY_ENTRY=sa-key.json" \
#          --vault "$VAULT" --key-name "$SKR_KEY" --upload-secret "$BUNDLE_SECRET"
#   3. export QUILL_AZURE_BUNDLE_VERSION=<version printed in step 2>
#   4. ./tools/deploy-azure-aci.sh --apply all
#
# Leaving the version unset is allowed and follows "current", which is exactly
# what makes silent substitution and silent rollback of the whole secret bundle
# possible on the next cold start. The script warns, every run.
#
# ============================================================================
# USAGE
# ============================================================================
#   ./tools/deploy-azure-aci.sh                      # dry-run every phase
#   ./tools/deploy-azure-aci.sh --apply all          # do it
#   ./tools/deploy-azure-aci.sh --apply policy bind  # one or more phases
#   ./tools/deploy-azure-aci.sh print-env            # env JSON for the sealer
#   ./tools/deploy-azure-aci.sh verify               # re-check a live deploy
#   ./tools/deploy-azure-aci.sh --apply rollback     # put the old pin back
#   ./tools/deploy-azure-aci.sh logs                 # both containers' logs
#
# Dry-run is the default, matching tools/deploy-aws-nitro.sh: only --apply
# touches AZURE. It does NOT mean "touches nothing at all": build, template and
# policy write $WORKDIR either way, because the whole point of a dry run is to
# produce a template and an ordering someone can read. That is also why the
# deploy guard derives its expectation from template.json itself rather than
# from a note left beside it — see phase_deploy.
#
# PREREQUISITES the script checks but cannot create (they are one-time, and
# creating identities and role assignments from a deploy script is how a deploy
# pipeline quietly becomes an admin):
#   - resource group, ACR, Key Vault Premium, MAA instance
#   - user-assigned identity with, on the vault, "Key Vault Crypto Service
#     Release User" + "Key Vault Crypto Officer" (to read/rebind the key) and
#     "Key Vault Secrets User" (to read the bundle), and AcrPull on the registry
#   - an exportable RSA-HSM key in the vault (the SKR wrapping key)
#   - docker, for `az confcom acipolicygen` (see the policy phase)

set -euo pipefail

# ---------------------------------------------------------------------------
# configuration
# ---------------------------------------------------------------------------
# Defaults name the resources that were proven on real SEV-SNP hardware in UAE
# North. Override any of them from the environment.

SUBSCRIPTION="${SUBSCRIPTION:-}"
RESOURCE_GROUP="${RESOURCE_GROUP:-tr-quill-uaen}"
LOCATION="${LOCATION:-uaenorth}"
ACR="${ACR:-trquillacr}"
VAULT="${VAULT:-trquillkv}"
MAA_ENDPOINT="${MAA_ENDPOINT:-trquilluaen.uaen.attest.azure.net}"
IDENTITY_NAME="${IDENTITY_NAME:-tr-skr-identity}"
SKR_KEY="${SKR_KEY:-tr-bootstrap-wrap}"
BUNDLE_SECRET="${BUNDLE_SECRET:-tr-bootstrap-bundle}"
SA_KEY_ENTRY="${SA_KEY_ENTRY:-tr-cross-cloud-sa-key}"
CONTAINER_GROUP="${CONTAINER_GROUP:-quill-enclave-${LOCATION}}"
DNS_LABEL="${DNS_LABEL:-${CONTAINER_GROUP}}"
API_HOST="${API_HOST:-api-azure.trustedrouter.com}"
IMAGE_REPO="${IMAGE_REPO:-quill-enclave-azure}"
IMAGE_TAG="${IMAGE_TAG:-azure-$(date -u +%Y%m%d%H%M%S)}"

# The skr sidecar. Version 2.7 is what was measured serving /attest/maa and
# /key/release on localhost:8080 (NOT 8284, which appears in some samples and
# which this sidecar refuses).
SKR_IMAGE="${SKR_IMAGE:-mcr.microsoft.com/aci/skr:2.7}"
# MEASURED SURFACE. The sidecar's command and its SkrSideCarArgs are part of the
# container-group definition, so they feed the CCE policy hash. If the hardware
# run these defaults were taken from used a different spelling, override rather
# than "fix" — a mismatch here does not error, it produces a different
# measurement and a 403 at boot.
SKR_COMMAND="${SKR_COMMAND:-/skr.sh}"
SKR_CERT_CACHE_ENDPOINT="${SKR_CERT_CACHE_ENDPOINT:-americas.test.acccache.azure.net}"

ENCLAVE_CPU="${ENCLAVE_CPU:-2}"
ENCLAVE_MEMORY_GB="${ENCLAVE_MEMORY_GB:-4}"
SKR_CPU="${SKR_CPU:-1}"
SKR_MEMORY_GB="${SKR_MEMORY_GB:-2}"

# Secret NAMES (never values). These are the keys of the sealed bundle and must
# match what tools/azure-seal-bundle.py was given.
QUILL_GCP_PROJECT_ID="${QUILL_GCP_PROJECT_ID:-quill-cloud-proxy}"
QUILL_DEVICE_KEYS_SECRET="${QUILL_DEVICE_KEYS_SECRET:-quill-device-keys}"
QUILL_OPENROUTER_SECRET="${QUILL_OPENROUTER_SECRET:-quill-openrouter-key}"
QUILL_ANTHROPIC_SECRET="${QUILL_ANTHROPIC_SECRET:-trustedrouter-anthropic-api-key}"
QUILL_OPENAI_SECRET="${QUILL_OPENAI_SECRET:-trustedrouter-openai-api-key}"
QUILL_GEMINI_SECRET="${QUILL_GEMINI_SECRET:-trustedrouter-gemini-api-key}"
QUILL_CEREBRAS_SECRET="${QUILL_CEREBRAS_SECRET:-trustedrouter-cerebras-api-key}"
QUILL_DEEPSEEK_SECRET="${QUILL_DEEPSEEK_SECRET:-trustedrouter-deepseek-api-key}"
QUILL_MISTRAL_SECRET="${QUILL_MISTRAL_SECRET:-trustedrouter-mistral-api-key}"
QUILL_KIMI_SECRET="${QUILL_KIMI_SECRET:-trustedrouter-kimi-api-key}"
QUILL_ZAI_SECRET="${QUILL_ZAI_SECRET:-trustedrouter-zai-api-key}"
QUILL_TOGETHER_SECRET="${QUILL_TOGETHER_SECRET:-trustedrouter-together-api-key}"
QUILL_FIREWORKS_SECRET="${QUILL_FIREWORKS_SECRET:-trustedrouter-fireworks-api-key}"
QUILL_COHERE_SECRET="${QUILL_COHERE_SECRET:-trustedrouter-cohere-api-key}"
QUILL_VOYAGE_SECRET="${QUILL_VOYAGE_SECRET:-trustedrouter-voyage-api-key}"
QUILL_GROK_SECRET="${QUILL_GROK_SECRET:-trustedrouter-grok-api-key}"
QUILL_NOVITA_SECRET="${QUILL_NOVITA_SECRET:-trustedrouter-novita-api-key}"
QUILL_PHALA_SECRET="${QUILL_PHALA_SECRET:-trustedrouter-phala-confidential-api-key}"
QUILL_SILICONFLOW_SECRET="${QUILL_SILICONFLOW_SECRET:-trustedrouter-siliconflow-api-key}"
QUILL_TINFOIL_SECRET="${QUILL_TINFOIL_SECRET:-trustedrouter-tinfoil-api-key}"
QUILL_VENICE_SECRET="${QUILL_VENICE_SECRET:-trustedrouter-venice-api-key}"
QUILL_PARASAIL_SECRET="${QUILL_PARASAIL_SECRET:-trustedrouter-parasail-api-key}"
QUILL_LIGHTNING_SECRET="${QUILL_LIGHTNING_SECRET:-trustedrouter-lightning-api-key}"
QUILL_GMI_SECRET="${QUILL_GMI_SECRET:-trustedrouter-gmi-api-key}"
QUILL_DEEPINFRA_SECRET="${QUILL_DEEPINFRA_SECRET:-trustedrouter-deepinfra-api-key}"
QUILL_FRIENDLI_SECRET="${QUILL_FRIENDLI_SECRET:-trustedrouter-friendli-api-key}"
QUILL_BASETEN_SECRET="${QUILL_BASETEN_SECRET:-trustedrouter-baseten-api-key}"
QUILL_THINKING_MACHINES_SECRET="${QUILL_THINKING_MACHINES_SECRET:-trustedrouter-thinking-machines-api-key}"
QUILL_WAFER_SECRET="${QUILL_WAFER_SECRET:-trustedrouter-wafer-api-key}"
QUILL_CRUSOE_SECRET="${QUILL_CRUSOE_SECRET:-trustedrouter-crusoe-api-key}"
QUILL_MAKORA_SECRET="${QUILL_MAKORA_SECRET:-trustedrouter-makora-api-key}"
QUILL_NEBIUS_SECRET="${QUILL_NEBIUS_SECRET:-trustedrouter-nebius-api-key}"
QUILL_MINIMAX_SECRET="${QUILL_MINIMAX_SECRET:-trustedrouter-minimax-api-key}"
QUILL_XIAOMI_SECRET="${QUILL_XIAOMI_SECRET:-trustedrouter-xiaomi-api-key}"
QUILL_SYNTH_PANEL_PROMPT_SECRET="${QUILL_SYNTH_PANEL_PROMPT_SECRET:-trustedrouter-synth-panel-prompt-v1}"
QUILL_SYNTH_SYNTHESIS_PROMPT_SECRET="${QUILL_SYNTH_SYNTHESIS_PROMPT_SECRET:-trustedrouter-synth-synthesis-prompt-v1}"
QUILL_SYNTH_CODE_PANEL_PROMPT_SECRET="${QUILL_SYNTH_CODE_PANEL_PROMPT_SECRET:-trustedrouter-synth-code-panel-prompt-v1}"
QUILL_SYNTH_CODE_SYNTHESIS_PROMPT_SECRET="${QUILL_SYNTH_CODE_SYNTHESIS_PROMPT_SECRET:-trustedrouter-synth-code-synthesis-prompt-v1}"
QUILL_ADVISOR_WORKER_PROMPT_SECRET="${QUILL_ADVISOR_WORKER_PROMPT_SECRET:-trustedrouter-advisor-worker-prompt-v1}"
QUILL_ADVISOR_PROMPT_SECRET="${QUILL_ADVISOR_PROMPT_SECRET:-trustedrouter-advisor-prompt-v1}"
QUILL_TRUSTEDROUTER_INTERNAL_SECRET="${QUILL_TRUSTEDROUTER_INTERNAL_SECRET:-trustedrouter-internal-gateway-token}"

QUILL_ACME_CACHE_GCS_BUCKET="${QUILL_ACME_CACHE_GCS_BUCKET:-quill-acme-cache}"
QUILL_ACME_EMAIL="${QUILL_ACME_EMAIL:-acme-azure-${LOCATION}@trustedrouter.com}"
QUILL_FIRST_BYTE_TIMEOUT_SECONDS="${QUILL_FIRST_BYTE_TIMEOUT_SECONDS:-20}"
QUILL_HEALTH_PORT="${QUILL_HEALTH_PORT:-8081}"
TR_CONTROL_PLANE_BASE_URL="${TR_CONTROL_PLANE_BASE_URL:-https://trustedrouter.com}"
# Unset = follow "current", which is substitutable and rollback-able. See the
# header. warn_unpinned_bundle() says so on every run.
QUILL_AZURE_BUNDLE_VERSION="${QUILL_AZURE_BUNDLE_VERSION:-}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="${WORKDIR:-${TMPDIR:-/tmp}/quill-azure-aci-${CONTAINER_GROUP}}"
APPLY=0

# ---------------------------------------------------------------------------
# plumbing
# ---------------------------------------------------------------------------

log()  { printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }
die()  { printf '\n[FAIL] %s\n' "$*" >&2; exit 1; }
note() { printf '        %s\n' "$*" >&2; }

# run: execute (or, in dry-run, print) a mutating command.
run() {
  if [ "$APPLY" = "1" ]; then
    "$@"
  else
    printf '  DRY-RUN  ' >&2
    printf '%q ' "$@" >&2
    printf '\n' >&2
  fi
}

# Two az wrappers, and the difference is WHEN they run, not what they may do.
#
#   az_cli  runs immediately, in dry-run too. Used for the lookups a dry-run
#           needs in order to mean anything (the identity's client id, the
#           currently deployed policy, the hostdata the key is bound to) — and,
#           inside an explicit `if [ "$APPLY" = "1" ]` branch, for the one
#           mutation whose result must be read back in the same phase.
#   az_rw   goes through run(), so it only executes under --apply.
az_cli() {
  local args=(az "$@")
  if [ -n "$SUBSCRIPTION" ]; then args+=(--subscription "$SUBSCRIPTION"); fi
  "${args[@]}"
}
az_rw() {
  local args=(az "$@")
  if [ -n "$SUBSCRIPTION" ]; then args+=(--subscription "$SUBSCRIPTION"); fi
  run "${args[@]}"
}

# require_tool only bites under --apply. A dry-run's job is to let someone
# review the template and the ordering on a laptop that has neither az nor
# docker installed; making it demand the tools it is not going to invoke would
# retire the only mode that is safe to run casually.
require_tool() {
  [ "$APPLY" = "1" ] || return 0
  command -v "$1" >/dev/null 2>&1 || die "$1 is required but not on PATH"
}

# ---------------------------------------------------------------------------
# the workdir lock
# ---------------------------------------------------------------------------
# $WORKDIR is derived from $CONTAINER_GROUP alone, so two runs against the same
# group share every artifact: image-digest.txt, template.json,
# cce-policy-hash.txt, release-policy.json. Interleave them and the deploy
# guard cannot help, because BOTH of its operands end up describing the OTHER
# run:
#
#   A: build -> template -> policy (hash_A) -> bind (key := hash_A)
#   B: build -> template (CLOBBERS A's) -> policy (hash_B) -> bind (key := hash_B)
#   A: deploy -> template.json is B's, the key pins hash_B, the guard compares
#      hash_B to hash_B, passes, and A ships B's workload believing it is its own
#
# Nothing downstream can detect that: the live group really is B's and the key
# really does pin B, so `verify` passes too. The only fix is to make the
# interleaving impossible.
#
# mkdir rather than flock(1): flock is not present on macOS, and mkdir is
# atomic on every filesystem this runs on.
LOCK_DIR=""

release_workdir_lock() {
  [ -n "$LOCK_DIR" ] || return 0
  rm -rf "$LOCK_DIR"
  LOCK_DIR=""
}

acquire_workdir_lock() {
  local lock="${WORKDIR}.lock"
  if ! mkdir "$lock" 2>/dev/null; then
    local holder=""
    holder="$(cat "$lock/pid" 2>/dev/null || true)"
    if [ -n "$holder" ] && kill -0 "$holder" 2>/dev/null; then
      die "another deploy (pid $holder) already holds $lock.
       Two runs sharing $WORKDIR silently swap workloads: each overwrites the
       other's template.json and cce-policy-hash.txt, and the deploy guard then
       compares two values that BOTH came from the clobbered files, so it passes
       and one run ships the other's image. Wait for that run, or use a different
       CONTAINER_GROUP (or an explicit WORKDIR)."
    fi
    log "clearing a stale lock at $lock (holder pid '${holder:-unknown}' is not running)"
    rm -rf "$lock"
    mkdir "$lock" 2>/dev/null || die "could not acquire $lock"
  fi
  printf '%s' "$$" > "$lock/pid"
  LOCK_DIR="$lock"
  trap release_workdir_lock EXIT
}

# ---------------------------------------------------------------------------
# the two measurements, and where each one comes from
# ---------------------------------------------------------------------------

# template_policy_hash prints sha256 over the DECODED ccePolicy embedded in the
# ARM template — the artifact that is actually submitted, not a note left
# beside it. This is the value the hardware will report as
# x-ms-sevsnpvm-hostdata.
#
# phase_deploy's guard authenticates THIS, and the distinction is the whole
# guard: $WORKDIR/cce-policy-hash.txt and $WORKDIR/template.json are separate
# files that drift apart easily (a re-run of `template` rewrites the template
# with an empty ccePolicy and leaves the hash file at the previous run's real
# value). A guard that reads the note instead of the artifact passes while the
# template it is about to submit carries a completely different policy — or
# none at all.
template_policy_hash() {
  python3 - "$WORKDIR/template.json" <<'PY'
import base64, hashlib, json, sys

with open(sys.argv[1]) as handle:
    template = json.load(handle)
policy = (template["resources"][0]["properties"]
          ["confidentialComputeProperties"]["ccePolicy"])
if not policy:
    raise SystemExit(
        "[FAIL] the ARM template's confidentialComputeProperties.ccePolicy is EMPTY.\n"
        "  phase_template writes it empty on purpose; the policy phase fills it in.\n"
        "  Deploying this template would create a container group with NO policy, whose\n"
        "  hostdata cannot match anything the SKR key is bound to — an enclave that\n"
        "  attests correctly, is refused by Key Vault with 403, and exits without\n"
        "  restarting. Run the policy phase against this template."
    )
print(hashlib.sha256(base64.b64decode(policy)).hexdigest())
PY
}

# ---------------------------------------------------------------------------
# the container-group environment — ONE definition, three consumers
# ---------------------------------------------------------------------------
# The ARM template, `print-env` (which feeds the sealer) and the operator all
# read this. Two definitions would drift, and a drift here is not a typo: the
# env is measured, so the sealer would validate a bundle for one measurement
# while the deploy ships another.
#
# Printed as JSON so the sealer can consume it without parsing shell.

render_env_json() {
  local mi_client_id="${1:-}"
  python3 - "$mi_client_id" <<'PY'
import json, os, sys

mi_client_id = sys.argv[1]

# Names only. Not one secret VALUE appears in this env: every value below is
# either a coordinate or the NAME of a bundle entry. The values live in the
# encrypted bundle and reach the enclave only under attestation.
env = {
    # --- Azure boot path (bootstrap_azure.go) -----------------------------
    "QUILL_AZURE_MAA_ENDPOINT":  os.environ["MAA_ENDPOINT"],
    "QUILL_AZURE_AKV_ENDPOINT":  os.environ["VAULT"] + ".vault.azure.net",
    "QUILL_AZURE_SKR_KEY_ID":    os.environ["SKR_KEY"],
    "QUILL_AZURE_BUNDLE_SECRET": os.environ["BUNDLE_SECRET"],
    "QUILL_AZURE_SA_KEY_ENTRY":  os.environ["SA_KEY_ENTRY"],
    "QUILL_AZURE_REGION":        os.environ["LOCATION"],
    # --- shared secret-name table (secrets.go) ----------------------------
    "QUILL_GCP_PROJECT_ID":      os.environ["QUILL_GCP_PROJECT_ID"],
    "QUILL_GCP_REGION":          os.environ["LOCATION"],
    "QUILL_DEVICE_KEYS_SECRET":  os.environ["QUILL_DEVICE_KEYS_SECRET"],
    # --- serving ----------------------------------------------------------
    "QUILL_API_HOST":                   os.environ["API_HOST"],
    "QUILL_ACME_EMAIL":                 os.environ["QUILL_ACME_EMAIL"],
    "QUILL_ACME_CACHE_GCS_BUCKET":      os.environ["QUILL_ACME_CACHE_GCS_BUCKET"],
    "QUILL_HEALTH_PORT":                os.environ["QUILL_HEALTH_PORT"],
    "QUILL_FIRST_BYTE_TIMEOUT_SECONDS": os.environ["QUILL_FIRST_BYTE_TIMEOUT_SECONDS"],
    "TR_CONTROL_PLANE_BASE_URL":        os.environ["TR_CONTROL_PLANE_BASE_URL"],
}

# Every QUILL_*_SECRET this deploy configures. Order is irrelevant to the
# enclave (secrets.go decides its own order) but the JSON is sorted below so
# the ARM template — and therefore the CCE policy hash — is stable across runs.
for name in (
    "QUILL_OPENROUTER_SECRET", "QUILL_ANTHROPIC_SECRET", "QUILL_OPENAI_SECRET",
    "QUILL_GEMINI_SECRET", "QUILL_CEREBRAS_SECRET", "QUILL_DEEPSEEK_SECRET",
    "QUILL_MISTRAL_SECRET", "QUILL_KIMI_SECRET", "QUILL_ZAI_SECRET",
    "QUILL_TOGETHER_SECRET", "QUILL_FIREWORKS_SECRET", "QUILL_COHERE_SECRET",
    "QUILL_VOYAGE_SECRET", "QUILL_GROK_SECRET", "QUILL_NOVITA_SECRET",
    "QUILL_PHALA_SECRET", "QUILL_SILICONFLOW_SECRET", "QUILL_TINFOIL_SECRET",
    "QUILL_VENICE_SECRET", "QUILL_PARASAIL_SECRET", "QUILL_LIGHTNING_SECRET",
    "QUILL_GMI_SECRET", "QUILL_DEEPINFRA_SECRET", "QUILL_FRIENDLI_SECRET",
    "QUILL_BASETEN_SECRET", "QUILL_THINKING_MACHINES_SECRET", "QUILL_WAFER_SECRET",
    "QUILL_CRUSOE_SECRET", "QUILL_MAKORA_SECRET", "QUILL_NEBIUS_SECRET",
    "QUILL_MINIMAX_SECRET", "QUILL_XIAOMI_SECRET",
    "QUILL_SYNTH_PANEL_PROMPT_SECRET", "QUILL_SYNTH_SYNTHESIS_PROMPT_SECRET",
    "QUILL_SYNTH_CODE_PANEL_PROMPT_SECRET", "QUILL_SYNTH_CODE_SYNTHESIS_PROMPT_SECRET",
    "QUILL_ADVISOR_WORKER_PROMPT_SECRET", "QUILL_ADVISOR_PROMPT_SECRET",
    "QUILL_TRUSTEDROUTER_INTERNAL_SECRET",
):
    value = os.environ.get(name, "")
    # An empty value is how this deploy says "provider not configured".
    # secrets.go treats "" as unset and skips the entry, so emitting the name
    # with an empty value would only add noise to the measurement.
    if value:
        env[name] = value

# Optional, and both are measured.
version = os.environ.get("QUILL_AZURE_BUNDLE_VERSION", "")
if version:
    env["QUILL_AZURE_BUNDLE_VERSION"] = version
if mi_client_id:
    # IMDS answers 400 "multiple user-assigned identities" if it has to guess,
    # and ACI attaches exactly one here — but naming it is free and removes a
    # whole failure mode if a second is ever attached.
    env["QUILL_AZURE_MI_CLIENT_ID"] = mi_client_id

json.dump(env, sys.stdout, indent=2, sort_keys=True)
sys.stdout.write("\n")
PY
}

# The env vars render_env_json reads out of the process. Exported here so the
# python heredoc sees them.
export MAA_ENDPOINT VAULT SKR_KEY BUNDLE_SECRET SA_KEY_ENTRY LOCATION API_HOST \
  QUILL_GCP_PROJECT_ID QUILL_DEVICE_KEYS_SECRET QUILL_ACME_EMAIL \
  QUILL_ACME_CACHE_GCS_BUCKET QUILL_HEALTH_PORT QUILL_FIRST_BYTE_TIMEOUT_SECONDS \
  TR_CONTROL_PLANE_BASE_URL QUILL_AZURE_BUNDLE_VERSION \
  QUILL_OPENROUTER_SECRET QUILL_ANTHROPIC_SECRET QUILL_OPENAI_SECRET \
  QUILL_GEMINI_SECRET QUILL_CEREBRAS_SECRET QUILL_DEEPSEEK_SECRET \
  QUILL_MISTRAL_SECRET QUILL_KIMI_SECRET QUILL_ZAI_SECRET QUILL_TOGETHER_SECRET \
  QUILL_FIREWORKS_SECRET QUILL_COHERE_SECRET QUILL_VOYAGE_SECRET \
  QUILL_GROK_SECRET QUILL_NOVITA_SECRET QUILL_PHALA_SECRET \
  QUILL_SILICONFLOW_SECRET QUILL_TINFOIL_SECRET QUILL_VENICE_SECRET \
  QUILL_PARASAIL_SECRET QUILL_LIGHTNING_SECRET QUILL_GMI_SECRET \
  QUILL_DEEPINFRA_SECRET QUILL_FRIENDLI_SECRET QUILL_BASETEN_SECRET \
  QUILL_THINKING_MACHINES_SECRET QUILL_WAFER_SECRET QUILL_CRUSOE_SECRET \
  QUILL_MAKORA_SECRET QUILL_NEBIUS_SECRET QUILL_MINIMAX_SECRET \
  QUILL_XIAOMI_SECRET QUILL_SYNTH_PANEL_PROMPT_SECRET \
  QUILL_SYNTH_SYNTHESIS_PROMPT_SECRET QUILL_SYNTH_CODE_PANEL_PROMPT_SECRET \
  QUILL_SYNTH_CODE_SYNTHESIS_PROMPT_SECRET QUILL_ADVISOR_WORKER_PROMPT_SECRET \
  QUILL_ADVISOR_PROMPT_SECRET QUILL_TRUSTEDROUTER_INTERNAL_SECRET

warn_unpinned_bundle() {
  if [ -z "$QUILL_AZURE_BUNDLE_VERSION" ]; then
    log "WARNING: QUILL_AZURE_BUNDLE_VERSION is unset."
    note "The enclave will read the CURRENT version of secret '$BUNDLE_SECRET'."
    note "SKR gates WHO can open the bundle, never WHICH bundle is opened, so anyone"
    note "holding secrets/set on $VAULT can substitute or roll back the entire secret"
    note "set and the next cold start picks it up. Pin a version (see the header)."
  fi
}

resolve_mi_client_id() {
  if [ -n "${QUILL_AZURE_MI_CLIENT_ID:-}" ]; then
    printf '%s' "$QUILL_AZURE_MI_CLIENT_ID"
    return
  fi
  az_cli identity show --resource-group "$RESOURCE_GROUP" --name "$IDENTITY_NAME" \
    --query clientId -o tsv 2>/dev/null || true
}

resolve_mi_resource_id() {
  az_cli identity show --resource-group "$RESOURCE_GROUP" --name "$IDENTITY_NAME" \
    --query id -o tsv 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# phase: build
# ---------------------------------------------------------------------------
# `az acr build --platform linux/amd64` matters twice over. SEV-SNP is x86-64,
# so amd64 is the hardware requirement; and it produces a SINGLE-ARCH image,
# which acipolicygen requires — Docker 29's containerd image store reports
# platform "/" for a multi-arch manifest and confcom rejects it outright.
phase_build() {
  require_tool az
  mkdir -p "$WORKDIR"
  local previous_digest=""
  previous_digest="$(cat "$WORKDIR/image-digest.txt" 2>/dev/null || true)"

  # REUSE_IMAGE=1 skips the build and keeps the digest already in the workdir.
  #
  # It exists because a re-run with no source change is NOT guaranteed to be a
  # no-op: IMAGE_TAG is minted from a fresh timestamp on every invocation and
  # `az acr build` runs unconditionally, so whether "nothing changed" survives
  # to the deploy depends entirely on whether ACR produces a byte-identical
  # manifest — and an OCI image config carries a `created` timestamp. If the
  # digest moves, the template moves, the CCE policy moves, and phase_deploy
  # correctly DELETES AND RECREATES production for a source tree that did not
  # change. This flag is the escape hatch; the log line below is the warning.
  if [ "${REUSE_IMAGE:-0}" = "1" ] && [ -n "$previous_digest" ]; then
    log "phase build: REUSE_IMAGE=1 — skipping the build, keeping $previous_digest"
    return 0
  fi

  log "phase build: $ACR/$IMAGE_REPO:$IMAGE_TAG (linux/amd64, single-arch)"
  az_rw acr build \
    --registry "$ACR" \
    --platform linux/amd64 \
    --image "${IMAGE_REPO}:${IMAGE_TAG}" \
    --file enclave-go/Dockerfile.enclave.azure.multi \
    "$REPO_ROOT/enclave-go"

  local digest=""
  if [ "$APPLY" = "1" ]; then
    digest="$(az_cli acr repository show --name "$ACR" \
      --image "${IMAGE_REPO}:${IMAGE_TAG}" --query digest -o tsv)"
    [ -n "$digest" ] || die "could not resolve the digest of ${IMAGE_REPO}:${IMAGE_TAG}"
  else
    # Dry-run still has to produce a template, and a template needs A digest.
    # A placeholder is used ONLY here and is impossible to mistake for real.
    digest="sha256:DRYRUN0000000000000000000000000000000000000000000000000000000000"
  fi
  printf '%s' "$digest" > "$WORKDIR/image-digest.txt"
  log "image digest: $digest"
  if [ -n "$previous_digest" ] && [ "$previous_digest" != "$digest" ]; then
    log "image digest CHANGED since the last run in this workdir"
    note "was: $previous_digest"
    note "now: $digest"
    note "The digest is measured, so this alone re-binds the SKR key and forces a"
    note "DELETE + RECREATE of the container group. If the source tree did not change,"
    note "the rebuild moved the digest on its own; re-run with REUSE_IMAGE=1 to avoid"
    note "churning production for a build that produced the same code."
  fi

  # The image is pinned BY DIGEST in the template, never by tag. A tag is a
  # mutable pointer; the CCE policy measures whatever the tag resolved to at
  # policy-generation time, so a tag that moves between `policy` and `deploy`
  # ships an image the key's release policy does not trust.
}

# ---------------------------------------------------------------------------
# phase: template
# ---------------------------------------------------------------------------
phase_template() {
  mkdir -p "$WORKDIR"
  [ -f "$WORKDIR/image-digest.txt" ] || die "run the build phase first (no $WORKDIR/image-digest.txt)"
  local digest mi_client_id mi_resource_id
  digest="$(cat "$WORKDIR/image-digest.txt")"
  mi_client_id="$(resolve_mi_client_id)"
  mi_resource_id="$(resolve_mi_resource_id)"
  if [ -z "$mi_resource_id" ]; then
    if [ "$APPLY" = "1" ]; then
      die "user-assigned identity '$IDENTITY_NAME' not found in '$RESOURCE_GROUP' — it is a prerequisite (see the header)"
    fi
    mi_resource_id="/subscriptions/DRYRUN/resourcegroups/${RESOURCE_GROUP}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/${IDENTITY_NAME}"
  fi

  render_env_json "$mi_client_id" > "$WORKDIR/container-env.json"
  log "phase template: $(python3 -c 'import json,sys;print(len(json.load(open(sys.argv[1]))))' "$WORKDIR/container-env.json") env vars, all measured"

  ACR_LOGIN_SERVER="${ACR_LOGIN_SERVER:-${ACR}.azurecr.io}" \
  IMAGE_DIGEST="$digest" MI_RESOURCE_ID="$mi_resource_id" \
  CONTAINER_GROUP="$CONTAINER_GROUP" DNS_LABEL="$DNS_LABEL" \
  IMAGE_REPO="$IMAGE_REPO" SKR_IMAGE="$SKR_IMAGE" SKR_COMMAND="$SKR_COMMAND" \
  SKR_CERT_CACHE_ENDPOINT="$SKR_CERT_CACHE_ENDPOINT" \
  ENCLAVE_CPU="$ENCLAVE_CPU" ENCLAVE_MEMORY_GB="$ENCLAVE_MEMORY_GB" \
  SKR_CPU="$SKR_CPU" SKR_MEMORY_GB="$SKR_MEMORY_GB" \
  QUILL_HEALTH_PORT="$QUILL_HEALTH_PORT" LOCATION="$LOCATION" \
  python3 - "$WORKDIR/container-env.json" "$WORKDIR/template.json" <<'PY'
import base64, json, os, sys

env_path, out_path = sys.argv[1], sys.argv[2]
with open(env_path) as handle:
    container_env = json.load(handle)

# The skr sidecar's own configuration. base64 of a JSON blob, per Microsoft's
# confidential-container samples; it tells the sidecar which certificate cache
# to fetch the AMD VCEK chain from.
skr_args = base64.b64encode(json.dumps({
    "certcache": {
        "endpoint": os.environ["SKR_CERT_CACHE_ENDPOINT"],
        "tee_type": "SevSnpVM",
        "api_version": "api-version=2020-10-15-preview",
    }
}).encode()).decode()

health_port = int(os.environ["QUILL_HEALTH_PORT"])
image = f'{os.environ["ACR_LOGIN_SERVER"]}/{os.environ["IMAGE_REPO"]}@{os.environ["IMAGE_DIGEST"]}'

skr_container = {
    "name": "skr-sidecar",
    "properties": {
        "image": os.environ["SKR_IMAGE"],
        # The sidecar is reached ONLY over the container group's loopback, on
        # 8080. It is deliberately absent from ipAddress.ports below:
        # bootstrap_azure.go refuses any non-loopback SKR URL precisely because
        # an off-box key-release endpoint would evaporate the whole attestation
        # gate, and exposing this port publicly would be the other half of that
        # mistake.
        "environmentVariables": [{"name": "SkrSideCarArgs", "value": skr_args}],
        "resources": {"requests": {
            "cpu": float(os.environ["SKR_CPU"]),
            "memoryInGB": float(os.environ["SKR_MEMORY_GB"]),
        }},
    },
}
command = os.environ.get("SKR_COMMAND", "").strip()
if command:
    # Part of the measurement. Empty means "use the image's own entrypoint".
    skr_container["properties"]["command"] = [command]

enclave_container = {
    "name": "quill-enclave",
    "properties": {
        "image": image,
        "ports": [{"protocol": "TCP", "port": 443}, {"protocol": "TCP", "port": health_port}],
        "environmentVariables": [
            {"name": name, "value": value}
            for name, value in sorted(container_env.items())
        ],
        "resources": {"requests": {
            "cpu": float(os.environ["ENCLAVE_CPU"]),
            "memoryInGB": float(os.environ["ENCLAVE_MEMORY_GB"]),
        }},
    },
}

template = {
    "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
    "contentVersion": "1.0.0.0",
    "resources": [{
        "type": "Microsoft.ContainerInstance/containerGroups",
        "apiVersion": "2023-05-01",
        "name": os.environ["CONTAINER_GROUP"],
        "location": os.environ["LOCATION"],
        "identity": {
            "type": "UserAssigned",
            "userAssignedIdentities": {os.environ["MI_RESOURCE_ID"]: {}},
        },
        "properties": {
            "osType": "Linux",
            # Confidential is the whole point: it is what puts the workload on
            # SEV-SNP hardware and makes a CCE policy meaningful.
            "sku": "Confidential",
            "confidentialComputeProperties": {
                # Filled in by `az confcom acipolicygen` in the policy phase.
                # Left EMPTY here on purpose: a stale policy string copied
                # forward from a previous build is the failure this script
                # exists to prevent, and an empty one fails loudly.
                "ccePolicy": ""
            },
            # Never. A confidential container group that restarts re-runs the
            # SNP report and the MAA exchange on every attempt; if the release
            # policy does not match, that is an unbounded attestation
            # crash-loop against Key Vault rather than one clear failure.
            "restartPolicy": "Never",
            "imageRegistryCredentials": [{
                "server": os.environ["ACR_LOGIN_SERVER"],
                # Identity-based, not username/password. The ARM template is an
                # input to the CCE policy AND is retained in the resource
                # group's deployment history, so a registry password here would
                # be both measured and archived in plaintext. The identity needs
                # AcrPull on the registry.
                "identity": os.environ["MI_RESOURCE_ID"],
            }],
            "ipAddress": {
                "type": "Public",
                "ports": [
                    {"protocol": "TCP", "port": 443},
                    {"protocol": "TCP", "port": health_port},
                ],
                # A stable FQDN across recreates. The public IP changes whenever
                # the group is recreated (which every measured change forces),
                # so point api-* at THIS name with a CNAME, never at the IP.
                "dnsNameLabel": os.environ["DNS_LABEL"],
            },
            "containers": [skr_container, enclave_container],
        },
    }],
    "outputs": {
        "ip":   {"type": "string", "value": f"[reference(resourceId('Microsoft.ContainerInstance/containerGroups', '{os.environ['CONTAINER_GROUP']}')).ipAddress.ip]"},
        "fqdn": {"type": "string", "value": f"[reference(resourceId('Microsoft.ContainerInstance/containerGroups', '{os.environ['CONTAINER_GROUP']}')).ipAddress.fqdn]"},
    },
}

with open(out_path, "w") as handle:
    json.dump(template, handle, indent=2)
    handle.write("\n")
print(f"[ok] wrote {out_path}")
PY
  log "template: $WORKDIR/template.json (ccePolicy empty, filled by the policy phase)"
}

# ---------------------------------------------------------------------------
# phase: policy
# ---------------------------------------------------------------------------
# `az confcom acipolicygen` is LINUX-ONLY, so it runs inside a container with
# the docker socket mounted — it pulls and inspects the image layers to build
# the policy, which needs a real docker daemon.
#
# ~/.azure is mounted so the tool can reach a private ACR; `az acr login` first
# so the DAEMON has the pull credential (the tool pulls through docker, not
# through the CLI).
phase_policy() {
  require_tool docker
  [ -f "$WORKDIR/template.json" ] || die "run the template phase first (no $WORKDIR/template.json)"

  log "phase policy: generating the CCE policy (this pulls the image; it takes a few minutes)"
  az_rw acr login --name "$ACR"

  local confcom_image="${CONFCOM_IMAGE:-mcr.microsoft.com/azure-cli:latest}"
  case "$confcom_image" in
    *@sha256:*) ;;
    *) log "NOTE: CONFCOM_IMAGE is $confcom_image — an unpinned tag feeding a"
       note "measurement-generating step. Pin it by digest for a reproducible policy." ;;
  esac
  if [ "$APPLY" = "1" ] && [ ! -d "${HOME}/.azure" ]; then
    die "${HOME}/.azure does not exist — run 'az login' first. (Letting docker create it
       would make the operator's own credential directory root-owned.)"
  fi

  # ~/.azure is the operator's Azure CREDENTIAL STORE: on Linux it holds
  # msal_token_cache.json in plaintext whenever no keyring backend is present.
  # This container also gets the host docker socket, which is already root on
  # the host, so mounting the credential store WRITABLE buys nothing and costs
  # the ability to overwrite the operator's refresh tokens.
  #
  # It is therefore mounted READ-ONLY at a side path and copied into a config
  # dir inside the container's own ephemeral (--rm) filesystem. The copy is not
  # ceremony — it is what makes read-only workable, twice over:
  #
  #   * az writes commandIndex.json / versionCheck.json / logs into
  #     AZURE_CONFIG_DIR on almost every invocation and errors against a
  #     read-only mount;
  #   * `az extension add --name confcom` installs into
  #     $AZURE_CONFIG_DIR/cliextensions. With ~/.azure bound there directly,
  #     a container running as uid 0 creates ROOT-OWNED files inside the
  #     operator's own config directory, and the operator's next host-side `az`
  #     fails with EACCES on its own config. (Docker Desktop on macOS remaps
  #     ownership and hides this; a Linux host or CI runner does not.)
  #   * the copied config's cliextensions are DELETED before installing. confcom
  #     ships NATIVE wheels (pydantic_core), so a host-built extension copied into
  #     this Linux container dies with
  #     "ModuleNotFoundError: No module named 'pydantic_core._pydantic_core'" —
  #     an error that names neither Azure nor the policy and sends you looking in
  #     the wrong place. Credentials are what we want from the host config; the
  #     extension must be installed for the container's own platform.
  # --platform is explicit: confcom only ships linux/amd64, and on an arm64
  # workstation docker would otherwise emulate or refuse, after the pull.
  run docker run --rm --platform linux/amd64 \
    -e AZURE_CONFIG_DIR=/azure-config \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v "$WORKDIR:/work" \
    -v "${HOME}/.azure:/azure-config-ro:ro" \
    "$confcom_image" \
    sh -c 'mkdir -p /azure-config \
      && cp -a /azure-config-ro/. /azure-config/ \
      && rm -rf /azure-config/cliextensions \
      && { az extension add --name confcom --yes >/dev/null 2>&1 || true; } \
      && az confcom acipolicygen --template-file /work/template.json -y' \
    2>&1 | tee "$WORKDIR/acipolicygen.log"

  if [ "$APPLY" != "1" ]; then
    # A placeholder so the remaining phases can be walked through offline. It is
    # deliberately not hex-shaped: nothing downstream can mistake it for a real
    # measurement, and `bind` under --apply would refuse it on readback.
    printf 'DRY-RUN-NO-POLICY-GENERATED' > "$WORKDIR/cce-policy-hash.txt"
    log "dry-run: no policy generated; wrote a placeholder hash so the later phases can be reviewed"
    return 0
  fi

  # HOST_DATA is sha256 over the DECODED rego policy text. Derived from the
  # template rather than scraped, because a hash we cannot reproduce is a hash
  # we cannot audit — and derived by the SAME function phase_deploy's guard
  # uses, so the two can never disagree about what this template measures.
  # Derivation is still not proof: the `verify` phase compares it against the
  # hostdata in a real MAA token, which is the only ground truth there is.
  local computed
  computed="$(template_policy_hash)" \
    || die "acipolicygen did not populate confidentialComputeProperties.ccePolicy — see above"
  printf '%s' "$computed" > "$WORKDIR/cce-policy-hash.txt"

  # Cross-check against the hash confcom printed. If the tool and this
  # derivation disagree, STOP: binding the wrong one produces an enclave that
  # cannot boot and a failure that points nowhere.
  #
  # Both sides are lowercased before comparing. They are the same 256-bit value
  # either way, and comparing them case-SENSITIVELY while scraping
  # case-INSENSITIVELY meant an acipolicygen build that prints uppercase hex
  # would refuse to bind for ever, on every deploy, over nothing.
  #
  # The scrape is also anchored to a line that mentions a hash: dm-verity layer
  # roots are 64-hex too, and `head -1` over every hex token in the log is one
  # confcom log-format change away from cross-checking against the wrong number.
  local scraped
  scraped="$(grep -iE 'hash' "$WORKDIR/acipolicygen.log" 2>/dev/null \
    | grep -oiE '\b[0-9a-f]{64}\b' | head -1 | tr '[:upper:]' '[:lower:]' || true)"
  if [ -z "$scraped" ]; then
    log "NOTE: acipolicygen printed no hash-labelled 64-hex value; cross-check skipped."
    note "The derived hash stands unconfirmed until the verify phase attests it."
  elif [ "$scraped" != "$computed" ]; then
    die "acipolicygen printed hash $scraped but sha256(decoded ccePolicy) is $computed.
       Refusing to bind either. One of them is what the hardware will report in
       x-ms-sevsnpvm-hostdata and binding the other guarantees a 403 at boot.
       Inspect $WORKDIR/acipolicygen.log."
  fi
  log "CCE policy hash: $computed"
}

# ---------------------------------------------------------------------------
# phase: bind  — THE STEP EVERY BROKEN AZURE DEPLOY SKIPPED
# ---------------------------------------------------------------------------
# Re-point the SKR key's release policy at the hash of the policy we are ABOUT
# to deploy. This must happen BEFORE the container group is created: an enclave
# that comes up against a stale binding attests fine, is refused by Key Vault,
# and exits with no restart (restartPolicy=Never) — a deploy that looks like a
# crash.
phase_bind() {
  [ -f "$WORKDIR/cce-policy-hash.txt" ] || die "run the policy phase first (no $WORKDIR/cce-policy-hash.txt)"
  local hash
  hash="$(cat "$WORKDIR/cce-policy-hash.txt")"

  # Read the pin we are about to change BEFORE changing it, and keep it.
  #
  # Until this existed, the old value survived in exactly one place — the key's
  # own release policy — and this phase overwrote it. Which meant that from the
  # moment `bind` succeeded, the measurement of the RUNNING enclave was
  # unrecoverable, and the very next step deletes that enclave. An ARM create
  # that then fails for an ordinary reason leaves nothing to go back to.
  local previous_set=""
  if [ "$APPLY" = "1" ]; then
    previous_set="$(bound_hostdata)"
  fi

  # `baseline` is the pin set as it stood BEFORE this deploy opened its window —
  # read from previous-hostdata.txt when a window is already open, so binding
  # three times without a narrow widens from the same baseline instead of
  # accumulating every intermediate hash into the release policy.
  local baseline=""
  if [ -f "$WORKDIR/previous-hostdata.txt" ]; then
    baseline="$(grep -v '^$' "$WORKDIR/previous-hostdata.txt" || true)"
  elif [ -n "$previous_set" ] && ! printf '%s\n' "$previous_set" | grep -qxF "$hash"; then
    baseline="$previous_set"
    printf '%s\n' "$previous_set" > "$WORKDIR/previous-hostdata.txt"
    log "recorded the outgoing pin in $WORKDIR/previous-hostdata.txt (for 'rollback')"
  fi

  # The window: {what the key accepted before this deploy} + {what we are
  # deploying}. `narrow` closes it after `verify` proves the new workload.
  local wanted
  wanted="$(printf '%s\n%s\n' "$baseline" "$hash" | grep -v '^$' | sort -u)"
  write_release_policy "$wanted"
  log "phase bind: $SKR_KEY in $VAULT -> hostdata {$(printf '%s' "$wanted" | tr '\n' ' ')}"
  apply_release_policy "$wanted"
}

# ---------------------------------------------------------------------------
# phase: narrow  — close the rolling window
# ---------------------------------------------------------------------------
# Run AFTER verify. Leaving the old hostdata pinned indefinitely would mean the
# key keeps releasing to a measurement nobody is running and nobody is watching
# — a workload that could be resurrected from an old image and would boot with
# every current secret.
phase_narrow() {
  [ -f "$WORKDIR/template.json" ] || die "run the template phase first"
  local hash
  hash="$(template_policy_hash)" || die "cannot narrow: this template has no CCE policy"
  log "phase narrow: $SKR_KEY in $VAULT -> hostdata $hash only"
  write_release_policy "$hash"
  apply_release_policy "$hash"
  rm -f "$WORKDIR/previous-hostdata.txt"
}

# ---------------------------------------------------------------------------
# phase: rollback — put the pin back where bind found it
# ---------------------------------------------------------------------------
# The counterpart to bind. It restores the key's release policy to the set that
# was in force before the last bind, so a deploy that died between `bind` and a
# healthy `verify` can be undone rather than reasoned about.
#
# It cannot bring the deleted container group back — nothing can, without the
# previous image — but it restores the pin, so redeploying the PREVIOUS image
# is an ordinary deploy instead of an archaeology exercise.
phase_rollback() {
  [ -f "$WORKDIR/previous-hostdata.txt" ] \
    || die "no $WORKDIR/previous-hostdata.txt — nothing to roll back to.
       bind writes it only when it actually changes the pin, so either bind has
       not run in this workdir or narrow has already closed the window."
  local previous
  previous="$(grep -v '^$' "$WORKDIR/previous-hostdata.txt" || true)"
  [ -n "$previous" ] || die "$WORKDIR/previous-hostdata.txt is empty"
  log "phase rollback: $SKR_KEY in $VAULT -> hostdata {$(printf '%s' "$previous" | tr '\n' ' ')}"
  note "this restores the KEY only; the container group must be redeployed from the previous image"
  write_release_policy "$previous"
  apply_release_policy "$previous"
}

# write_release_policy renders $WORKDIR/release-policy.json for a SET of
# hostdata values, one anyOf clause each.
#
# These four claims are the gate, and they are the same four
# bootstrap_azure.go documents. hostdata alone would let any SEV-SNP guest with
# a matching policy through; the other three establish that it is a genuine,
# non-debuggable, Azure-compliant confidential VM.
#
# `authority` is the ONE MAA instance we trust to sign. *.attest.azure.net is a
# namespace every Azure tenant can join, not an authority — the same reason
# verify-attestation.py makes --expected-maa-issuer mandatory.
write_release_policy() {
  local hostdata_set="$1"
  # The values travel in argv, not on stdin: `python3 -` already takes its
  # SCRIPT from stdin via the heredoc, so a pipe here would be silently eaten
  # and every policy would pin nothing.
  local -a values=()
  local line
  while IFS= read -r line; do
    [ -n "$line" ] && values+=("$line")
  done <<< "$hostdata_set"
  [ "${#values[@]}" -gt 0 ] || die "refusing to write a release policy that pins no hostdata at all"
  python3 - "$WORKDIR/release-policy.json" "$MAA_ENDPOINT" "${values[@]}" <<'PY'
import json, sys

out_path, maa = sys.argv[1], sys.argv[2]
hostdata = [value.strip() for value in sys.argv[3:] if value.strip()]
if not hostdata:
    raise SystemExit("[FAIL] refusing to write a release policy that pins no hostdata at all")
policy = {
    "version": "1.0.0",
    "anyOf": [
        {
            "authority": f"https://{maa}",
            "allOf": [
                {"claim": "x-ms-attestation-type",       "equals": "sevsnpvm"},
                {"claim": "x-ms-compliance-status",      "equals": "azure-compliant-uvm"},
                {"claim": "x-ms-sevsnpvm-is-debuggable", "equals": "false"},
                {"claim": "x-ms-sevsnpvm-hostdata",      "equals": value},
            ],
        }
        for value in hostdata
    ],
}
with open(out_path, "w") as handle:
    json.dump(policy, handle, indent=2)
    handle.write("\n")
print(f"[ok] wrote {out_path} pinning {len(hostdata)} hostdata value(s)")
PY
}

# apply_release_policy pushes $WORKDIR/release-policy.json and reads it back.
apply_release_policy() {
  local wanted="$1"
  if [ "$APPLY" != "1" ]; then
    run az keyvault key set-attributes --vault-name "$VAULT" --name "$SKR_KEY" \
      --policy "$WORKDIR/release-policy.json"
    return 0
  fi
  # --policy is the current spelling; older azure-cli builds call the same
  # thing --release-policy. Try both rather than fail on a CLI version.
  if ! az_cli keyvault key set-attributes --vault-name "$VAULT" --name "$SKR_KEY" \
      --policy "$WORKDIR/release-policy.json" -o none 2>/dev/null; then
    az_cli keyvault key set-attributes --vault-name "$VAULT" --name "$SKR_KEY" \
      --release-policy "$WORKDIR/release-policy.json" -o none \
      || die "could not update the release policy of $SKR_KEY (needs Key Vault Crypto Officer on $VAULT)"
  fi

  # Read it back. A set-attributes that succeeded against the wrong key
  # version, or that a policy-immutable key silently ignored, is
  # indistinguishable from success at the CLI — and the symptom is a 403 four
  # minutes later.
  local bound
  bound="$(bound_hostdata)"
  if [ "$(printf '%s\n' "$bound" | sort -u)" != "$(printf '%s\n' "$wanted" | sort -u)" ]; then
    die "release policy readback mismatch.
       the key now pins : $(printf '%s' "$bound" | tr '\n' ' ')
       wanted           : $(printf '%s' "$wanted" | tr '\n' ' ')"
  fi
  log "bound and verified: $SKR_KEY releases to $(printf '%s' "$bound" | tr '\n' ' ')"
}

# bound_hostdata prints EVERY hostdata value the KEY currently accepts, one per
# line. This is the authority on what the deploy must measure — not our local
# hash file. It is a set rather than a single value because bind deliberately
# widens it for the duration of a deploy; see the header.
bound_hostdata() {
  az_cli keyvault key show --vault-name "$VAULT" --name "$SKR_KEY" \
    --query "releasePolicy.encodedPolicy" -o tsv 2>/dev/null \
  | python3 -c '
import base64, json, sys
raw = sys.stdin.read().strip()
if not raw:
    sys.exit(0)
raw += "=" * (-len(raw) % 4)
policy = json.loads(base64.urlsafe_b64decode(raw))
seen = []
for clause in policy.get("anyOf", []):
    for claim in clause.get("allOf", []):
        if claim.get("claim") == "x-ms-sevsnpvm-hostdata":
            value = claim.get("equals", "")
            if value and value not in seen:
                seen.append(value)
for value in seen:
    print(value)
'
}

# ---------------------------------------------------------------------------
# phase: deploy
# ---------------------------------------------------------------------------
phase_deploy() {
  [ -f "$WORKDIR/template.json" ] || die "run the template phase first"

  # THE GUARD AUTHENTICATES THE ARTIFACT IT IS ABOUT TO SUBMIT.
  #
  # `hash` is derived from template.json — the exact bytes handed to
  # `az deployment group create` below — and NOT from $WORKDIR/cce-policy-hash.txt.
  # That file is a side note, and it desynchronizes from the template easily:
  # re-running `template` rewrites the template with an EMPTY ccePolicy while
  # leaving the hash file at the previous run's real value. A guard reading the
  # note then compares the old hash to the key's old pin, passes, and deletes a
  # healthy production group to replace it with one carrying no policy at all —
  # which cannot attest to anything and, under restartPolicy=Never, never comes
  # back. template_policy_hash() also refuses an empty policy outright.
  local hash
  hash="$(template_policy_hash)" \
    || die "REFUSING TO DEPLOY: see above. Run the policy phase against this template."

  # Refuse to create a group the key cannot serve. This is the trap stated as a
  # precondition instead of discovered as a symptom.
  if [ "$APPLY" = "1" ]; then
    local bound
    bound="$(bound_hostdata)"
    if [ -z "$bound" ]; then
      die "key $SKR_KEY in $VAULT has no hostdata pin in its release policy — run the bind phase"
    fi
    # Membership, not equality: bind deliberately widens the pin to {old, new}
    # for the duration of the deploy.
    if ! printf '%s\n' "$bound" | grep -qxF "$hash"; then
      die "REFUSING TO DEPLOY: the key expects a different workload.
       key '$SKR_KEY' releases to hostdata : $(printf '%s' "$bound" | tr '\n' ' ')
       this TEMPLATE measures              : $hash
       Creating this container group now yields an enclave that attests correctly,
       is refused by Key Vault with 403, and exits without restarting. Run the
       policy and bind phases against the CURRENT template first."
    fi
  fi

  # A confidential container group's measured surface cannot be updated in
  # place — image, env and ccePolicy are fixed at creation. So when anything
  # measured changed, the group is deleted and recreated. When nothing changed,
  # this is a no-op, which is what makes re-running the script safe.
  #
  # "no such group" and "the CLI failed" are NOT the same fact, and only one of
  # them is safe. Collapsing both into an empty string makes an expired token
  # look like a fresh region: the delete is skipped and the create becomes a PUT
  # over a LIVE confidential group whose measured surface cannot change in
  # place. Since `bind` has already re-pointed the key by this point, the update
  # errors out and leaves the old group running on the old measurement while the
  # key pins the new one — fine until the next cold start, then dead. So the
  # group is probed explicitly and anything that is not a clean "does not exist"
  # is fatal.
  local group_json="" show_rc=0
  group_json="$(az_cli container show --resource-group "$RESOURCE_GROUP" --name "$CONTAINER_GROUP" \
    -o json 2>"$WORKDIR/container-show.err")" || show_rc=$?
  local group_exists=0
  if [ "$show_rc" = "0" ] && [ -n "$group_json" ]; then
    group_exists=1
  elif grep -qiE 'ResourceNotFound|was not found|could not be found|does not exist' \
       "$WORKDIR/container-show.err" 2>/dev/null; then
    group_exists=0
  else
    die "could not determine whether container group $CONTAINER_GROUP exists (az exited $show_rc).
       Treating that as 'no group' would skip the delete and turn the create into an
       in-place update of a live confidential group, which cannot change its measured
       surface — and the key has already been re-bound. Fix the CLI error and re-run:
$(sed 's/^/       /' "$WORKDIR/container-show.err" 2>/dev/null | head -5)"
  fi

  local desired_policy
  desired_policy="$(python3 -c '
import json,sys
with open(sys.argv[1]) as h:
    print(json.load(h)["resources"][0]["properties"]["confidentialComputeProperties"]["ccePolicy"])
' "$WORKDIR/template.json")"

  if [ "$group_exists" = "1" ]; then
    local deployed_policy
    deployed_policy="$(printf '%s' "$group_json" | python3 -c '
import json,sys
doc = json.load(sys.stdin)
print((doc.get("confidentialComputeProperties") or {}).get("ccePolicy") or "")
' 2>/dev/null || true)"
    if [ -n "$deployed_policy" ] && [ "$deployed_policy" = "$desired_policy" ]; then
      log "phase deploy: container group $CONTAINER_GROUP already runs this exact policy — nothing to do"
      return 0
    fi
    if [ -z "$deployed_policy" ]; then
      # The group exists but ACI did not echo its policy back. Recreate rather
      # than assume: an in-place update of a confidential group is the one
      # thing that definitely does not work.
      log "phase deploy: $CONTAINER_GROUP exists but reports no ccePolicy; recreating rather than updating in place"
    else
      log "phase deploy: measured definition changed; deleting $CONTAINER_GROUP before recreating"
    fi
    note "the public IP will change — this is why api-* must be a CNAME to the dnsNameLabel FQDN"
    az_rw container delete --resource-group "$RESOURCE_GROUP" --name "$CONTAINER_GROUP" --yes
  fi

  log "phase deploy: creating $CONTAINER_GROUP in $RESOURCE_GROUP"
  # $$ disambiguates two runs that start in the same second; the lock makes that
  # rare, but an ARM deployment name collision is a confusing way to find out.
  az_rw deployment group create \
    --resource-group "$RESOURCE_GROUP" \
    --name "quill-enclave-$(date -u +%Y%m%d%H%M%S)-$$" \
    --template-file "$WORKDIR/template.json" \
    --output none
}

# ---------------------------------------------------------------------------
# phase: verify — a deploy that cannot prove its own measurement is not a deploy
# ---------------------------------------------------------------------------
phase_verify() {
  if [ "$APPLY" != "1" ]; then
    log "phase verify: dry-run — would wait for the group, then attest with"
    note "tools/verify-attestation.py --api-host $API_HOST --expected-maa-issuer https://$MAA_ENDPOINT --expected-hostdata <bound>"
    return 0
  fi
  require_tool python3
  require_tool curl

  # What the key ACCEPTS comes from Key Vault; what this deploy SHIPPED comes
  # from the template. The check is membership, because bind widens the pin to
  # {old, new} for the duration of a deploy — but the attestation is then held
  # to the single hash of the template we submitted, so "the key would also
  # accept the previous workload" can never stand in for "the new workload
  # attested".
  local accepted expected_hostdata
  accepted="$(bound_hostdata)"
  [ -n "$accepted" ] || die "key $SKR_KEY has no hostdata pin; nothing to verify against"
  expected_hostdata="$(template_policy_hash)" \
    || die "cannot verify: this workspace's template has no CCE policy"
  if ! printf '%s\n' "$accepted" | grep -qxF "$expected_hostdata"; then
    die "the key accepts {$(printf '%s' "$accepted" | tr '\n' ' ')} but this workspace's template
       measures $expected_hostdata — the deployed group and the key disagree."
  fi

  log "phase verify: waiting for $CONTAINER_GROUP to run"
  local state="" ip="" fqdn="" waited=0
  while [ "$waited" -lt "${VERIFY_TIMEOUT_SECONDS:-600}" ]; do
    state="$(az_cli container show --resource-group "$RESOURCE_GROUP" --name "$CONTAINER_GROUP" \
      --query "instanceView.state" -o tsv 2>/dev/null || true)"
    ip="$(az_cli container show --resource-group "$RESOURCE_GROUP" --name "$CONTAINER_GROUP" \
      --query "ipAddress.ip" -o tsv 2>/dev/null || true)"
    fqdn="$(az_cli container show --resource-group "$RESOURCE_GROUP" --name "$CONTAINER_GROUP" \
      --query "ipAddress.fqdn" -o tsv 2>/dev/null || true)"
    case "$state" in
      Running) break ;;
      # Succeeded and Stopped are the states of the failure this whole script
      # exists to prevent. `Terminated` is a CONTAINER state, not a group state:
      # a group whose containers exited under restartPolicy=Never reports
      # Succeeded — which is exactly what a Key Vault 403 at boot looks like from
      # the outside. Listing only Failed|Terminated meant the 403 was the one
      # path that spun the full timeout in silence and then died without ever
      # dumping the log that says "http 403".
      Failed|Terminated|Succeeded|Stopped)
        phase_logs
        die "container group state is '$state'. If the enclave log shows a Key Vault 403, the
       release policy does not match this workload's measurement: re-run the policy
       and bind phases, then redeploy. The key currently accepts $(printf '%s' "$accepted" | tr '\n' ' ')." ;;
    esac
    sleep 10
    waited=$((waited + 10))
  done
  if [ "$state" != "Running" ]; then
    phase_logs
    die "container group did not reach Running within ${VERIFY_TIMEOUT_SECONDS:-600}s (state='$state').
       The container logs are above — a Key Vault 403 there means this workload's
       measurement is not one the key accepts ($(printf '%s' "$accepted" | tr '\n' ' '))."
  fi
  log "running at $ip (fqdn $fqdn)"

  cat >&2 <<EOF

  DNS: $API_HOST must resolve to this group for TLS-ALPN-01 to issue a cert.
       Point it at the STABLE name, not the IP:
           $API_HOST  CNAME  $fqdn

EOF

  log "waiting for the enclave to serve /attestation on $API_HOST"
  waited=0
  until curl -fsS --max-time 10 --resolve "${API_HOST}:443:${ip}" \
        "https://${API_HOST}/attestation" -o /dev/null 2>/dev/null; do
    if [ "$waited" -ge "${VERIFY_TIMEOUT_SECONDS:-600}" ]; then
      phase_logs
      die "the enclave never served /attestation. A Key Vault 403 in the log above means the
       measurement and the key's pin ($expected_hostdata) disagree."
    fi
    sleep 10
    waited=$((waited + 10))
  done

  # BOTH Azure pins are mandatory and neither is optional theatre:
  #   --expected-maa-issuer  because *.attest.azure.net is a namespace every
  #                          Azure tenant can join, not an authority
  #   --expected-hostdata    because MAA re-attests ANY caller's hardware report,
  #                          so "our instance signed it" does not mean "it
  #                          describes our workload"
  log "verifying the live attestation against the pin the KEY requires"
  python3 "$REPO_ROOT/tools/verify-attestation.py" \
    --api-host "$API_HOST" \
    --connect-ip "$ip" \
    --expected-maa-issuer "https://${MAA_ENDPOINT}" \
    --expected-hostdata "$expected_hostdata" \
    || die "attestation verification FAILED. The container group is running but has not proved
       it is the workload $SKR_KEY releases to. Do not put traffic on it."

  cat >&2 <<EOF

  VERIFIED. $CONTAINER_GROUP serves $API_HOST and attests as hostdata
  $expected_hostdata, which is one of the measurements $SKR_KEY in $VAULT releases to.

  Publish the pin so clients can check it themselves:
      $expected_hostdata            -> trust page hostdata-azure.txt
      https://${MAA_ENDPOINT}       -> trust page maa-issuer-azure.txt

EOF

  if [ "$(printf '%s\n' "$accepted" | grep -c .)" -gt 1 ]; then
    log "WARNING: the key still accepts more than one measurement (the deploy window is open)."
    note "Run 'narrow' to pin only $expected_hostdata. 'all' does this for you."
  fi
}

phase_logs() {
  for container in skr-sidecar quill-enclave; do
    printf '\n===== %s =====\n' "$container" >&2
    az_cli container logs --resource-group "$RESOURCE_GROUP" --name "$CONTAINER_GROUP" \
      --container-name "$container" >&2 2>/dev/null || note "(no logs)"
  done
}

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

PHASES=()
for arg in "$@"; do
  case "$arg" in
    --apply) APPLY=1 ;;
    -h|--help) sed -n '2,98p' "${BASH_SOURCE[0]}"; exit 0 ;;
    -*) die "unknown flag $arg" ;;
    *) PHASES+=("$arg") ;;
  esac
done
[ "${#PHASES[@]}" -gt 0 ] || PHASES=(all)

# print-env is pure local computation: no Azure, no --apply, no workdir. It
# exists so the sealer and the deploy cannot disagree about the measured env.
if [ "${PHASES[0]}" = "print-env" ]; then
  warn_unpinned_bundle
  render_env_json "$(resolve_mi_client_id)"
  exit 0
fi

if [ "$APPLY" != "1" ]; then
  log "DRY RUN. Nothing in AZURE will be created or modified. Add --apply to execute."
  note "(build/template/policy still write \$WORKDIR — that is what produces a reviewable template.)"
fi
warn_unpinned_bundle
log "workdir: $WORKDIR"
mkdir -p "$WORKDIR"
acquire_workdir_lock

for phase in "${PHASES[@]}"; do
  case "$phase" in
    all)      phase_build; phase_template; phase_policy; phase_bind; phase_deploy; phase_verify; phase_narrow ;;
    build)    phase_build ;;
    template) phase_template ;;
    policy)   phase_policy ;;
    bind)     phase_bind ;;
    deploy)   phase_deploy ;;
    verify)   phase_verify ;;
    narrow)   phase_narrow ;;
    rollback) phase_rollback ;;
    logs)     phase_logs ;;
    *) die "unknown phase '$phase' (build template policy bind deploy verify narrow rollback all print-env logs)" ;;
  esac
done
