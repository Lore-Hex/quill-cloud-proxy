#!/usr/bin/env bash
# Delete a region's old enclave instance templates so deploys never hit the
# project's global INSTANCE_TEMPLATES quota (1000). Every deploy creates a new
# template and nothing else removes them; on 2026-11-04 the project reached
# 1,646 and every GCP deploy failed at template creation.
#
# Keeps the newest KEEP templates for the prefix (rollback targets), any
# template a managed instance group still references in any version, and any
# template a running instance was created from (a stuck roll). Never
# fatal: a failed list or delete only skips pruning, and the caller goes on to
# create its template.
#
# Usage: prune-gcp-instance-templates.sh PROJECT_ID TEMPLATE_PREFIX [KEEP]
set -uo pipefail

PROJECT_ID="$1"
TEMPLATE_PREFIX="$2"
KEEP="${3:-20}"

log() { printf '[prune-templates] %s\n' "$*" >&2; }

if ! templates="$(gcloud --project "$PROJECT_ID" compute instance-templates list \
  --filter="name~^${TEMPLATE_PREFIX}-[0-9]+\$" --format="value(name)")"; then
  log "listing templates failed; skipping prune"
  exit 0
fi
if ! referenced="$(gcloud --project "$PROJECT_ID" compute instance-groups managed list \
  --format="value(instanceTemplate.basename(),versions[].instanceTemplate.basename())")"; then
  log "listing instance groups failed; skipping prune"
  exit 0
fi
if ! instance_templates="$(gcloud --project "$PROJECT_ID" compute instances list \
  --format="value(metadata.items.instance-template.basename())")"; then
  log "listing instances failed; skipping prune"
  exit 0
fi
referenced="${referenced}"$'\n'"${instance_templates}"
in_use="$(printf '%s\n' "$referenced" | tr ',; \t' '\n' | sed 's#.*/##' | grep . || true)"

total=0
victims=()
# Newest first by numeric suffix (version sort, so -1000 follows -999); the
# first KEEP survive, and so does anything an instance group references.
while IFS= read -r name; do
  [ -n "$name" ] || continue
  total=$((total + 1))
  if [ "$total" -le "$KEEP" ] || printf '%s\n' "$in_use" | grep -Fxq -- "$name"; then
    continue
  fi
  victims+=("$name")
done < <(printf '%s\n' "$templates" | sort -V -r)

if [ "${#victims[@]}" -eq 0 ]; then
  log "nothing to prune for ${TEMPLATE_PREFIX} (${total} templates)"
  exit 0
fi
log "deleting ${#victims[@]} of ${total} templates for ${TEMPLATE_PREFIX}"
for ((start = 0; start < ${#victims[@]}; start += 50)); do
  if ! gcloud --project "$PROJECT_ID" compute instance-templates delete --quiet \
    "${victims[@]:start:50}"; then
    log "a delete batch failed; continuing"
  fi
done
exit 0
