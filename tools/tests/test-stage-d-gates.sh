#!/usr/bin/env bash
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "${root}"

python3 tools/test_stage_d_policy.py
python3 tools/test_stage_d_publication.py
python3 tools/test_stage_d_stream.py
python3 tools/test_wait_stage_d_policy.py

tmp="$(mktemp -d "${TMPDIR:-/tmp}/stage-d-gates-test-XXXXXX")"
trap 'rm -rf "${tmp}"' EXIT
digest_a="sha256:8ce7f0f3000000000000000000000000000000000000000000000000000000aa"
digest_b="sha256:b1c0f84d000000000000000000000000000000000000000000000000000000bb"

# Fixed input must reproduce the cross-repository wire fixture byte for byte.
python3 tools/write-stage-d-policy.py \
  --output "${tmp}/fixed.json" \
  --github-run-number 600 \
  --kind transitional \
  --issued-at 2026-09-03T21:30:00Z \
  --incoming-digest "${digest_a}" \
  --running-digest "${digest_b},${digest_a}"
cmp tools/testdata/stage-d-accepted.json "${tmp}/fixed.json"

# The parser cases are recorded responses and never touch the network.
python3 tools/verify-stage-d-stream.py stream tools/testdata/stage-d-stream-done.sse
python3 tools/verify-stage-d-stream.py stream tools/testdata/stage-d-stream-finish-reason.sse
if python3 tools/verify-stage-d-stream.py stream tools/testdata/stage-d-stream-no-terminal.sse 2>/dev/null; then
  echo "stream without a terminal unexpectedly passed" >&2
  exit 1
fi
fixture_request_id="rlog_00112233445566778899aabbccddeeff"
fixture_boot_kid="gcp-b1c0f84d-0001"
python3 tools/verify-stage-d-stream.py evidence tools/testdata/stage-d-evidence-lookup.json \
  --expected-gateway-request-id "${fixture_request_id}" \
  --expected-boot-kid "${fixture_boot_kid}" --require-stage-d on \
  --probe-key-in-use on
python3 tools/verify-stage-d-stream.py evidence \
  tools/testdata/stage-d-evidence-regional-quota.json \
  --expected-gateway-request-id "${fixture_request_id}" \
  --expected-boot-kid "" --require-stage-d off --probe-key-in-use off
if python3 tools/verify-stage-d-stream.py evidence \
  tools/testdata/stage-d-evidence-regional-quota.json \
  --expected-gateway-request-id "${fixture_request_id}" \
  --expected-boot-kid "" --require-stage-d off --probe-key-in-use on \
  2>/dev/null; then
  echo "regional-lease evidence unexpectedly passed with the Stage D probe key" >&2
  exit 1
fi
python3 - tools/testdata/stage-d-evidence-lookup.json "${tmp}" <<'PY'
import copy
import json
import pathlib
import sys

fixture = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
out = pathlib.Path(sys.argv[2])
for name, updates in {
    "pending": {"settled": False},
    "bare-id": {"authorization_id": "0123456789abcdef0123456789abcdef"},
    "legacy": {"authorization_kind": "legacy"},
    "no-heartbeat": {"heartbeat_seq": 0},
}.items():
    payload = copy.deepcopy(fixture)
    payload["data"].update(updates)
    (out / f"{name}.json").write_text(json.dumps(payload), encoding="utf-8")
PY

# The production gate parses the literal response with jq. Exercise it when jq
# is installed (GitHub's runner has it); the Python contract test above keeps
# this offline test runnable on developer machines that do not.
# shellcheck source=tools/stage-d-gate-lib.sh
source tools/stage-d-gate-lib.sh

# A previous template with heartbeat off predates the evidence route. Recovery
# selects that template before invoking the same verifier, so its recorded 404
# must take the compatibility branch after streaming itself has passed.
recorded_404_code="$(awk 'NR == 1 { print $2 }' \
  tools/testdata/stage-d-evidence-route-not-found.http)"
STAGE_D_MISSING_EVIDENCE_ROUTE_WARNED=0
{
  stage_d_accept_missing_evidence_route \
    off "${recorded_404_code}" fixture-region recovery
  stage_d_accept_missing_evidence_route \
    off "${recorded_404_code}" fixture-region recovery
} 2>"${tmp}/404-off.err"
[ "$(wc -l <"${tmp}/404-off.err")" -eq 1 ]
grep -Fq '/internal/gateway/authorizations/by-gateway-request-id/{x-request-id}' \
  "${tmp}/404-off.err"
grep -Fq 'passing the gate on plain streaming health alone' "${tmp}/404-off.err"
if stage_d_accept_missing_evidence_route \
    on "${recorded_404_code}" fixture-region rollout 2>"${tmp}/404-on.err"; then
  echo "evidence-route 404 unexpectedly passed with heartbeat on" >&2
  exit 1
fi
[ ! -s "${tmp}/404-on.err" ]
if stage_d_accept_missing_evidence_route \
    off 503 fixture-region recovery 2>"${tmp}/503-off.err"; then
  echo "non-404 evidence lookup unexpectedly took the compatibility branch" >&2
  exit 1
fi
[ ! -s "${tmp}/503-off.err" ]

if command -v jq >/dev/null 2>&1; then
  [ "$(stage_d_evidence_state tools/testdata/stage-d-evidence-lookup.json \
    "${fixture_request_id}" on "${fixture_boot_kid}" on)" = "valid" ]
  [ "$(stage_d_evidence_state tools/testdata/stage-d-evidence-lookup.json \
    "${fixture_request_id}" off wrong-boot-kid on)" = "valid" ]
  [ "$(stage_d_evidence_state tools/testdata/stage-d-evidence-lookup.json \
    "${fixture_request_id}" off wrong-boot-kid off)" = "valid" ]
  [ "$(stage_d_evidence_state "${tmp}/pending.json" \
    "${fixture_request_id}" on "${fixture_boot_kid}" on)" = "pending" ]
  if stage_d_evidence_state "${tmp}/bare-id.json" \
    "${fixture_request_id}" on "${fixture_boot_kid}" on >/dev/null 2>&1; then
    echo "bare hexadecimal authorization_id unexpectedly passed" >&2
    exit 1
  fi
  [ "$(stage_d_evidence_state \
    tools/testdata/stage-d-evidence-regional-quota.json \
    "${fixture_request_id}" off wrong-boot-kid off)" = "valid" ]
  if stage_d_evidence_state tools/testdata/stage-d-evidence-regional-quota.json \
    "${fixture_request_id}" off wrong-boot-kid on >/dev/null 2>&1; then
    echo "regional-lease evidence unexpectedly passed with the Stage D probe key" >&2
    exit 1
  fi
  if stage_d_evidence_state "${tmp}/legacy.json" \
    "${fixture_request_id}" off wrong-boot-kid off >/dev/null 2>&1; then
    echo "an unsupported synthetic-monitor authorization kind unexpectedly passed" >&2
    exit 1
  fi
  if stage_d_evidence_state "${tmp}/no-heartbeat.json" \
    "${fixture_request_id}" on "${fixture_boot_kid}" on >/dev/null 2>&1; then
    echo "missing heartbeat evidence unexpectedly passed with the flag on" >&2
    exit 1
  fi
  [ "$(stage_d_evidence_state "${tmp}/no-heartbeat.json" \
    "${fixture_request_id}" off wrong-boot-kid on)" = "valid" ]
fi

# Missing dedicated-key landing behavior depends on the selected template.
# With heartbeat off, use the old Secret Manager monitor key and warn loudly.
unset STAGE_D_PROBE_API_KEY
gcloud() {
  [ "$*" = "secrets versions access latest --secret=trustedrouter-synthetic-monitor-api-key --project=fixture-project" ]
  printf '%s' fallback-monitor-key
}
stage_d_select_probe_key off fixture-project fixture-region 2>"${tmp}/off-missing.err"
fallback_warning="$(<"${tmp}/off-missing.err")"
[ "${STAGE_D_PROBE_KEY}" = "fallback-monitor-key" ]
[ "${STAGE_D_PROBE_KEY_NAME}" = "trustedrouter-synthetic-monitor-api-key" ]
[ "${STAGE_D_PROBE_KEY_IN_USE}" = "off" ]
grep -Fq 'WARNING: fixture-region: STAGE_D_PROBE_API_KEY is unavailable' <<<"${fallback_warning}"
grep -Fq 'plain streaming health and settled authorization only' <<<"${fallback_warning}"

# With heartbeat on, do not touch the legacy secret and fail closed.
gcloud() {
  : >"${tmp}/legacy-key-touched"
  printf '%s' should-not-be-used
}
if stage_d_select_probe_key on fixture-project fixture-region 2>"${tmp}/on-missing.err"; then
  echo "missing Stage D probe key unexpectedly passed with heartbeat on" >&2
  exit 1
fi
[ ! -e "${tmp}/legacy-key-touched" ]
grep -Fq 'QUILL_USAGE_HEARTBEAT=on; failing closed' "${tmp}/on-missing.err"

# A provisioned Stage D key remains authoritative even when heartbeat checks
# are disabled by the selected template.
STAGE_D_PROBE_API_KEY=dedicated-probe-key
stage_d_select_probe_key off fixture-project fixture-region
[ "${STAGE_D_PROBE_KEY}" = "dedicated-probe-key" ]
[ "${STAGE_D_PROBE_KEY_NAME}" = "STAGE_D_PROBE_API_KEY" ]
[ "${STAGE_D_PROBE_KEY_IN_USE}" = "on" ]

# Both Stage D flags must match their declared regional rollout exactly.
workflow=.github/workflows/deploy-enclave-gcp.yml
inventory=tools/gcp-enclave-migs.txt
heartbeat_regions=tools/stage-d-heartbeat-regions.txt
terminate_regions=tools/stage-d-terminate-regions.txt
# Parse the supported step/env layout strictly, without a YAML dependency.
# Scan every assignment, including shell/metadata forms, so an on outside a
# region's own step env cannot escape the allowlist. Unknown layouts fail shut.
stage_d_counts="$(python3 - "${workflow}" "${inventory}" "${heartbeat_regions}" "${terminate_regions}" <<'PY'
import pathlib
import re
import sys


def require(condition, message):
    if not condition:
        raise SystemExit(f"Stage D region bijection: {message}")


workflow, inventory, heartbeat_file, terminate_file = map(pathlib.Path, sys.argv[1:])
configured_list = [line.split(":")[0] for line in inventory.read_text().splitlines()]
configured = set(configured_list)
require(configured and len(configured) == len(configured_list), "invalid MIG inventory")
flag_files = (
    ("QUILL_USAGE_HEARTBEAT", heartbeat_file),
    ("QUILL_TERMINATE_AT_CAP", terminate_file),
)
declared_by_flag = {}
for flag, declared_file in flag_files:
    declared_text = declared_file.read_text()
    declared_list = declared_text.splitlines()
    require(not declared_text or declared_text.endswith("\n"), f"{flag}: allowlist needs a final newline")
    require(all(re.fullmatch(r"[a-z]+(?:-[a-z]+)+[0-9]+", r) for r in declared_list),
            f"{flag}: allowlist must contain one region per line, without comments or blanks")
    declared = set(declared_list)
    require(len(declared) == len(declared_list), f"{flag}: duplicate declared region")
    require(declared <= configured, f"{flag}: unconfigured regions: {sorted(declared - configured)}")
    declared_by_flag[flag] = declared

heartbeat = declared_by_flag["QUILL_USAGE_HEARTBEAT"]
terminate = declared_by_flag["QUILL_TERMINATE_AT_CAP"]
require(terminate <= heartbeat,
        f"termination requires heartbeat in declared regions: {sorted(terminate - heartbeat)}")

lines = workflow.read_text().splitlines()
steps = {}
current_step = None
for number, line in enumerate(lines):
    # A new step or enclosing YAML key ends the previous step; comments do not.
    if line.strip() and not line.lstrip().startswith("#"):
        indent = len(line) - len(line.lstrip())
        if current_step is not None and indent <= current_step[1]:
            current_step = None
        match = re.fullmatch(r"(\s*)- name: (.+)", line)
        if match:
            current_step = (number, len(match[1]), match[2])
    if current_step is not None:
        steps[number] = current_step

for flag, declared in declared_by_flag.items():
    observed = {}
    for number, line in enumerate(lines):
        if not re.search(rf"(?:tee-env-)?{flag}(?:=|:\s+)", line):
            continue
        step = steps.get(number)
        require(step is not None, f"{flag}: line {number + 1}: flag outside a named step")
        start, indent, name = step
        value = re.fullmatch(r' {%d}%s: "(on|off)"' % (indent + 4, flag), line)
        require(value is not None, f"{flag}: line {number + 1}: flag must be a literal step env")
        parent = next((prior for prior in reversed(lines[start:number])
                       if prior.strip() and not prior.lstrip().startswith("#")
                       and len(prior) - len(prior.lstrip()) < indent + 4), "")
        require(parent == " " * (indent + 2) + "env:", f"{flag}: {name}: flag is not in step env")
        block = "\n".join(lines[n] for n, owner in steps.items() if owner == step)
        regions = set()
        primary = re.fullmatch(r"Roll the GCP MIG \(([^()]+)\)", name)
        if primary:
            regions.add(primary[1])
        templates = re.findall(
            r"^ {%d}PREV_TEMPLATE: \$\{\{ steps\.prev\.outputs\.([a-z0-9_]+)_template \}\}$"
            % (indent + 4), block, re.MULTILINE)
        regions.update(region.replace("_", "-") for region in templates)
        require(name.startswith("Roll ") and "GCP MIG" in name and len(regions) == 1,
                f"{flag}: {name}: cannot determine a unique rollout region")
        region = regions.pop()
        require(region in configured, f"{flag}: {name}: unknown MIG region {region}")
        require(region not in observed, f"{flag}: {region}: duplicate flag")
        observed[region] = value[1]

    on_regions = {region for region, value in observed.items() if value == "on"}
    off_regions = {region for region, value in observed.items() if value == "off"}
    require(on_regions == declared,
            f"{flag}: declared regions not on: {sorted(declared - on_regions)}; "
            f"undeclared regions on: {sorted(on_regions - declared)}")
    require(off_regions == configured - declared,
            f"{flag}: expected off regions {sorted(configured - declared)}, got {sorted(off_regions)}")
    print(flag, len(on_regions), len(off_regions), len(configured))
PY
)"
while read -r flag on_count off_count configured_region_count; do
  [ "$((on_count + off_count))" -eq "${configured_region_count}" ]
done <<<"${stage_d_counts}"
grep -Fq "/internal/gateway/authorizations/by-gateway-request-id/\${request_log_id}" tools/verify-region-before-dns.sh
grep -Fq 'STAGE_D_EVIDENCE_TIMEOUT_SECONDS:-60' tools/verify-region-before-dns.sh
grep -Fq '.data.authorization_kind != "regional_lease"' tools/stage-d-gate-lib.sh
grep -Fq 'stage_d_accept_missing_evidence_route' tools/verify-region-before-dns.sh

# Recovery binds the previous template before invoking the verifier; the
# verifier then reads the heartbeat flag from that selected template.
recovery=tools/recover-gcp-region.sh
template_restore_line="$(grep -nF "set-instance-template \"\${mig}\"" "${recovery}" | cut -d: -f1)"
recovery_gate_line="$(grep -nF 'bash tools/verify-region-before-dns.sh' "${recovery}" | cut -d: -f1)"
[ "${template_restore_line}" -lt "${recovery_gate_line}" ]
grep -Fq 'select(.key == "tee-env-QUILL_USAGE_HEARTBEAT")' tools/verify-region-before-dns.sh

# Final publication is structurally unreachable from recovery: only the
# finalize job writes kind=final, and it requires the whole rollout job.
grep -Fq 'needs: [build-and-release, rollout]' .github/workflows/deploy-enclave-gcp.yml
grep -Fq -- '--kind final' .github/workflows/deploy-enclave-gcp.yml
grep -Fq 'trust-page/gcp/stage-d-accepted.json; do' .github/workflows/publish-trust-gcp.yml
grep -Fq "cosign sign-blob --bundle \"\$f.bundle\" \"\$f\"" .github/workflows/publish-trust-gcp.yml
stage_d_sign_block="$(grep -A5 -F "if [ \"\$f\" = \"\$stage_d_policy\" ]; then" .github/workflows/publish-trust-gcp.yml)"
grep -Fq "cosign sign-blob --new-bundle-format --bundle \"\$f.bundle\" \"\$f\"" <<<"${stage_d_sign_block}"
grep -Fq 'cosign verify-blob --new-bundle-format' .github/workflows/publish-trust-gcp.yml
grep -Fq 'cosign verify-blob --new-bundle-format' .github/workflows/deploy-enclave-gcp.yml
grep -Fq 'cosign verify-blob --new-bundle-format' tools/wait-stage-d-policy.sh
grep -Fq -- "--certificate-identity \"\$identity\"" .github/workflows/publish-trust-gcp.yml
if grep -Eq 'write-stage-d-policy|--kind[[:space:]]+final' tools/recover-gcp-region.sh tools/roll-secondary-region.sh; then
  echo "a recovery path can publish a final Stage D policy" >&2
  exit 1
fi

echo "Stage D publication and streaming gate tests passed"
