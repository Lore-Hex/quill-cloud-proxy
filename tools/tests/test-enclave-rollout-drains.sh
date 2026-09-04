#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "${root}"

# shellcheck source=tools/enclave-rollout-drain-lib.sh
source tools/enclave-rollout-drain-lib.sh

[ "$(rollout_restore_drain_operation us-central1 active none)" = clear ]
[ "$(rollout_restore_drain_operation us-central1 drained operator)" = set ]
stale_warning="$(mktemp "${TMPDIR:-/tmp}/restore-drain-warning-XXXXXX")"
trap 'rm -f "${stale_warning}"' EXIT
[ "$(rollout_restore_drain_operation us-central1 drained rollout:33800000001 \
  2>"${stale_warning}")" = clear ]
grep -Fq \
  '::warning::us-central1 was drained by stale rollout:33800000001; restoring active and dropping the stale rollout drain' \
  "${stale_warning}"
if rollout_restore_drain_operation us-central1 active operator >/dev/null 2>&1; then
  echo "active/operator unexpectedly passed the restore decision table" >&2
  exit 1
fi

test_root="$(mktemp -d "${TMPDIR:-/tmp}/rollout-drain-cleanup-test-XXXXXX")"
trap 'rm -f "${stale_warning}"; rm -rf "${test_root}"' EXIT
mkdir "${test_root}/bin"

cat >"${test_root}/bin/uv" <<'EOF'
#!/bin/bash
echo "uv $*" >>"${COMMAND_LOG}"
case "$*" in
  *--list-drain-regions*) cat "${DRAIN_LIST_FIXTURE}" ;;
  *--clear-drain-region*) ;;
  *--apply*) ;;
  *) exit 2 ;;
esac
EOF
cat >"${test_root}/bin/gcloud" <<'EOF'
#!/bin/bash
echo "gcloud $*" >>"${COMMAND_LOG}"
[ "${STABLE}" = 1 ]
EOF
cat >"${test_root}/bin/bash" <<'EOF'
#!/bin/bash
echo "bash $*" >>"${COMMAND_LOG}"
[ "${ATTESTED}" = 1 ]
EOF
chmod +x "${test_root}/bin/uv" "${test_root}/bin/gcloud" "${test_root}/bin/bash"

command_log="${test_root}/commands.log"
cleanup_output="${test_root}/cleanup.out"
PATH="${test_root}/bin:/usr/bin:/bin" \
COMMAND_LOG="${command_log}" \
DRAIN_LIST_FIXTURE="${root}/tools/testdata/drain-list-mixed.txt" \
STABLE=1 ATTESTED=1 GITHUB_RUN_ID=33807667585 \
  /bin/bash tools/cleanup-enclave-rollout-drains.sh >"${cleanup_output}" 2>&1
grep -Fq -- '--clear-drain-region us-central1' "${command_log}"
if grep -Fq -- '--clear-drain-region europe-west4' "${command_log}"; then
  echo "operator drain was cleared" >&2
  exit 1
fi
grep -Fq -- '--apply' "${command_log}"
grep -Fq \
  '::warning::clearing stale rollout:33800000001 drain for healthy us-central1' \
  "${cleanup_output}"

printf 'us-central1\trollout:33807667585\n' >"${test_root}/current-run-list.txt"
: >"${command_log}"
if PATH="${test_root}/bin:/usr/bin:/bin" \
    COMMAND_LOG="${command_log}" \
    DRAIN_LIST_FIXTURE="${test_root}/current-run-list.txt" \
    STABLE=0 ATTESTED=1 GITHUB_RUN_ID=33807667585 \
      /bin/bash tools/cleanup-enclave-rollout-drains.sh \
        >"${cleanup_output}" 2>&1; then
  echo "unstable rollout drain unexpectedly cleared" >&2
  exit 1
fi
if grep -Fq -- '--clear-drain-region' "${command_log}"; then
  echo "unstable rollout drain invoked the clear command" >&2
  exit 1
fi
if grep -Fq 'wait-region-attested.sh' "${command_log}"; then
  echo "unstable rollout drain proceeded to attestation" >&2
  exit 1
fi
grep -Fq -- '--apply' "${command_log}"
# The backticks are literal GitHub annotation text, not command substitutions.
# shellcheck disable=SC2016
grep -Fq \
  '::error::us-central1 remains drained (origin rollout:33807667585): clear with `uv run --script tools/reconcile-enclave-dns.py --clear-drain-region us-central1` followed by `uv run --script tools/reconcile-enclave-dns.py --apply`' \
  "${cleanup_output}"

: >"${command_log}"
if PATH="${test_root}/bin:/usr/bin:/bin" \
    COMMAND_LOG="${command_log}" \
    DRAIN_LIST_FIXTURE="${test_root}/current-run-list.txt" \
    STABLE=1 ATTESTED=0 GITHUB_RUN_ID=33807667585 \
      /bin/bash tools/cleanup-enclave-rollout-drains.sh \
        >"${cleanup_output}" 2>&1; then
  echo "unattested rollout drain unexpectedly cleared" >&2
  exit 1
fi
grep -Fq 'wait-region-attested.sh' "${command_log}"
if grep -Fq -- '--clear-drain-region' "${command_log}"; then
  echo "unattested rollout drain invoked the clear command" >&2
  exit 1
fi

echo "enclave rollout drain tests passed"
