#!/usr/bin/env python3
"""Kill A2 regressions on disposable source copies; never alter the checkout.

Run with the same offline Python that provides pytest:
    python3 tools/check_a2_mutations.py
Each mutant must fail its named test (not fail collection or import).
"""
from __future__ import annotations

import ast
import os
import re
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
RECONCILER = "tools/reconcile-enclave-dns.py"
PARSER = "tools/cloud_dns_records.py"
TESTS = "tools/test_reconcile_enclave_dns.py"
# (test, source file, exact original source fragment, regression)
MUTATIONS = [
    ("GeoCanonicalTests::test_geo_shape_and_both_mirrors", RECONCILER,
     '"enableFencing": False, "items": items', '"enableFencing": True, "items": items'),
    ("GeoCanonicalTests::test_geo_shape_and_both_mirrors", RECONCILER,
     '"healthCheck": GEO_HEALTH_CHECK,', '"healthCheck": "unexpected",'),
    ("GeoCanonicalTests::test_geo_shape_and_both_mirrors", RECONCILER,
     'for mirror_zone, mirror_record in CANONICAL_MIRRORS:', 'for mirror_zone, mirror_record in []:'),
    ("GeoCanonicalTests::test_geo_shape_and_both_mirrors", RECONCILER,
     'by_region.setdefault(instance["region"], set()).add(instance["ip"])',
     'by_region.setdefault("us-central1", set()).add(instance["ip"])'),
    ("GeoCanonicalTests::test_dead_region_is_omitted_and_regional_records_stay_flat", RECONCILER,
     '        if ok:\n            healthy.append(inst)', '        if True:\n            healthy.append(inst)'),
    ("GeoCanonicalTests::test_dead_region_is_omitted_and_regional_records_stay_flat", RECONCILER,
     '            if PUBLISH_REGIONAL:', '            if PUBLISH_REGIONAL and not CANONICAL_GEO:'),
    ("GeoCanonicalTests::test_empty_policy_refused_even_with_zero_minimum", RECONCILER,
     'if not healthy_ips or (not CANONICAL_GEO and len(healthy_ips) < MIN_HEALTHY):', 'if len(healthy_ips) < MIN_HEALTHY:'),
    ("GeoCanonicalTests::test_empty_policy_refused_even_with_zero_minimum", RECONCILER,
     '    if not items:\n', '    if False:\n'),
    ("GeoCanonicalTests::test_empty_policy_refused_even_with_zero_minimum", RECONCILER,
     '    if not record_ips(desired):', '    if False:'),
    ("GeoCanonicalTests::test_one_survivor_removes_dead_region_below_minimum", RECONCILER,
     'if not healthy_ips or (not CANONICAL_GEO and len(healthy_ips) < MIN_HEALTHY):', 'if not healthy_ips or len(healthy_ips) < MIN_HEALTHY:'),
    ("GeoCanonicalTests::test_flat_to_geo_is_one_change_even_when_membership_matches", RECONCILER,
     'if not CANONICAL_GEO and not (current and "routingPolicy" in current):',
     'if not (current and "routingPolicy" in current):'),
    ("GeoCanonicalTests::test_geo_to_flat_is_one_change_even_when_membership_matches", RECONCILER,
     'if not CANONICAL_GEO and not (current and "routingPolicy" in current):',
     'if not CANONICAL_GEO:'),
    ("GeoCanonicalTests::test_geo_drains_pending_and_exclusions_apply_before_grouping", RECONCILER,
     'return EXCLUDE_CANONICAL_REGIONS | GCP_ENCLAVE_PENDING_REGIONS', 'return EXCLUDE_CANONICAL_REGIONS'),
    ("GeoCanonicalTests::test_geo_drains_pending_and_exclusions_apply_before_grouping", RECONCILER,
     'return EXCLUDE_CANONICAL_REGIONS | GCP_ENCLAVE_PENDING_REGIONS', 'return GCP_ENCLAVE_PENDING_REGIONS'),
    ("GeoCanonicalTests::test_geo_drains_pending_and_exclusions_apply_before_grouping", RECONCILER,
     'canonical_excludes = canonical_excluded_regions() | persistent_excludes',
     'canonical_excludes = canonical_excluded_regions()'),
    ("GeoCanonicalTests::test_default_off_keeps_original_flat_output", RECONCILER,
     'CANONICAL_GEO = os.environ.get("QUILL_CANONICAL_GEO", "0") == "1"',
     'CANONICAL_GEO = os.environ.get("QUILL_CANONICAL_GEO", "1") == "1"'),
    ("GeoCanonicalTests::test_geo_idempotence_ttl_and_location_membership_are_compared", RECONCILER,
     '    return current == desired',
     '    return sorted(record_ips(current)) == sorted(record_ips(desired))'),
    ("GeoCanonicalTests::test_geo_idempotence_ttl_and_location_membership_are_compared", RECONCILER,
     'geo.setdefault("enableFencing", False)', 'geo.setdefault("enableFencing", True)'),
    ("GeoCanonicalTests::test_geo_idempotence_ttl_and_location_membership_are_compared", RECONCILER,
     '    return current == desired',
     '    return {k: v for k, v in current.items() if k != "ttl"} == {k: v for k, v in desired.items() if k != "ttl"}'),
    ("GeoCanonicalTests::test_dry_run_never_submits_geo_or_shape_switch", RECONCILER,
     '    if apply:\n        replace_dns_record(zone, desired)',
     '    if True:\n        replace_dns_record(zone, desired)'),
    ("GeoCanonicalTests::test_changed_drain_prevents_atomic_write_and_releases_failed_lease", RECONCILER,
     '        _check_pinned_drains()\n        try:\n            submit_dns_change',
     '        try:\n            submit_dns_change'),
    ("GeoCanonicalTests::test_atomic_api_request_contains_exact_deletion_and_no_standalone_delete", RECONCILER,
     '"deletions": [_dns_record_data(current)] if current is not None else []', '"deletions": []'),
    ("GeoCanonicalTests::test_atomic_api_request_contains_exact_deletion_and_no_standalone_delete", RECONCILER,
     '    _check_pinned_drains()\n    with urllib.request.urlopen(request, timeout=GCLOUD_TIMEOUT_SECONDS)',
     '    with urllib.request.urlopen(request, timeout=GCLOUD_TIMEOUT_SECONDS)'),
    ("GeoCanonicalTests::test_drain_set_during_token_fetch_blocks_post", RECONCILER,
     '    _check_pinned_drains()\n    with urllib.request.urlopen(request, timeout=GCLOUD_TIMEOUT_SECONDS)',
     '    with urllib.request.urlopen(request, timeout=GCLOUD_TIMEOUT_SECONDS)'),
    ("GeoCanonicalTests::test_conflict_retries_with_fresh_exact_record_and_is_bounded", RECONCILER,
     'if attempt or exc.code not in {409, 412}:', 'if True:'),
    ("GeoCanonicalTests::test_conflict_retries_with_fresh_exact_record_and_is_bounded", RECONCILER,
     'if attempt or exc.code not in {409, 412}:', 'if attempt > 1 or exc.code not in {409, 412}:'),
    ("GeoCanonicalTests::test_ambiguous_failure_never_deletes_or_blindly_retries", RECONCILER,
     '        if _same_dns_record(current, desired):', '        if False:'),
    ("GeoCanonicalTests::test_geo_keeps_release_digest_fallback", RECONCILER,
     '    return results, expanded', '    return [(inst, False) for inst, ok in results], expanded'),
    ("GeoReaderTests::test_reconciler_reads_flat_and_geo_for_either_name", RECONCILER,
     '        return record_ips(row)', '        return list(row.get("rrdatas", []))'),
    ("GeoReaderTests::test_route53_copies_complete_flat_and_geo_membership", "tools/sync-route53-api-aliases.py",
     '            values = record_ips(row)', '            values = row.get("rrdatas", [])'),
    ("GeoReaderTests::test_unknown_or_malformed_policies_fail_closed", PARSER,
     'raise ValueError("unsupported DNS routing policy")', 'return []'),
    ("GeoReaderTests::test_shell_drain_gate_cannot_mistake_geo_for_empty", PARSER,
     '                values.extend(targets["externalEndpoints"])', '                pass'),
    ("GeoReaderTests::test_shell_drain_gate_fails_on_missing_record", PARSER,
     'raise ValueError(f"expected exactly one A record for {name}")', 'return []'),
    ("GeoReaderTests::test_azure_deploy_refuses_canonical_or_mirror_dns_ownership", "tools/deploy-azure-aci.sh",
     '  api.trustedrouter.com|api.quillrouter.com)', '  api.unrelated.example)'),
]
for workflow in ("reconcile-enclave-dns.yml", "deploy-enclave-gcp.yml", "relieve-mig-stockout.yml", "deploy-enclave-dns-reconciler.yml"):
    MUTATIONS.append(("GeoReaderTests::test_workflow_writers_share_setting_and_image_contains_parser",
                      ".github/workflows/" + workflow,
                      "QUILL_CANONICAL_GEO: ${{ vars.QUILL_CANONICAL_GEO || '0' }}", "QUILL_CANONICAL_GEO: '0'"))
MUTATIONS.extend([
    ("GeoReaderTests::test_workflow_writers_share_setting_and_image_contains_parser", "tools/Dockerfile.reconciler",
     'reconcile-enclave-dns.py cloud_dns_records.py dns_geo_health.py gcp-enclave-migs.txt', 'reconcile-enclave-dns.py dns_geo_health.py gcp-enclave-migs.txt'),

])

MUTATIONS.extend([
    ("GeoCanonicalTests::test_off_reads_each_unchanged_canonical_once_and_needs_no_check", RECONCILER,
     'current_ips=record_ips(current) if current else []', 'current_ips=None'),
    ("GeoCanonicalTests::test_off_reads_each_unchanged_canonical_once_and_needs_no_check", RECONCILER,
     'if not healthy_ips or (not CANONICAL_GEO and len(healthy_ips) < MIN_HEALTHY):', 'if not healthy_ips:'),
    ("GeoCanonicalTests::test_health_check_validation_refuses_missing_or_misconfigured_before_geo_write", RECONCILER,
     'verify_health_check(GEO_HEALTH_CHECK, PROJECT, gcloud_json)', 'pass'),
    ("GeoCanonicalTests::test_operator_creation_is_explicit_and_verified", "tools/dns_geo_health.py",
     '    if args.create:', '    if True:'),
    ("GeoCanonicalTests::test_operator_creation_is_explicit_and_verified", "tools/dns_geo_health.py",
     '"--port=443"', '"--port=80"'),
    ("GeoCanonicalTests::test_operator_creation_is_explicit_and_verified", "tools/dns_geo_health.py",
     '    verify_health_check(url, args.project, read)', '    pass'),
])
for before in (
    'if not url.startswith(prefix) or not re.fullmatch(r"[a-z](?:[-a-z0-9]{0,61}[a-z0-9])?", name):',
    'if not isinstance(check, dict):',
    'if any(check.get(key) != value for key, value in expected.items()) or check.get("region"):',
    'if sorted(check.get("sourceRegions", [])) != sorted(SOURCE_REGIONS):',
):
    MUTATIONS.append(("GeoCanonicalTests::test_health_check_validation_refuses_missing_or_misconfigured_before_geo_write",
                      "tools/dns_geo_health.py", before, 'if False:'))
MUTATIONS.append(("GeoCanonicalTests::test_health_check_validation_refuses_missing_or_misconfigured_before_geo_write",
                  "tools/dns_geo_health.py", 'tcp.get("port") != 443', 'False'))
for workflow in ("reconcile-enclave-dns.yml", "deploy-enclave-gcp.yml", "relieve-mig-stockout.yml", "deploy-enclave-dns-reconciler.yml"):
    MUTATIONS.append(("GeoReaderTests::test_workflow_writers_share_setting_and_image_contains_parser",
                      ".github/workflows/" + workflow,
                      "QUILL_GEO_HEALTH_CHECK: ${{ vars.QUILL_GEO_HEALTH_CHECK }}", "QUILL_GEO_HEALTH_CHECK: ''"))

for before, after in (
    ('verify_geo_zones(canonical_healthy)', 'pass'),
    ('if dnssec == "on" and any(len(ips) > 1 for ips in counts.values()):', 'if False:'),
    ('if dnssec not in {"off", "on"}:', 'if False:'),
    ('config.get("visibility") != "public"', 'False'),
    ('{DNS_ZONE} | {zone for zone, _ in CANONICAL_MIRRORS}', '{DNS_ZONE}'),
):
    MUTATIONS.append(("GeoCanonicalTests::test_geo_zone_constraints_are_checked_for_both_names",
                      RECONCILER, before, after))

MUTATIONS.extend([
    ("GeoReaderTests::test_reconciler_reads_flat_and_geo_for_either_name", PARSER,
     '                values.extend(item["rrdatas"])', '                pass'),
    ("GeoReaderTests::test_unknown_or_malformed_policies_fail_closed", PARSER,
     'or set(targets) - {"externalEndpoints", "kind"}', 'or False'),
])

# Round 3: check failure must change publication shape, not freeze membership.
for before, after in (
    ('                    geo_degraded = True', '                    raise'),
    ('if CANONICAL_GEO and not force_flat else', 'if CANONICAL_GEO else'),
    ('if force_flat and current is None:', 'if force_flat and (current is None or "routingPolicy" not in current):'),
    ('                force_flat=geo_degraded,\n            )', '                force_flat=False,\n            )'),
    ('                    force_flat=geo_degraded,', '                    force_flat=False,'),
    ('return 1 if confidential_failed or geo_degraded else 0', 'return 1 if confidential_failed else 0'),
    ('log(f"reconcile: ERROR: GEO health check invalid: {exc}; "',
     'log(f"reconcile: GEO fallback; "'),
    ('"deletions": [_dns_record_data(current)] if current is not None else []', '"deletions": []'),
    ('        if ok:\n            healthy.append(inst)', '        if True:\n            healthy.append(inst)'),
):
    MUTATIONS.append(("GeoCanonicalTests::test_invalid_attached_check_removes_dead_east_and_keeps_reconciling_flat",
                      RECONCILER, before, after))
MUTATIONS.extend([
    ("GeoCanonicalTests::test_fixed_health_check_resumes_geo_from_degraded_flat", RECONCILER,
     'if CANONICAL_GEO and not force_flat else', 'if CANONICAL_GEO and not force_flat and current is None else'),
    ("GeoCanonicalTests::test_deleted_or_misconfigured_attached_check_degrades_both_names", RECONCILER,
     '                    geo_degraded = True', '                    raise'),
    ("GeoCanonicalTests::test_deleted_or_misconfigured_attached_check_degrades_both_names", RECONCILER,
     '"deletions": [_dns_record_data(current)] if current is not None else []',
     '"deletions": [dict(_dns_record_data(current), ttl=TTL)] if current is not None else []'),
    ("GeoCanonicalTests::test_degraded_flat_uses_flat_filters_and_refuses_zero", RECONCILER,
     'if not healthy_ips or (not CANONICAL_GEO and len(healthy_ips) < MIN_HEALTHY):',
     'if not CANONICAL_GEO and len(healthy_ips) < MIN_HEALTHY:'),
    ("GeoCanonicalTests::test_degraded_flat_uses_flat_filters_and_refuses_zero", RECONCILER,
     'return EXCLUDE_CANONICAL_REGIONS | GCP_ENCLAVE_PENDING_REGIONS', 'return EXCLUDE_CANONICAL_REGIONS'),
    ("GeoCanonicalTests::test_degraded_flat_uses_flat_filters_and_refuses_zero", RECONCILER,
     'return EXCLUDE_CANONICAL_REGIONS | GCP_ENCLAVE_PENDING_REGIONS', 'return GCP_ENCLAVE_PENDING_REGIONS'),
    ("GeoCanonicalTests::test_degraded_flat_uses_flat_filters_and_refuses_zero", RECONCILER,
     'canonical_excludes = canonical_excluded_regions() | persistent_excludes',
     'canonical_excludes = canonical_excluded_regions()'),
    ("GeoCanonicalTests::test_degraded_flat_honors_dry_run_and_concurrent_drains", RECONCILER,
     '    if apply:\n        replace_dns_record(zone, desired)',
     '    if True:\n        replace_dns_record(zone, desired)'),
    ("GeoCanonicalTests::test_degraded_flat_honors_dry_run_and_concurrent_drains", RECONCILER,
     '        _check_pinned_drains()\n        try:\n            submit_dns_change',
     '        try:\n            submit_dns_change'),
    ("GeoCanonicalTests::test_invalid_check_does_not_block_existing_when_other_name_is_absent", RECONCILER,
     'if force_flat and current is None:', 'if False:'),
    ("GeoCanonicalTests::test_off_with_invalid_check_keeps_byte_identical_logs_and_commands", RECONCILER,
     '            if CANONICAL_GEO:\n                try:', '            if True:\n                try:'),
    ("GeoCanonicalTests::test_off_with_invalid_check_keeps_byte_identical_logs_and_commands", RECONCILER,
     'if not CANONICAL_GEO and not (current and "routingPolicy" in current):', 'if False:'),
])


# Round 4: every nonempty degraded survivor set bypasses the GEO minimum.
# Restore the rejected guard independently for the exact finding and each filter.
for test in (
    "test_invalid_attached_check_removes_dead_east_and_keeps_reconciling_flat",
    "test_invalid_attached_check_removes_drained_east_below_minimum",
    "test_invalid_attached_check_removes_excluded_east_below_minimum",
    "test_invalid_attached_check_removes_pending_east_below_minimum",
):
    MUTATIONS.append(("GeoCanonicalTests::" + test, RECONCILER,
                      '            if CANONICAL_GEO and not geo_degraded:',
                      '            if geo_degraded and len(healthy_ips) < MIN_HEALTHY:\n'
                      '                sys.exit("regressed degraded floor")\n'
                      '            if CANONICAL_GEO and not geo_degraded:'))
MUTATIONS.extend([
    ("GeoCanonicalTests::test_invalid_attached_check_removes_drained_east_below_minimum", RECONCILER,
     'canonical_excludes = canonical_excluded_regions() | persistent_excludes',
     'canonical_excludes = canonical_excluded_regions()'),
    ("GeoCanonicalTests::test_invalid_attached_check_removes_excluded_east_below_minimum", RECONCILER,
     'return EXCLUDE_CANONICAL_REGIONS | GCP_ENCLAVE_PENDING_REGIONS', 'return GCP_ENCLAVE_PENDING_REGIONS'),
    ("GeoCanonicalTests::test_invalid_attached_check_removes_pending_east_below_minimum", RECONCILER,
     'return EXCLUDE_CANONICAL_REGIONS | GCP_ENCLAVE_PENDING_REGIONS', 'return EXCLUDE_CANONICAL_REGIONS'),
    ("GeoCanonicalTests::test_off_floor_keeps_byte_identical_failure_and_logs", RECONCILER,
     'if not healthy_ips or (not CANONICAL_GEO and len(healthy_ips) < MIN_HEALTHY):', 'if not healthy_ips:'),
    ("GeoCanonicalTests::test_off_floor_keeps_byte_identical_failure_and_logs", RECONCILER,
     'refusing to shrink DNS — leaving last-good record in place', 'refusing to shrink DNS'),
])


def main() -> None:
    tree = ast.parse((ROOT / TESTS).read_text())
    expected = {node.name + "::" + method.name for node in tree.body
                if isinstance(node, ast.ClassDef) and node.name in {"GeoCanonicalTests", "GeoReaderTests"}
                for method in node.body if isinstance(method, ast.FunctionDef) and method.name.startswith("test_")}
    covered = {case[0] for case in MUTATIONS}
    assert covered == expected, f"mutation coverage mismatch: {covered ^ expected}"
    files = {case[1] for case in MUTATIONS} | {
        TESTS, "tools/dns_geo_health.py", "tools/gcp-enclave-migs.txt", "tools/gcp-enclave-migs-pending.txt",
        "tools/wait-canonical-drained.sh",
    }
    with tempfile.TemporaryDirectory(prefix="a2-mutations-") as tmp:
        copy = Path(tmp)
        for name in files:
            target = copy / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", QUILL_CANONICAL_GEO="0")
        for number, (test, name, before, after) in enumerate(MUTATIONS, 1):
            target = copy / name
            original = target.read_text()
            assert original.count(before) == 1, f"ambiguous mutation: {name} {before!r}"
            try:
                target.write_text(original.replace(before, after))
                result = subprocess.run(
                    [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", TESTS + "::" + test],
                    cwd=copy, env=env, capture_output=True, text=True, timeout=30,
                )
                output = result.stdout + result.stderr
                assert result.returncode == 1 and re.search(
                    r"^(?:FAILED |SUBFAILED\(.*\) )" + re.escape(TESTS + "::" + test),
                    output, re.MULTILINE,
                ), (
                    f"mutant {number} survived or failed to run: {test}\n{output}"
                )
                print(f"killed {number}/{len(MUTATIONS)} {test}", flush=True)
            finally:
                target.write_text(original)
    print(f"{len(MUTATIONS)} mutants killed; all {len(expected)} new tests covered; checkout untouched")


if __name__ == "__main__":
    main()
