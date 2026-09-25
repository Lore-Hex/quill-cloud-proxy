A2: opt-in geographic canonical enclave DNS
==========================================

Implemented on `geo-canonical-dns`. The default is OFF. No production enablement, image deployment, DNS mutation, push, or A1 dependency is part of this change.

`QUILL_CANONICAL_GEO=1` makes the reconciler publish `API_HOST` and every `CANONICAL_MIRRORS` entry as an A RRset with `routingPolicy.geo.items`. Each item contains a GCP region and its sorted, deduplicated, healthy IPs. The existing attestation results are filtered by pending inventory, environment exclusions and persistent drains **before** grouping. Regions without eligible IPs have no item. Both permanent names receive the same policy membership. TTL remains `QUILL_DNS_TTL` (60 seconds by default).

With the setting unset or `0`, an existing flat record follows the original writer, logging and IP ordering. A snapshot test checks the original output byte-for-byte. The additional shape read allows OFF to undo a previous GEO deployment even when the IP union is unchanged. Regional `api-<region>.quillrouter.com` records retain their existing flat A/CNAME promotion path, own-SNI attestation and regional minimum guard. Confidential-only records remain on their existing separate eligibility path. Signed release-digest fallback, single-flight lease behavior, drain-origin handling and minimum-health guards remain in place. Zero canonical health is explicitly refused even if an operator configures `MIN_HEALTHY=0`.

Cloud DNS native health checking is **disabled**: there is no `healthCheck` or `healthCheckedTargets`; items contain `rrdatas`. Serving-socket attestation remains the admission and health signal. A generic liveness check cannot replace the certificate binding, accepted measurement and debug-state checks. `enableFencing` is explicitly false. Without native health checks, empty-region failover comes from removing the region's item, not from Cloud DNS independently detecting enclave failure.

Switching and enabling
----------------------

1. First distribute this code and its new `tools/cloud_dns_records.py` helper to every writer, including the Cloud Run job image. Leave GEO off until the owner wants it enabled; A1 may be deployed separately first.
2. All four workflow entry points now consume the repository Actions variable `QUILL_CANONICAL_GEO`, defaulting to `0`: `reconcile-enclave-dns.yml`, `deploy-enclave-gcp.yml`, `relieve-mig-stockout.yml`, and `deploy-enclave-dns-reconciler.yml`. The last workflow copies the value into the Cloud Run job environment. The helper is included in the image and rebuild triggers.
3. Coordinate the change while no old/in-flight/manual writers are running. Pause scheduled writers for this configuration change, set the Actions variable to `1`, and run the reconciler-image deployment workflow so the job receives the same value. Confirm job configuration before resuming writers. Changing the repository variable alone does not update an already deployed job. Ad hoc recovery/deploy/finalizer scripts inherit the shell environment; export the same value before invoking them. The GitHub schedule is every five minutes; the separate Cloud Scheduler declaration is every two minutes, with the job in `us-east4`.
4. Preview with `QUILL_CANONICAL_GEO=1 python3 tools/reconcile-enclave-dns.py --dry-run`, retaining the deployment's project, zones, mirror, lease and exclusion settings. Applying uses the same command with `--apply`. These are deployment instructions, not commands executed during this task. Dry-run still performs normal cloud reads and probes.
5. To turn it off, coordinate writers the same way, set `QUILL_CANONICAL_GEO=0`, update the Cloud Run job through the deployment workflow, and reconcile once. No manual deletion is needed. Do not roll back to a pre-A2 reader while GEO records still exist.

A GEO write or either shape transition uses one native Cloud DNS `changes.create` POST per record: exact old RRset data in `deletions`, replacement in `additions`. The old TTL and policy are preserved in the deletion, apart from output-only kind/signature metadata. No separate delete is issued. Cloud DNS applies the change atomically: old or new record, no deliberate NXDOMAIN interval. The installed SDK 575.0.0's `transaction_util._RecordSetsFromDictionaries` copies only name/type/TTL/rrdatas and discards routingPolicy; generating a gcloud transaction file would therefore be wrong. The REST writer obtains the same active gcloud credentials with `auth print-access-token` and checks pinned drains again after token acquisition, immediately before POST.

A 409/412 conflict causes one fresh read and retry. A transport timeout is ambiguous and is not blindly retried; the next reconcile reads authoritative state. Tests inspect the actual POST body and simulate atomic state replacement, conflicts and a drain arriving during token acquisition. Atomicity is per managed zone/record, not a cross-zone transaction. If the mirror write fails after the primary succeeds, the mirror retains its old record and the next pass repairs it.

Client routing and failure limits
---------------------------------

For public GEO DNS, location is based on the DNS query's source, or EDNS Client Subnet information when provided by the recursive resolver. Cloud DNS selects the closest configured geographic location. This is geographic selection, not measured application latency, and a remote resolver without useful ECS can select a location different from the client's. It returns ordinary A answers: clients and TLS/attestation code do not receive routing-policy JSON. Existing connections do not move when DNS changes.

Clients in Asia or South America also select the nearest **configured remaining** location; no enclave or empty placeholder item is required on those continents. Cold regional CNAME aliases that point to a canonical hostname inherit its GEO choice. We do not promise a particular destination for an entire continent, or claim that the supplied 553/653/1,704/4,473 ms timings have been reproduced.

- A region losing all enclaves: after a successful attestation reconcile, its item disappears and new lookups select a remaining location. Detection takes the scheduling/probing delay plus DNS caching (normally another 60 seconds). Connections and caches can retain old addresses longer.
- Too little total health: the existing `MIN_HEALTHY` guard (default 2) freezes canonical records. All regions empty also freezes them, never publishing zero items. **The requested safety rules mean an unconditional “never stranded” guarantee is impossible:** if only one enclave remains, the floor can retain a failed location even though that one enclave could serve. With the normal eight-IP fleet, losing one two-IP region leaves six and does not trigger this guard.
- Reconciler stopped, lease/storage/credential failure, or unavailable attestation/trust inputs: DNS freezes at the last good set. It is not a serving-path dependency, but there is no new health failover while it is stopped. A location failing after that freeze can strand its nearby clients until reconciliation resumes. Native liveness checks were not added to hide that limitation.
- Cloud DNS outage: both permanent names share this DNS provider. GEO does not create provider independence. Cached answers/existing connections may work temporarily; fresh resolution can fail. The existing independent Route53 names (`api.allyrouter.com`, `api.uptimerouter.com`) remain flat copies of the whole attested set; clients must explicitly support those backup names. They are not automatic DNS failover for either canonical name.
- Concurrent drain or writer: pinned-drain changes stop the pass; exact-match API deletions reject stale updates atomically. As before, a drain can arrive after the final check, and different zones can temporarily disagree. Mixed versions/settings must not run concurrently.

Reader audit
------------

Searched the repository, including hidden workflow files, for `rrdatas`, `record-sets`, DNS resolver calls, `dig`, and both permanent hostnames. The canonical management-API readers and action paths are:

| Reader / caller | Resolution and disposition |
| --- | --- |
| `reconcile-enclave-dns.py`: `current_dns_ips()` | Uses shared parser for static and GEO membership. Canonical comparison additionally checks shape, region assignment and TTL, so equal IP unions cannot suppress a transition. |
| `wait-canonical-drained.sh` | Reads full `--format=json` and invokes the shared parser. Both record shapes produce the complete IP set. Missing, empty and unsupported records fail the gate, rather than falsely authorizing a rollout. Tests execute the actual gate with local shell stubs. Configured `QUILL_API_HOST` can name either permanent record. |
| `sync-route53-api-aliases.py`: `source_ips()` | Flattens every GEO item before its existing public-IPv4 and minimum-health validation. Does not copy a resolver-local subset or introduce a dependency on the canonical domain into backups. |
| `recover-gcp-region.sh`, `roll-secondary-region.sh`, `cleanup-enclave-rollout-drains.sh`, deploy/stockout workflows | Delegate canonical membership and drain decisions to the reconciler, sync helper and drain gate above. They do not independently extract canonical `rrdatas`. Recovery inherits GEO configuration. Direct canaries obtain VM IPs from Compute inventory. |
| `deploy-azure-aci.sh` | Generic per-ACI DNS code previously allowed an arbitrary `API_HOST`. It now rejects either permanent fleet name, including trailing-dot form, before any cloud action. Its remaining A/CNAME reads and propagation assertions are Azure-specific. |
| `check-public-tls.py` / `check-dns.yml` | `socket.create_connection(host, 443)` uses ordinary DNS and works for both shapes. Added the permanent QuillRouter mirror to its host list. Regional probes remain necessary because one canonical connection samples only one location. The workflow's `dig` checks concern zone NS delegation, not canonical IP counts. |
| `capture-plane-measurements.py`: `live_gcp()` | `_fetch(GCP_ATTESTATION_URL)` uses normal HTTPS resolution; no Cloud DNS JSON or fleet count. It samples one selected enclave. AWS/Azure measurement paths use their own endpoints/origins. |
| `verify-attestation.py`, `wait-region-attested.sh`, `verify-region-before-dns.sh`, `relieve-mig-stockout.py`, deploy/release/bootstrap scripts | Socket/HTTP DNS resolution or direct Compute-discovered IPs with canonical SNI. Bootstrap's management-API A/CNAME reads are strictly `REGIONAL_RECORD=api-${REGION}.quillrouter.com.`, never the canonical A record. |
| Monitoring/debugging/state runbooks, trust-page instructions, DNS verification output | `dig`/curl show selected ordinary answers and still work. Updated `enclave-deploy-monitoring-checklist.md` to inspect the full policy and flatten JSON for fleet comparison; corrected its outdated mirror-CNAME claim. Historical observations are not current expected IP counts. |
| `tools/dns/main.tf` | Native Terraform provider resource, no hand-written canonical `rrdatas` parser. Added `ignore_changes` for mirror membership, TTL and routing_policy to prevent refresh/apply restoring its historical single bootstrap IP. The preexisting `trustedrouter_api_cname` block/import recipe is obsolete (it reads CNAME, not A); do not use it to recreate today's canonical name. Its stale bootstrap ownership needs separate Terraform-state review before applying that legacy module. No Terraform apply was performed. |
| `fix-quillrouter-dns.sh`, `fix-trustedrouter-dns.sh` | Historical one-shot scripts. Their `dig` output is ordinary DNS, not a membership/rollback decision. Their transactions repair regional or non-API records/NS; they do not parse canonical A membership. They are not an A2 switch mechanism. |
| `reconcile_ses_dns.py`, `enclave-go/internal/enclavetls/dns01_provider.go` | SES authentication records and ACME challenge TXT records respectively; their `rrdatas` code never reads canonical/mirror A membership. |

Suspected readers/writers outside this checkout: quill-router control-plane and synthetic/SDK monitors, its deploy and DNS-vendor runbooks, separately installed copies of the tools above, existing Cloud Run images, operator cron/repair scripts, Terraform state/provider versions, dashboards querying DNS through gcloud, and client-side regional/backup retries. Audit any whole-fleet assertion that uses `dig` or only `rrdatas`; resolver answers intentionally become a subset. No external repositories or live services were inspected.

Offline verification
--------------------

The default Python initially reported `No module named pytest`. All pytest commands below used an existing environment, with `PATH=/private/tmp/gatecost-revert-base/.venv/bin:$PATH` prepended; nothing was installed/downloaded and tests were not run through uv. Runtime Python was 3.14; deployment's supported Python floor remains 3.11.

- `python3 -m pytest -q -p no:cacheprovider tools/test_reconcile_enclave_dns.py`
  - `87 passed, 22 subtests passed in 2.06s`
- `QUILL_CANONICAL_GEO=1 python3 -m pytest -q -p no:cacheprovider tools/test_reconcile_enclave_dns.py`
  - `87 passed, 22 subtests passed in 2.17s` (the test suite also works in workflows with GEO enabled).
- `python3 tools/check_a2_mutations.py`
  - `40 mutants killed; all 23 new tests covered; checkout untouched`
  - Copies selected files to temporary directories, mutates only those copies, and requires failure of each named test (including pytest subtest failures). No git checkout/reset is used for mutations. Mutations cover shape/health-check/fencing, mirror publication, region grouping/omission, regional behavior, empty/floor refusal, both conversions, exclusions/drains/pending regions, defaults, idempotence/TTL, dry-run, atomic request data, stale drains/leases, conflicts/timeouts, release fallback, readers and setting/image distribution.
- `python3 -m pytest -q -p no:cacheprovider tools/test_sync_route53_api_aliases.py tools/test_check_public_tls.py tools/test_dns_reconciler_scheduler.py tools/test_recover_gcp_region.py tools/test_rollout_safety.py tools/test_gcp_enclave_inventory.py tools/test_mirror_independence.py`
  - `101 passed, 64 subtests passed in 14.75s`
- `python3 -m pytest -q -p no:cacheprovider tools/test_reconcile_enclave_dns.py tools/test_check_public_tls.py tools/test_capture_plane_measurements.py`
  - `1 failed, 121 passed, 26 subtests passed in 2.51s`
  - The failure is the unchanged provenance test's missing `9b3b68897dd6762b754dc638ee2417644ce4164b` object. `git cat-file -t '9b3b68897dd6762b754dc638ee2417644ce4164b^{commit}'` confirms it is missing; this is a shallow checkout. The measurement implementation changed only by explanatory comments. No history was fetched or release metadata changed.
- `python3 -m pytest -q -p no:cacheprovider tools/test_deploy_azure_aci.py`
  - `101 passed, 26 subtests passed in 207.33s (0:03:27)`
- `bash -n tools/wait-canonical-drained.sh tools/deploy-azure-aci.sh` and `git diff --check`: exit 0, no diagnostics.

During an early test run, an existing test mocked the old entry point and missed the new wrapper, inadvertently invoking real gcloud read commands. Those failed locally on credential-file permissions; no DNS write occurred. This violated the requested no-gcloud execution constraint. The test was corrected, and the reconciler suite now rejects unmocked external commands and socket connections, with teardown that prevents the guard leaking into other test modules. All subsequent cloud interactions in tests were mocks/local stubs. No intentional live cloud or network validation was performed.

Not verified offline: live IAM/token access to `changes.create`, API acceptance/DNSSEC behavior and actual propagation of both shape changes, production resolver/ECS mappings, latency benefit, a real region outage, current job images/settings/permissions, provider outages or external backup-client behavior. The local SDK source establishes the schema and transaction-reader limitation; tests establish request construction and control-flow properties, not production DNS behavior.

Git staging was attempted with hooks disabled, but the sandbox refused creation of `.git/index.lock` (`Operation not permitted`). No commit could be made. All changes remain in the working tree on `geo-canonical-dns`; nothing was pushed.
