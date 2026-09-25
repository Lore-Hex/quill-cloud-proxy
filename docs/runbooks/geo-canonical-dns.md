A2 revision: geographic canonical enclave DNS
============================================

Round 4 revision of `839b55898aaba1792bbaa8d8fb50fb6a7230da5c` / PR #374 on `geo-canonical-dns`. No network, gcloud execution, cloud mutation, deployment or push was performed during this revision. GEO remains OFF by default.

Round 4: publish degraded survivors below the minimum
----------------------------------------------------

**P1 fixed:** removed the extra `MIN_HEALTHY` guard on degraded GEO publication. With an invalid attached health check, any nonempty set of attested, eligible survivors replaces both existing canonical names with flat A records, even below the configured minimum. Persistent drains, environment exclusions and pending regions still filter that set. The shared zero-IP guard and OFF's minimum guard, failure message and publication path are unchanged.

The regression now uses the default `MIN_HEALTHY=2`: publish central/east GEO, invalidate the attached check to TCP/80, lose east before the next pass, and let only central attest. Both names must become flat `[central]`, with exact old-record deletions. It also checks continued degraded membership updates and idempotence. Three additional tests keep east attesting and independently drain, exclude or mark east pending; each must still publish only central at the default floor. An OFF floor snapshot pins the pre-fix failure text, log bytes, empty command serialization and retained records for valid, missing and TCP/80 checks. Zero survivors remain refused at minima 2 and 0.

All four finding scenarios failed against the reviewed code before the fix (`4 failed, 97 deselected in 0.34s`). The mutation runner restores the degraded floor separately for each scenario, bypasses each east filter separately, and removes OFF's floor or alters its failure message. It continues to mutate disposable copies only and requires the named test to fail.

Round 4 verification (offline):

- Six tools test files, using the full command in **Offline verification** below: `178 passed, 114 subtests passed in 8.62s`
- `python3 tools/check_a2_mutations.py`: `91 mutants killed; all 38 new tests covered; checkout untouched`
- `git diff --check`: exit 0.
- Git staging failed with `Unable to create .../.git/index.lock: Operation not permitted`; no commit was possible. The four changed files remain in the working tree. No network, real gcloud or push occurred.


Round 3: invalid attached health check
--------------------------------------

**P1 fixed:** a missing, unreadable or misconfigured health check no longer aborts reconciliation before existing canonical membership can be updated. Each pass validates the configured check. On failure it logs `ERROR: GEO health check invalid:` with the validation/read reason, then reconciles existing canonical and mirror A records to flat attested survivors. It returns status 1 after the ordinary and regional updates, including on unchanged degraded passes, so monitoring continues to surface the problem. Missing canonical records are refused independently; they cannot prevent recovery of the other existing name. New GEO publication still requires a valid check and valid zone configuration.

The fallback uses the same filtered, sorted, deduplicated survivor set as OFF and the same flat record shape. Both the initial GEO-to-flat replacement and later degraded flat membership updates use the existing exact-deletion `changes.create` path. TTL/policy from the old record remain in the deletion. It retains pinned-drain checks, dry-run behavior and bounded conflict handling. Each record is atomic; separate zones remain separate changes. Every pass revalidates the check, so restoring TCP/443 and the reviewed configuration automatically resumes GEO without changing the feature flag or storing a degradation marker.

**Minimum behavior (corrected in round 4):** valid and degraded GEO both publish any nonempty eligible survivor set regardless of `MIN_HEALTHY`. OFF alone retains its floor. Neither mode publishes zero IPs, even with a zero minimum. Pending regions, environment exclusions and persistent drains are applied before either publication shape. Round 3's degraded floor and `minimum=1` regression masked unsafe retention; the default-floor regressions above replace that behavior.

Seven new tests cover valid GEO → TCP/80 → east failure, continued flat updates as survivors change, repeated degraded alerts, restored-check recovery, deleted/404/timeout/wrong-protocol/misconfigured checks, exact deletion with an old TTL, filtering/minimum/zero behavior, dry-run/concurrent drains, either missing canonical name, and byte-identical OFF logs and command serialization. The mutation runner adds 22 regressions on disposable copies; each must fail its named test. The validation-refusal test now verifies refusal of new publication plus failure status and reason, while existing records recover.

Round 3 verification (offline):

- Six tools test files, using the full command in **Offline verification** below: `174 passed, 111 subtests passed in 9.25s`
- `python3 tools/check_a2_mutations.py`: `83 mutants killed; all 34 new tests covered; checkout untouched`
- `git diff --check`: exit 0.
- Git staging failed with `Unable to create .../.git/index.lock: Operation not permitted`; no commit was possible. All four changed files remain in the working tree. No network, real gcloud, deployment or push occurred.

Earlier finding disposition (updated for round 4)
------------------------------------------------

- **P1-1 fixed:** GEO ignores the `MIN_HEALTHY` floor whenever at least one eligible healthy canonical IP remains. The zero-IP case still preserves the last record, including with `MIN_HEALTHY=0`. The unsafe `test_minimum_guard_keeps_last_good_geo` was replaced by a test starting with one central and one eastern enclave, failing either region, checking both permanent names reduce to the surviving region, and repeating the pass. OFF retains its existing floor, writer, logs and ordering.
- **P1-2 implemented; semantics supplied by the reviewer:** GEO now uses `routingPolicy.healthCheck` and each item's `healthCheckedTargets.externalEndpoints`, with `enableFencing=false` and no static `rrdatas` bypass. Cloud DNS can check previously admitted endpoints while the reconciler is stopped. Before publishing either permanent name, the reconciler reads and validates the configured, operator-created global TCP check and both managed zones. Missing, inaccessible or misconfigured checks stop new GEO publication and trigger the existing-record flat fallback described above. The reviewer-supplied Google semantics at the end of this runbook settle the all-buckets-unhealthy question: Cloud DNS treats all endpoints as healthy. That is why an invalid check must not freeze dead GEO membership. No live validation was performed.
- **P2 separated:** Terraform canonical ownership is outside this PR and ships as its own follow-up PR, as the reviewer notes below. The earlier report referred to `tools/dns/reconciler-ownership.patch`; that file is absent from this checkout, so its historical `git apply --check` result is not a round 3 verification. No Terraform files were changed in round 3.
- **P3 fixed:** the OFF wrapper passes the already-read flat membership to the existing writer. Each unchanged canonical record is read exactly once per pass, including the compatibility mirror. A new counting test fails if the redundant read returns. Changed flat records retain the legacy writer's additional existence read and race retry, as before A2. No health-check/zone reads occur with GEO OFF. The existing byte-for-byte OFF log snapshot still passes.

Published policy and admission
------------------------------

`QUILL_CANONICAL_GEO=1` groups the already attested, pending/exclusion/drain-filtered IPs by GCP region. Every nonempty region has one GEO item; sorted, deduplicated external endpoints contain only that region's admitted IPs. `API_HOST` and every `CANONICAL_MIRRORS` entry receive the same policy. TTL remains `QUILL_DNS_TTL`, default 60 seconds. Native TCP health checking is liveness only: it cannot admit a new IP, validate a measurement or replace certificate binding/debug-state verification. Regional A/CNAME promotion and confidential records retain their separate existing rules. Release-digest fallback and pinned drains remain in place.

A GEO write or shape transition uses one native Cloud DNS `changes.create` POST per record, deleting the exact old record and adding its replacement atomically. The old TTL and routing policy are retained in the deletion, except output-only kind/signature fields. There is no standalone deletion or intentional NXDOMAIN interval. SDK 575's transaction dictionary reader discards routingPolicy, so the existing REST path is retained. It obtains the active CLI credential and rechecks pinned drains immediately before POST. A 409/412 gets one fresh read/retry; ambiguous transport errors wait for the next pass. Separate zones are not a cross-zone transaction.

SDK constraints read offline
----------------------------

Installed SDK version: `575.0.0`, read from `/opt/homebrew/share/google-cloud-sdk/VERSION`. There is no `schemas/dns` directory or Compute HealthCheck YAML in this installation. The generated v1 API message schemas and CLI source are the installed schema/documentation for these resources; none of the citations below required executing gcloud or accessing a URL.

| Constraint | Installed source and text | Implementation |
| --- | --- | --- |
| External endpoints | [DNS v1 messages](/opt/homebrew/share/google-cloud-sdk/lib/googlecloudsdk/generated_clients/apis/dns/v1/dns_v1_messages.py:2387): “Set either `internal_load_balancer` or `external_endpoints`. Do not set both.” `externalEndpoints` is “The Internet IP addresses to be health checked.” | Uses external IPs only. Shared readers flatten the external endpoints and reject internal/unknown target shapes. Both legacy static GEO and native checked GEO remain readable for migration/rollback. |
| Check resource scope | [DNS routing policy schema](/opt/homebrew/share/google-cloud-sdk/lib/googlecloudsdk/generated_clients/apis/dns/v1/dns_v1_messages.py:2324) requires a fully qualified `https://www.googleapis.com/compute/v1/projects/{project}/global/healthChecks/{healthCheck}` URL. | Requires this URL in `QUILL_GEO_HEALTH_CHECK`, same project, valid resource name, matching selfLink/kind/name and no regional scope. No default missing-resource creation. |
| Type and port | [Compute HealthCheck](/opt/homebrew/share/google-cloud-sdk/lib/googlecloudsdk/generated_clients/apis/compute/v1/compute_v1_messages.py:51765): “Exactly one of the protocol-specific health check fields must be specified”; [TCPHealthCheck](/opt/homebrew/share/google-cloud-sdk/lib/googlecloudsdk/generated_clients/apis/compute/v1/compute_v1_messages.py:98815) specifies TCP port and fixed-port semantics. | TCP connect-only on fixed 443; rejects other protocol fields, named/serving ports, request/response content and proxy headers. Port 443 is already public; no firewall change. |
| Probe regions and timing | [Compute sourceRegions schema](/opt/homebrew/share/google-cloud-sdk/lib/googlecloudsdk/generated_clients/apis/compute/v1/compute_v1_messages.py:51799): “exactly 3 regions”; “This can only be set for global health check”; interval “must be at least 30.” SSL/HTTP2/GRPC, TCP requests and proxy headers are unsupported; timeout cannot exceed interval. [CLI source-regions help](/opt/homebrew/share/google-cloud-sdk/lib/googlecloudsdk/api_lib/compute/health_checks_utils.py:592) says these checks are for DNS routing policies and cannot be used for backend services or MIG autohealing. | Requires the reviewed regions `us-east1,europe-west1,asia-east1`, interval 30 seconds, timeout 5 seconds, two consecutive successes/failures. This is stricter than the schema's minimums. Three distributed probes avoid reliance on one probe region. |
| Public zones and DNSSEC | [DNS GEO item schema](/opt/homebrew/share/google-cloud-sdk/lib/googlecloudsdk/generated_clients/apis/dns/v1/dns_v1_messages.py:2374): “When using health-checked targets for DNSSEC-enabled zones, you can only use at most one health-checked IP address per item.” | Reads every distinct canonical managed zone, requires public visibility and a known DNSSEC state. Refuses multiple IPs per region in a signed zone before either canonical write. It does not disable DNSSEC or silently discard healthy endpoints. |
| Nearest healthy region | [GEO fencing schema](/opt/homebrew/share/google-cloud-sdk/lib/googlecloudsdk/generated_clients/apis/dns/v1/dns_v1_messages.py:2345): “Without fencing, if health check fails for all configured items in the current geo bucket, we failover to the next nearest geo bucket.” | Explicit `enableFencing=false` plus native health-checked targets, independently of future reconciler writes. Tests inspect the exact policy sent for both names. |
| Every item unhealthy | The same fencing schema says **with fencing**, “we return all the items in the current bucket even when all targets are unhealthy.” It does **not** state the terminal outcome when all buckets are unhealthy **without fencing**. The primary/backup schema's unrelated all-unhealthy fallback does not establish GEO's behavior. | No invented citation or mock simulation is used as proof. The reviewer-supplied Google documentation below establishes that all-unhealthy buckets fail open. The SDK alone did not establish this; no live experiment was performed. |

Operator procedure (not executed)
--------------------------------

1. Review `tools/dns_geo_health.py`. It is the explicit operator provisioning/verification step, never invoked by the reconciler. Create with `python3 tools/dns_geo_health.py --project PROJECT --name canonical-dns-tcp --create`; verify an existing resource by omitting `--create`. Creation is a global TCP health check with the reviewed three probe regions, port, timings and thresholds; the script then describes it and uses the same validator as the reconciler. Failed verification does not silently repair anything. Protect this resource from deletion while policies refer to it.
2. Review the supplied all-target fail-open semantics below. Verify native probe reachability, API acceptance, DNSSEC state, and `compute.healthChecks.get` / `dns.managedZones.get` access for every reconciler identity. Grant only read access to the check to reconcilers; resource creation belongs to the reviewed operator. No live IAM or probe check was performed here.
3. Distribute the reconciler and both `cloud_dns_records.py` and `dns_geo_health.py` helpers to every writer. Four workflow entry points carry both `QUILL_CANONICAL_GEO` and `QUILL_GEO_HEALTH_CHECK`; the deployment workflow passes both into the Cloud Run job and rebuilds when either helper changes. Configure the URL printed by the operator verifier as the Actions variable `QUILL_GEO_HEALTH_CHECK` and as the environment value for ad hoc writers.
4. Coordinate writers so old/in-flight versions cannot overwrite the policy. Set GEO to `1`, deploy the job configuration/image, and preview via `python3 tools/reconcile-enclave-dns.py --dry-run` before `--apply`. A changed repository variable alone does not update an existing job. These commands require cloud access and were not run here.
5. Roll back by coordinating all writers, setting GEO to `0`, updating the job and reconciling once. OFF can atomically convert either static or checked GEO to flat without manual deletion. Do not roll back readers to a version that cannot read GEO while such records remain.

Availability limits
-------------------

- One region dead, another healthy: successful reconciliation removes the dead region even below `MIN_HEALTHY`; native TCP checks can fail over the existing policy while writes/credentials/trust inputs/reconciler are unavailable. Membership can remain stale during that freeze; TCP success says nothing about attestation validity or application-level responsiveness.
- Zero attested eligible IPs: the reconciler preserves membership rather than publishing an empty record. Under the reviewer-supplied Google semantics, Cloud DNS treats all endpoints as healthy when all buckets are unhealthy; these unit tests do not exercise that live behavior.
- Native probe thresholds, propagation and DNS caching delay failover; no instantaneous guarantee is made. Existing connections and caches can retain old addresses. Resolver source/ECS drives geographical selection, not measured application latency. Clients in other continents select among configured regions.
- Both permanent names still use Cloud DNS. This change adds no reconciler serving-path dependency but does not create provider independence. Existing independent Route53 backup names stay flat copies of the full admitted membership, and clients must support them explicitly.
- Concurrent drains stop further writes; a drain can still arrive after the last check. Conflicts are rejected atomically. Mirrors can briefly differ if a later zone write fails.

Reader audit
------------

Searched the repository, including hidden workflow files, for `rrdatas`, `record-sets`, DNS resolver calls, `dig`, and both permanent hostnames. The canonical management-API readers and action paths are:

| Reader / caller | Resolution and disposition |
| --- | --- |
| `reconcile-enclave-dns.py`: `current_dns_ips()` | Uses shared parser for flat records, legacy static GEO items and health-checked external GEO endpoints. Canonical comparison additionally checks shape, region assignment and TTL, so equal IP unions cannot suppress a transition. |
| `wait-canonical-drained.sh` | Reads full `--format=json` and invokes the shared parser. Both record shapes produce the complete IP set. Missing, empty and unsupported records fail the gate, rather than falsely authorizing a rollout. Tests execute the actual gate with local shell stubs. Configured `QUILL_API_HOST` can name either permanent record. |
| `sync-route53-api-aliases.py`: `source_ips()` | Flattens every GEO item before its existing public-IPv4 and minimum-health validation. Does not copy a resolver-local subset or introduce a dependency on the canonical domain into backups. |
| `recover-gcp-region.sh`, `roll-secondary-region.sh`, `cleanup-enclave-rollout-drains.sh`, deploy/stockout workflows | Delegate canonical membership and drain decisions to the reconciler, sync helper and drain gate above. They do not independently extract canonical `rrdatas`. Recovery inherits GEO configuration. Direct canaries obtain VM IPs from Compute inventory. |
| `deploy-azure-aci.sh` | Generic per-ACI DNS code previously allowed an arbitrary `API_HOST`. It now rejects either permanent fleet name, including trailing-dot form, before any cloud action. Its remaining A/CNAME reads and propagation assertions are Azure-specific. |
| `check-public-tls.py` / `check-dns.yml` | `socket.create_connection(host, 443)` uses ordinary DNS and works for both shapes. Added the permanent QuillRouter mirror to its host list. Regional probes remain necessary because one canonical connection samples only one location. The workflow's `dig` checks concern zone NS delegation, not canonical IP counts. |
| `capture-plane-measurements.py`: `live_gcp()` | `_fetch(GCP_ATTESTATION_URL)` uses normal HTTPS resolution; no Cloud DNS JSON or fleet count. It samples one selected enclave. AWS/Azure measurement paths use their own endpoints/origins. |
| `verify-attestation.py`, `wait-region-attested.sh`, `verify-region-before-dns.sh`, `relieve-mig-stockout.py`, deploy/release/bootstrap scripts | Socket/HTTP DNS resolution or direct Compute-discovered IPs with canonical SNI. Bootstrap's management-API A/CNAME reads are strictly `REGIONAL_RECORD=api-${REGION}.quillrouter.com.`, never the canonical A record. |
| Monitoring/debugging/state runbooks, trust-page instructions, DNS verification output | `dig`/curl show selected ordinary answers and still work. Updated `enclave-deploy-monitoring-checklist.md` to inspect the full policy and flatten JSON for fleet comparison; corrected its outdated mirror-CNAME claim. Historical observations are not current expected IP counts. |
| `tools/dns/main.tf` | Native Terraform provider resource, no hand-written canonical `rrdatas` parser. The unrelated `ignore_changes` ownership change belongs to a separate follow-up PR; no patch artifact is present in this checkout. The preexisting `trustedrouter_api_cname` block/import recipe is obsolete (it reads CNAME, not A); do not use it to recreate today's canonical name. Its stale bootstrap ownership needs separate Terraform-state review before applying that legacy module. No Terraform apply was performed. |
| `fix-quillrouter-dns.sh`, `fix-trustedrouter-dns.sh` | Historical one-shot scripts. Their `dig` output is ordinary DNS, not a membership/rollback decision. Their transactions repair regional or non-API records/NS; they do not parse canonical A membership. They are not an A2 switch mechanism. |
| `reconcile_ses_dns.py`, `enclave-go/internal/enclavetls/dns01_provider.go` | SES authentication records and ACME challenge TXT records respectively; their `rrdatas` code never reads canonical/mirror A membership. |

Suspected readers/writers outside this checkout: quill-router control-plane and synthetic/SDK monitors, its deploy and DNS-vendor runbooks, separately installed copies of the tools above, existing Cloud Run images, operator cron/repair scripts, Terraform state/provider versions, dashboards querying DNS through gcloud, and client-side regional/backup retries. Audit any whole-fleet assertion that uses `dig` or only `rrdatas`; resolver answers intentionally become a subset. No external repositories or live services were inspected.

Offline verification
--------------------

All tests used the existing interpreter `/private/tmp/gatecost-revert-base/.venv/bin/python3`; nothing was installed/downloaded. Reconciler tests reject unmocked external commands and socket connections. The operator script was tested only with mocked subprocess calls. Mutations run only in disposable copies and require the named test to fail, not merely collection/import failure.

- Requested six-file suite: `python3 -m pytest -q -p no:cacheprovider tools/test_reconcile_enclave_dns.py tools/test_sync_route53_api_aliases.py tools/test_check_public_tls.py tools/test_dns_reconciler_scheduler.py tools/test_recover_gcp_region.py tools/test_rollout_safety.py`
  - `178 passed, 114 subtests passed in 8.62s`
- `python3 tools/check_a2_mutations.py`
  - `91 mutants killed; all 38 new tests covered; checkout untouched`
- `git diff --check`: exit 0. The historical ownership-patch check cannot be repeated: `tools/dns/reconciler-ownership.patch` is absent (the attempted check reported that missing file).

The mutation tests cover every A2 GEO test, including degraded flat fallback, recovery, deleted checks, flat safeguards and byte-identical OFF behavior, as well as the earlier survivor, OFF-read-count, resource-validation, operator-provisioning and DNSSEC/zone tests. During development, mutation testing exposed an invalid-URL assertion that was masked by a later selfLink check; the test now proves malformed URLs are rejected before any resource read. A workflow assertion was updated to include the new health-check environment variable while retaining the lock-bucket assertion.

No live failover, all-unhealthy DNS result, IAM, resource creation, firewall, DNSSEC/API acceptance, propagation or deployment was exercised. The earlier report's pre-revision test summaries and historical gcloud-test incident are superseded as revision validation by the results above; that prior incident is not a claim of cloud activity in this revision.

Cloud DNS health-check semantics (added by the reviewer from Google's published documentation, 2026-09-25)
-------------------------------------------------------------------------------------------------------

The local SDK text could not settle the all-unhealthy case; Google's routing-policies overview
(https://docs.cloud.google.com/dns/docs/routing-policies-overview) does:

- Next-nearest failover without fencing: "For a geolocation policy that doesn't have fencing enabled, the traffic switches to endpoints in the next closest geography to the source Google Cloud region defined in the policy."
- Fail open: "If all policy buckets are unhealthy, Cloud DNS behaves as if all endpoints are healthy." A GEO record with health checking therefore never answers empty because probes fail.
- External endpoints: TCP, HTTP and HTTPS checks are supported (TCP request field and proxyHeader unsupported); probes come from three source regions you specify (nine probers per endpoint); an unspecified port defaults to 80, so the check must name 443.

The Terraform ownership change (ignore_changes on the canonical record) is NOT part of this PR; it prevents a stale apply of tools/dns from clobbering the reconciler-owned record whether or not GEO is enabled, and ships as its own follow-up PR.
