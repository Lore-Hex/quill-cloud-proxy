# Shadow v2 enclave startup records

This runtime runs once per workload boot. After the listeners are initialized,
`main` starts the coordinator in its own goroutine immediately before entering
the serving loop. The coordinator never makes startup wait for a descriptor,
manifest, router read, image record, stdout reader, or ready acknowledgement.
It can leave checks missing. With today's router surfaces it does leave checks
missing, so this round does not make a live opted boot ready.

`EnclaveOptedAdmission` is bound in `retainShadowV2`, after the v2 policy marker
is parsed and before either retention variant. The existing caller invokes this
only when its shadow flag is on. Only chat.completions and responses are gated.
Before readiness, the hook takes the existing `(false, true)` non-retention
outcome. After readiness, existing v2 processing continues. The decision is one
atomic pointer read. The request entry samples the time before calling retention
and records the result from the completed retention decision. Its preallocated
256-entry buffer uses TryLock; a busy or full buffer
drops and counts immediately. No clock, lock or append runs inside the hook. There is no added request error or wire field.
With shadow off the existing caller returns before this hook.

The coordinator also runs with shadow off. A completed marker record uses the
actual `off` value, never an anticipated rollout state. Other missing inputs
remain missing in the dormant stage too. Non-cohort traffic is unchanged.

## Configuration and release manifest

`TR_SHADOW_V2_STARTUP_MANIFEST` names a regular local file of at most 262144
bytes. It must contain exactly one canonical JSON object: sorted object keys,
compact UTF-8 JSON, integer times, no trailing newline, duplicate or extra keys.
This is a reviewed release input, installed before startup. Its absence or an
invalid file leaves criteria missing. This runtime does not produce review
approval or infer it from a filename.

The exact top-level fields are:

| Field | Value |
| --- | --- |
| revision | Full lowercase 40-character released SHA; must equal the baked `ShadowBuildRevision` or embedded Go VCS revision and launch descriptor |
| region | Descriptor's enclave region |
| config_sha256 | SHA-256 of the exact UTF-8 bytes in `config_original` |
| policy_sha256, fixture_sha256 | Reviewed release digests, 64 lowercase hex characters |
| config_original | JSON string carrying the complete shared release original, preserving formatting, trailing newline and shared fields |
| public_descriptors | Exact `{authority_epoch,config_sha256,source_revision,descriptor_ids}` original; epoch positive and the other values equal this release |
| artifacts | Object indexed by criterion then source role, containing selected artifact records |

`config_original` carries the same shared original that the collector retains.
The runtime hashes and retains its exact decoded string bytes, then reads only
its local projection. It does not reencode that projection to obtain the digest.
The shared original includes `dependencies.router` and `dependencies.enclave`,
`router_path`, `descriptor_ids`, `enclave_image_sha256`, and `effective_pins`.
Other shared release fields remain in the original and therefore in its digest.

- `dependencies.enclave` is the finite local target list, 2..16 entries. Each
  target has `operation,resource,region`; both `transport` and `read` must occur,
  without duplicate operation/resource pairs. `dependencies.router` remains
  part of the exact shared original and is not probed by this process. Each local
  call has a ten-second deadline supplied by the adapter, outside the digest.
- `router_path` is exactly `{resource,region}` and agrees with every local
  target. Hostnames come from release configuration and must equal the first
  existing control-plane endpoint. The configured region is never inferred
  from the enclave hostname. The manifest's artifact region is the enclave's
  region; dependency/router-path region is the configured router's region.
- `descriptor_ids` is an ordered list of 1..16 distinct bounded IDs.
- `enclave_image_sha256` is the reviewed image digest.
- `effective_pins` is exactly `TR_ASYNC_SETTLE_NEGOTIATE` and
  `TR_ASYNC_SETTLE_SHADOW`, with normalized `on`/`off` values. Actual values use
  the same bootstrap/environment flag readers as the existing client.

Each artifact has exactly
`id,criterion,source,revision,region,config_sha256,started_at_us,completed_at_us,checks`.
Its ID is a bounded release-supplied artifact ID, not a generated filename.
Revision, region and config digest must match the manifest. Original UTC
microsecond start must be less than completion, and completion no later than
adoption. Non-CI trials last at most one hour. `checks` has the exact criterion
check names from the fixture, with `pass` or `fail` values. A failed source
remains failed. Original times remain in the retained manifest bytes; each
emitted `completed_at_us` is this boot's adoption time.

| Criterion | Required selected sources | This boot's additional input |
| --- | --- | --- |
| transport | ci, regional_trial | None |
| size | ci, sizing_trial | None |
| regional_load | budget_trial | None |
| boot_transport | regional_trial | One measured call per configured target, matching markers and declared deadline |
| observer_freshness | Empty inputs object | Configured router ready/boot observation, local transport and existing echo readiness |
| marker_keys | ci | Actual flags, public original, current image record and released digests |

One final record is emitted per available criterion. No retry can replace a
failed adoption; another boot is needed. A missing source or incomplete local
measurement emits no substitute check. A known failed trial can produce a
failed adoption if the rest of that criterion's closed fields are available.

## Descriptor, boot clock, and records

The launcher must explicitly set `TR_SHADOW_V2_LAUNCH_FD=3` and pass a readable
pipe or regular file as fd 3 across exec (without `FD_CLOEXEC`). `main` captures
only that declared descriptor before opening listeners. Without the declaration,
fd 3 is never inspected, made nonblocking, read or closed: the Go runtime may
already own it for network polling. An empty/invalid declaration, missing fd,
wrong descriptor type, close-on-exec fd or write-only fd fails closed without
taking ownership; it never selects the metadata fallback. A present descriptor
is read once with a three-second outer deadline, at most 2048 bytes, and EOF.
It must be a canonical object with exactly
`instance,launch,role,revision,region`, role `enclave`, bounded ASCII identities,
and the released SHA. A malformed present descriptor is never replaced by the
fallback. Descriptor failure leaves readiness unavailable.

If the launch-descriptor declaration is absent, the metadata adapter reads project, zone and numeric instance
ID using the existing metadata-server pattern, then reads
`/proc/sys/kernel/random/boot_id`. `LauncherLaunchDescriptor` remains the bridge
for the independent launcher start. Instance encoding is `instance:` plus
SHA-256 of canonical
`{"coordinate":{"instance_id":"...","project":"...","zone":"..."},"source":"launcher_start"}`.
In instance-as-launch mode the launch uses that same digest with `launch:`.
The VM boot ID, mode, and `startInsertIDKnown=false` are retained separately in
the local acquisition observation. This is explicitly a candidate one-start
mapping, not the full launcher start encoding. The workload cannot obtain the
launcher's start insertId or distinguish repeated starts in one VM boot through
this fallback. fd 3 supplies the exact independently retained full-coordinate
encoding when the bridge exists; the start insertId itself remains unknown
inside the child even in fd 3 mode. Fallback alone does not qualify a launch.

A fresh local boot ID identifies this coordinator's in-memory journal. The first
record is `a3_startup_correlation`, before manifest loading or checks. The process
start observation is at entry to `main`; it is not a measurement of the earlier
OS process creation instant. UTC Unix microseconds are used for record times.
The clock original is exactly `{clock,boot,boot_at_us}`, with clock `utc_ns`.
`BootClockQualification` remains external: this projection cannot establish
clock adjustments, uncertainty, or the independent process start relation.
Monotonic durations use Go times captured in this process, never UTC subtraction.

The five emitted shapes are the fixture's enclave shapes. Their canonical JSON
limits are respectively 2048, 16384, 1024, 2048 and 4096 bytes. Invalid records
are counted and dropped. A queue of 32 lines and a 250 ms write acknowledgement
bound keep stdout stalls off request and startup paths. One worker writes each
whole JSON line through the existing workload stdout channel; existing stderr
logging is unchanged. No generic structured-log wrapper exists in the inspected
startup/shadow path, so no timestamp/message wrapper is added to the closed
object. Launcher capture preserves this line inside MESSAGE.

Coordinates are exactly `{kind,sha256,bytes}`. Digest and length come from an
owned copy of the exact retained original buffer. The clock, public descriptor,
and image originals remain local for this boot. `EnclaveOriginalRetention`
names the missing native collection channel for those buffers and their survival
across VM loss. The stdout record alone cannot resolve its own coordinates.

## Live checks and remaining inputs

The live router adapter makes one bounded `/ready` GET for each declared
transport/read target, without redirects or retries, using the existing client
transport and configured endpoint. Responses are capped at 4096 bytes. The
adapter records status and actual elapsed intervals. It then performs one
bounded observer read. No target or record builder accepts an incoming request.

`RouterMarkerObservation` remains missing: current `/ready` exposes status and
checks, without the boot's marker/pin match. The closed dependency shape requires
`marker_matches=true`, so a missing/mismatched marker is held in local observations
and prevents the boot_transport adoption. `RouterBootExposure` remains missing:
`/ready` has no router boot ID. The observed ready/resource/region/time remain
local; no empty boot is emitted. `ExistingSettleEcho` remains missing for startup:
the existing echo runs on real settlement traffic and exposes no independent
boot-ready measurement. A synthetic booking is not added to measure it.

`EnclaveImageRecord` reads the existing locally minted document cache, with no
new fetch. GCP `image_digest` or `submods.container.image_digest` supplies the
image digest; conflicting fields remain missing. The two-field image original
joins that digest to the baked source revision using the reviewed manifest's
image mapping. It does not claim the document itself contains a source SHA.
Other cached document formats have no implemented image mapping in this round
and leave marker_keys missing. The original document is never copied to a
startup record or this harness's original buffers.

## Readiness, attempts, and termination

Only six successful adoptions permit a single `a3_traffic_ready`, whose sampled
time must be strictly later than every completion. Failed emission or a missing,
failed, empty or late acknowledgement leaves admission unavailable. The ready
record and acknowledgement are never retried with a new timestamp.

`EnclaveReadyRetention` is installed as **local completion plus successful stdout
emission only**. Admission would then be gated locally only. This is the fallback
allowed for this round, not the interface's durable acknowledgement. The existing
GCS cache `Put` discards the returned generation and its certificate cache does
not establish a reviewed 30-day record location. This round changes neither that
transport nor its configured location. A future adapter must acknowledge the
same ready bytes through an existing approved retained channel and preserve both
bytes and acknowledgement for at least 30 days. Current missing local criteria
prevent reaching this local-only ready path in a live boot.

`ReceiptPageRetention` remains missing. The enclave does not retain the v2 PAGE
that owns the native start event. At admission start the request-entry recorder samples `at_us`
and records accepted/rejected after retention returns; accepted means the request
was retained at entry. It does not describe a later settlement result. There are 256 preallocated local slots and a separate atomic drop
count for a busy or full recorder. No request fields enter those observations. The closed receipt field is
mandatory, so no `a3_opted_attempt` line is emitted until an existing PAGE writer
can provide a joined retained page. No page, sequence or coordinate is invented.
The local observations and overflow count do not establish a complete attempt
population across process loss.

`EnclaveShutdownStages` retains the actual settlement queue wait as `export_wait`
when the serving loop returns after termination. The connection drain begins
inside `serveUntilCanceled`; no existing callback exposes its start, so this
round does not guess a drain interval from signal-delivery time. There is no enclave v2 daily
close, final pass, or close-result writer. Missing stages stay absent, never zero.
The record builder accepts only all five actual endpoint pairs, so this round
leaves the final `a3_shutdown_span` absent instead of emitting a partial shape.
The inventory has no role field on that record; the startup correlation supplies
the enclave role. The router's closures remain the frozen shutdown population.

## Cross-repository fixture rule

`internal/trustedrouter/testdata/shadow_v2_runtime_records_inventory.json` is the
literal supplied JSON block, copied byte-for-byte. SHA-256 is
`a661658e2fa8a958292fe39e8ba82d252935254c2a17d646b6205052603428f3`.
`TestStartupInventory` checks that byte pin, all five reflected Go field sets,
enclave role extensions, limits, criterion/source sets, result values,
coordinate kinds/limits and descriptor keys. A router inventory change must
explicitly update this fixture, the Go schemas/validators, and this test's pin
in a reviewed enclave change. Do not regenerate or silently fetch it during
build or test. No a1/a2 fixture is changed.

Round 2 uses the supplied section 15.3 table. Tests use in-memory ports and
local files. The producer-to-collector check runs the sibling read-only collector
with the literal `shadow_v2_shared_release_config.json`, six actual Go-produced
adoptions, their originals, and explicit fake trial inputs. It produces six
collector checks and one ledger with the same exact config digest. It does not
stand in for native trials or original delivery from a deployed process.


## Startup failures and round 2 checks

Every launched startup input worker recovers a panic. The coordinator also
recovers, leaves the interrupted criterion missing, and leaves admission
unavailable. Output writes recover and count a drop. Ordinary serving continues.
A context deadline bounds the coordinator's wait; it cannot stop a callback that
ignores cancellation. Each such input can leave at most its one worker waiting.

`TestStartupPanickingPorts` starts a child process for each input and exercises
ordinary requests before and after the failed startup. `TestStartupProductionHandoff`
invokes `StartShadowV2Startup` with each input stalled and completes an ordinary
request. `TestStartupRealServingHandoff` uses the production handoff and serving
loop with an in-memory listener and a descriptor pipe without EOF.

The incoming-value test exercises both readiness states, both marked variants,
both cohort routes, all production record constructors, and the two currently
uninstalled attempt/shutdown constructors. It inspects the complete emitted
stream and retained originals for distinct incoming values that also fit the ID
shape. The round-3 entry test also calls both production request methods with
distinct identifiers, a digest, header values, model and metadata in both states.
It captures every output line and retained original; the direct retention test
remains in place. The transition test changes readiness between entry and
retention and checks the completed result and original entry timestamp.
The base transcript test compares full request/response bytes with a
literal captured from 21292b56; v1 retained state and the existing frozen main
outcomes are checked again in both readiness states.

All valid record shapes have stricter field/count bounds than their outer byte
ceilings. The emission test calculates an upper bound for each shape, then sets
the existing ceiling table to the actual serialized length and one byte below
it. It exercises serialization, queued output, exact bytes and counted drops;
removing the production ceiling call is detected. The complete coordinate map
must equal the fixture-derived map, and the attempt result lookup is derived
from the embedded literal. Outside kinds and results cannot enter output.

## Section 15.3 enclave rows and named input seams

| Row | Records and checks | Remaining input seam and reason |
| --- | --- | --- |
| transport | This boot adopts the exact selected ci/regional_trial IDs, region, config digest and original times; failed checks remain failed. | `ReleasedTransportOriginals`: real both-route/full/hash-only authorize/echo/settle/refund trial originals and both released revisions must come from release packaging. The local manifest has one revision and is not that whole original. |
| size | ci/sizing_trial adoption checks event_snapshot, headers_fragments, native_memory and transactions for this config. | `NativeSizingOriginals`: no native maximum event/snapshot, header/fragment, four-page/counter/closure transaction, separate-result, encoding/RSS/queue measurements are supplied here. |
| regional_load | budget_trial must match true region/config and last no more than one hour; the complete shared release limits stay in the original. | `RegionalEnvelopeBinding`: the current selected-artifact projection does not independently establish measured CPU/read/publisher/export/shutdown values or that this boot fits N=1/K/cap/surge. The reviewed native original is still required. |
| boot_transport | One bounded transport/read call per configured enclave target on this process, with measured elapsed time, marker match and clock original; regional_trial is adopted separately. | `RouterMarkerObservation`: the existing ready response lacks the marker fields, so the live check stays missing. `CrossRegionDependencyJoin`: the collector requires dependency region equal boot region; a differing configured router region needs a reviewed input resolution and must never be relabeled. |
| observer_freshness | Only enclave router_path, configured_router_region, local_transport_ready, echo_ready and clock_basis are emitted. | `RouterBootExposure` and `ExistingSettleEcho`: existing ready output supplies no router boot or independent local echo-ready observation. Available status remains local; no borrowed router warm result is used. |
| marker_keys | Actual flags, this revision, released policy/fixture/config digests, public descriptor/epoch and cached image mapping are recorded. Dormant off remains off. | `ReleaseStagePins`: release packaging must check activation shadow-on/negotiation-off, both-release CI originals and deployed revision. `EnclaveImageRecord`: only the existing GCP cached format has an image mapping. Other formats remain missing. |

Common remaining seams are `LauncherLaunchDescriptor`, `BootClockQualification`,
`EnclaveOriginalRetention`, `EnclaveReadyRetention`, `ReceiptPageRetention` and
`EnclaveShutdownStages`, as described above. None is filled by a passed unit test.
The installed live adapters still lack required inputs and leave opted readiness
unavailable. This package does not create native observations or complete a rollout.
