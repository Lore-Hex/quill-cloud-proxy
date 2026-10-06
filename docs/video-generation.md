# BytePlus video resolution billing

The enclave routes text and first-frame Seedance jobs directly to BytePlus at
480p and 720p, and also at 1080p for `bytedance/seedance-2.5` and
`bytedance/seedance-2.0`. `bytedance/seedance-2.0-fast` supports only 480p and
720p. Direct BytePlus jobs remain limited to 4–15 seconds and cannot include
video references, audio references, negative prompts, last frames, or reference
images. Seed support and the seeded-request provider policy are unchanged.

For requests without video input, the control plane freezes these BytePlus
output-token tariffs (USD per million tokens):

| Model | 480p / 720p | 1080p |
| --- | ---: | ---: |
| Seedance 2.5 | 10.70 | 11.70 |
| Seedance 2.0 | 7.00 | 7.70 |

The enclave reserves 20,000 tokens per second for 480p, 40,000 for 720p, and
100,000 for 1080p. The 1080p ceiling provides headroom over approximately 48,600
actual tokens per second (up to about 48,912 for the published 21:9 dimensions)
and reaches at most 1,500,000 tokens, below the
2,000,000-token authorization cap. Settlement reports the provider's actual
`completion_tokens`; the router applies its authorization-time tariff snapshot.
The reservation ceiling is never billed as usage. The bound tests use the
[BytePlus dimension table](https://docs.byteplus.com/fr/docs/modelark/video-generation-tutorial)
and [billing formula](https://docs.byteplus.com/docs/ModelArk/1099320)
(`duration × width × height × 24 / 1024`), covering every published ratio and
adaptive first-frame output at durations 4–15. For the additional 3:2 and 2:3
ratios accepted by the generic Seedance 2.0 resolver, the test uses the largest
published 1080p pixel footprint as an envelope; the table has no exact dimensions
for those ratios.

Video authorization carries the resolved `video_resolution` as a top-level
field alongside `route_type: "videos"` and `max_tokens`. The internal contract
accepts `480p`, `720p`, and `1080p`; other existing fixed-quote resolutions retain
their prior authorization shape. Chat, image, and embedding authorization never
send this field. The router acknowledges resolution pricing through
`data.video_tariff_resolution`.

In `cmd/enclave/video.go`, `authorizedVideoRoutes` requires an exact `1080p`
acknowledgment before admitting any BytePlus 1080p route, including fallbacks.
This check runs after quotes and authorization, when the acknowledgment is
known, but before job preparation or any paid queue request. On an older control
plane, a quoted and authorized Venice candidate can use the shared reservation;
its fixed-price settlement selects the Venice endpoint and releases the unused
hold, without billing BytePlus tokens. Caller routing restrictions and seed
compatibility still apply. If no eligible authorized candidate remains, the
enclave uses the shared durable rejection path for seeded and unseeded requests.
It prepares the deterministic job row at the authorization’s pinned authority
(`submitting`, no provider job ID). It tries the authorized primary, then candidates
in order, choosing the first known provider/endpoint that can carry a valid
row. A token-billed provider uses zero fixed quote and the output-token limit sent
in authorization (`max(1, maximumVideoTokenLimit(quotes))`). A fixed-price provider
uses the authorization's additional-cost reservation only when it is positive.
The row is never dispatched, whichever route it names. The enclave refunds there
with `video_tariff_unavailable`, and only after refund success marks the row failed
with `tariff_unavailable`.
The client receives HTTP 503 `video_tariff_unavailable`; BytePlus is never queued.
An existing row is returned unchanged with 202. If the inline refund or status
update fails, the submitting row survives restarts and main’s worker refunds it
once due (about 300 seconds, plus lease/polling delay) with
`video_submission_interrupted`, then marks it failed. Refund outages extend
recovery time; the row remains retryable. If prepare fails with a 5xx or transport
error, refund remains best effort and the response is 503
`video_job_store_unavailable`. Closing this prepare-outage gap is a non-goal. So is durable recovery when no authorized route can carry a valid
row (for example, only fixed-price routes with a zero additional-cost reservation),
or the router rejects prepare with a 4xx. In those cases refund is best effort
and the response retains the rejection's own 503 `video_tariff_unavailable` or
`video_routing_unavailable` code. Durability begins only once a row is stored.

When BytePlus was quoted at 1080p and the missing echo leaves no route, the tariff
error takes precedence even for seed. Other seeded no-route rejections use the
same durable helper with `video_routing_unavailable` / `routing_unavailable`.
Other unseeded no-route rejections retain main’s best-effort refund and response
bytes. See [seeded rejection recovery](video-seed-routing-rollout.md).
480p and 720p continue to work without the acknowledgment.

The router implementation owns tariff freezing, credit holds, and settlement;
see the companion quill-router `docs/video-generation.md` section
“Internal resolution tariff contract.” The enclave tests exercise that contract
with a mock control plane; they do not replace the router's billing tests.

Deploy in this order:

1. Router [#1546](https://github.com/Lore-Hex/quill-router/pull/1546) live: accept `video_resolution` and freeze resolution tariffs.
2. Router [#1555](https://github.com/Lore-Hex/quill-router/pull/1555) live: exclude derived resolution and token limits from video fingerprints and replay legacy authorizations.
3. Enclave [#465](https://github.com/Lore-Hex/quill-cloud-proxy/pull/465): seeded routing and durable rejection.
4. Enclave [#468](https://github.com/Lore-Hex/quill-cloud-proxy/pull/468): direct BytePlus 1080p.

A four-second 1080p retry changes the derived token bound from one to 400,000.
Router #1555 must recover the original authorization despite that change and the
added resolution, while preserving the request fingerprint, idempotency key,
and caller provider policy. The enclave contract test checks original-job replay
with no new hold, prepare, or dispatch; router tests own legacy fingerprint migration.
