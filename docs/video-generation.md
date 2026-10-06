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
actual tokens per second and reaches at most 1,500,000 tokens, below the
2,000,000-token authorization cap. Settlement reports the provider's actual
`completion_tokens`; the router applies its authorization-time tariff snapshot.
The reservation ceiling is never billed as usage.

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
enclave refunds the authorization and returns HTTP 503 with
`video_tariff_unavailable`. It never stores or queues that BytePlus job.
480p and 720p continue to work without the acknowledgment.

The router implementation owns tariff freezing, credit holds, and settlement;
see the companion quill-router `docs/video-generation.md` section
“Internal resolution tariff contract.” The enclave tests exercise that contract
with a mock control plane; they do not replace the router's billing tests.
