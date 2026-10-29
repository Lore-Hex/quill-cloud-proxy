# Kling 4.0 via Runway

Canonical `kling/v4` maps to Runway `kling_4` through the existing Runway
credential, tunnel and asynchronous task transport. There are no new secrets
or hosts. Do not add a Venice/fal route based only on a public model card.

The initial adapter accepts text and first/last-frame images, 3-30 seconds,
720p/1080p and native audio. It rejects reference assets, video edits,
negative prompts, seed and audio-off rather than silently ignoring them.
Text aspect ratios map to Runway's exact pixel pairs; image jobs use
`auto_720p` / `auto_1080p` to preserve source framing.

The quote uses standard USD 0.157/s or 0.235/s, rounds the full job upward
to whole USD 0.01 credits, and then applies the existing 20% video fee.
Temporary discounts do not alter this list-price contract. The control-plane
price refresh audits the official standard rates and rounding declaration.

Sources:
- https://dev.runway.com/learn/kling-4-0-api
- https://docs.dev.runwayml.com/guides/pricing/

Real upstream text canary on 2026-10-29:
`354b4b81-a2d7-4994-a4b0-5c64fe5cd2ad`, SUCCEEDED, 1280x720, H.264/AAC,
3.042 seconds; visual output matches the synthetic prompt.
First/last-frame image canary `9807d696-d478-4f85-acdc-25b65c49c16a`
also SUCCEEDED: 1920x1080, H.264/AAC, 3.042 seconds.

This is Standard privacy, not confidential or ZDR. Deploy gateway support
from clean merged main using the normal two-cloud coordinator, staged trust
publication and per-instance verification. Activate the control-plane
catalog only after all relevant gateways are ready. Do not disturb the
already-qualified Maple gateways or another release's reservation.
