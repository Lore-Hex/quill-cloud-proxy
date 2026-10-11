# Speech Gateway

`POST /v1/audio/speech` implements the OpenRouter request shape and returns
binary audio. Adapters call ElevenLabs, xAI, Mistral, Google AI Studio Gemini
3.8 TTS, and Microsoft MAI Voice directly using managed credentials and
cloud-specific HTTP transport. Mistral and Gemini base64 audio is decoded inside
the enclave. Audio is buffered and validated before settlement and delivery;
this is not incremental synthesis streaming.

The enclave counts input Unicode code points and sends only the count,
model/provider selection, caller metadata, and a credential-keyed content HMAC
to control-plane authorization. The control plane computes and reserves a
frozen character-price quote, except Gemini, which reserves bounded maximum
input/output tokens and settles actual provider-reported tokens against frozen
rates. Character-priced settlement must match the quote with zero token usage.
Failures release the reservation. A reused idempotency key
returns 409: audio is not retained and must not be regenerated or charged twice.
Neither input text nor generated audio is sent to settlement or broadcast.

Provider privacy filters still apply. Routing through the enclave does not
make any ordinary upstream speech endpoint confidential. BYOK, custom
voices, input arrays and unpriced provider options are rejected explicitly.

## ElevenLabs Voices

All four models (`elevenlabs/eleven-v3`, `elevenlabs/eleven-multilingual-v2`,
`elevenlabs/eleven-flash-v2.5`, and `elevenlabs/eleven-turbo-v2.5`) accept the
same premade voices. Set `voice` to an exact ID below; there is no default voice.
All other IDs, including custom voices, and voice names are rejected.

| Voice | Gender | Accent | `voice` ID |
| --- | --- | --- | --- |
| George | Male | — | `JBFqnCBsd6RMkjVDRZzb` |
| Sarah | Female | American | `EXAVITQu4vr4xnSDxMaL` |
| Alice | Female | British | `Xb7hH8MSUJpSbSDYk0k2` |
| Matilda | Female | American | `XrExE9yKIg1WjnnlVkGX` |
| Bella | Female | American | `hpp4J3VqNfWAUOO0d1Us` |
| Jessica | Female | American | `cgSgspJ2msm6clMCkdW9` |
| Laura | Female | American | `FGY2WhTYpPnrIDTdsKH5` |
| Lily | Female | British | `pFZP5JQG7iQjIQuC4Bku` |

The female IDs and accents were read from ElevenLabs `GET /v1/voices` on
2026-10-10, with category `premade`. George remains the first voice used by the
optional live smoke test. ElevenLabs billing uses the input Unicode character
count and the model's character rate, independent of the chosen voice.

## Release Order

Deploy this gateway first, then the companion quill-router speech catalog and
authorization changes. An old control plane rejects the unknown speech model;
the gateway also fails closed without a positive applicable reservation. Do not
publish the speech catalog until the serving gateway pool supports this route.
Keep normal multi-cloud release coordination and measured-image gates intact.

`GET /v1/models` relays the control-plane catalog; it does not derive
`supported_voices` from the enclave allowlist. The read-only quill-router
`origin/main` inspected for this change (`20ed38c2`, 2026-10-10) has no ElevenLabs
speech catalog or character-billing authorization support, and still registers
`/audio/speech` as an unsupported stub. Its companion speech implementation must
publish the eight IDs above in each ElevenLabs model's `supported_voices` when
it lands. There is no existing George-only list on that ref to update.

The Azure bundle for this release is
`5baf19644b84457289ad6254e9969dbc` (October 10, 2026). It preserves all
71 entries from the deployed `d51b399193294a1aaa6cfa1b34890e31` bundle and
adds only `trustedrouter-elevenlabs-api-key` and `trustedrouter-azure-api-key`.
Pin `QUILL_AZURE_BUNDLE_VERSION` to the new version when following the
Azure build/template/policy/bind/deploy/audit runbook. Do not edit the public
attestation release document until the actual measured rollout is verified.

## Tests

Run the full gateway tests for each production build-tag combination. An
optional small paid adapter smoke uses `TR_SPEECH_LIVE_TEST=1`, `GROK_API_KEY`,
`MISTRAL_API_KEY`, `GEMINI_API_KEY`, `AZURE_FOUNDRY_API_KEY`, and
`ELEVEN_LABS_API_KEY`:

```sh
go test ./internal/speech -run '^TestSpeechLive$' -count=1 -v
```

Live tests log only audio sizes/types, never credentials or input/output content.
After deployment, call the public speech endpoint with each provider and check
`X-Generation-Id`, `X-Usage-Cost`, exact character/token billing, idempotent 409, JSON
errors and both cloud-local and canonical-origin health.
