# Speech Gateway

`POST /v1/audio/speech` implements the OpenRouter request shape and returns
binary audio. The initial adapters call xAI `/v1/tts` and Mistral
`/v1/audio/speech` directly, using the existing managed credentials and
cloud-specific HTTP transport. Mistral's base64 JSON envelope is decoded inside
the enclave. Audio is buffered and validated before settlement and delivery;
this is not incremental synthesis streaming.

The enclave counts input Unicode code points and sends only the count,
model/provider selection, caller metadata, and a credential-keyed content HMAC
to control-plane authorization. The control plane computes and reserves a
frozen character-price quote. Successful settlement must match that quote with
zero token usage. Failures release the reservation. A reused idempotency key
returns 409: audio is not retained and must not be regenerated or charged twice.
Neither input text nor generated audio is sent to settlement or broadcast.

Provider privacy filters still apply. Routing through the enclave does not
make either ordinary upstream speech endpoint confidential. BYOK, custom
voices, input arrays and unpriced provider options are rejected explicitly.

## Release Order

Deploy this gateway first, then the companion quill-router speech catalog and
authorization changes. An old control plane rejects the unknown speech model;
the gateway also fails closed without a positive character reservation. Do not
publish the speech catalog until the serving gateway pool supports this route.
Keep normal multi-cloud release coordination and measured-image gates intact.

## Tests

Run the full gateway tests for each production build-tag combination. An
optional small paid adapter smoke uses `TR_SPEECH_LIVE_TEST=1`, `GROK_API_KEY`,
and `MISTRAL_API_KEY`:

```sh
go test ./internal/speech -run '^TestSpeechLive$' -count=1 -v
```

Live tests log only audio sizes/types, never credentials or input/output content.
After deployment, call the public speech endpoint with both models and check
`X-Generation-Id`, `X-Usage-Cost`, exact character billing, idempotent 409, JSON
errors and both cloud-local and canonical-origin health.
