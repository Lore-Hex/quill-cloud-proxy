# Calling TrustedRouter from a browser

The attested API at `https://api.trustedrouter.com` supports cross-origin
browser calls to Chat Completions, Responses, Messages, embeddings, images,
speech, transcription, Responses input-token counting, and key introspection.
Public model discovery and attestation also support cross-origin reads.

`OPTIONS` on these API routes returns `204` before authentication. Inference
preflights allow `GET`, `POST`, and `OPTIONS`, with `Authorization` and
`Content-Type` explicitly allowed. Other request headers, including SDK metadata
and idempotency keys, are allowed with the non-credentialed wildcard. Preflights
do not authorize spending or call a provider.

Normal responses, including JSON, SSE, authorization errors, and provider
errors, carry `Access-Control-Allow-Origin: *`. JavaScript can also read
`X-Request-ID`, `Request-ID`, `Retry-After`, `X-Should-Retry`, and
`X-Inference-Receipt` when present.

Authentication still requires an explicit API key. Use `credentials: "omit"`;
the gateway does not enable cookie credentials. The confidential-only hostname
keeps its existing route and provider restrictions. CORS does not make an
ordinary downstream provider confidential or independently verify attestation.

Keep a user's scoped key in memory, or obtain a delegated application key through
Sign in with TrustedRouter. Never embed a shared server key in a published
JavaScript bundle. CORS allows the page receiving the key to use it, so users
must trust that page. Prompts go directly to the attested gateway; the frontend
still handles their plaintext before sending.

```javascript
// apiKey is supplied by the user or a delegated authorization flow.
const response = await fetch("https://api.trustedrouter.com/v1/chat/completions", {
  method: "POST",
  credentials: "omit",
  headers: {
    Authorization: `Bearer ${apiKey}`,
    "Content-Type": "application/json",
  },
  body: JSON.stringify({
    model: "trustedrouter/auto",
    messages: [{ role: "user", content: "Hello" }],
    stream: true,
  }),
});
if (!response.ok) throw new Error(await response.text());
for await (const chunk of response.body.pipeThrough(new TextDecoderStream())) {
  // Pass chunks to an SSE parser; network chunks need not be complete events.
  console.log(chunk);
}
```

Account, console, administrative, batch, and video-job routes are not added to
this CORS policy. Malformed HTTP framing can be rejected before a route is known.

## Regression checks

Run the Go CORS tests normally. With an installed Playwright and Chromium,
the optional real-browser test exercises a local gateway with a fake provider:

```sh
cd enclave-go
QUILL_PLAYWRIGHT_MODULE=/path/to/node_modules/playwright \
  go test -tags cloud_gcp,llm_multi ./cmd/enclave -run TestBearerCORSRealBrowser -v
```

After rollout, the browser smoke can check preflight, readable authentication
errors, and cookie-credential rejection on production without paid inference:

```sh
QUILL_PLAYWRIGHT_MODULE=/path/to/node_modules/playwright \
  node tools/browser-cors-smoke.cjs https://api.trustedrouter.com
```
