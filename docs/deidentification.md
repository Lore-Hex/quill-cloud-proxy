# Optional provider-bound de-identification

Send `"deidentify": true` on `/v1/chat/completions`, `/v1/responses`, or
`/v1/messages`. It is a gateway feature, not a provider capability. Omit the
field or send `false` for the existing execution path. `null`, strings, and
numbers are rejected rather than treated as disabled.

```python
response = client.chat.completions.create(
    model="anthropic/claude-opus-5.5",
    messages=[{"role": "user", "content": "Write a greeting to Alice Smith."}],
    extra_body={"deidentify": True},
)
```

The gateway runs National Design Studio's Rampart inside the measured enclave.
The provider receives typed placeholders for detected identifiers, not the
placeholder-to-value table. The caller receives restored text and function
arguments in both JSON and SSE, with JSON-output escaping preserved. Reasoning
and opaque/signed provider artifacts are passed through without restoration:
editing their text could invalidate provider signatures. They may contain
placeholders. Resubmitted conversation history is scanned
again. Mapping is request-scoped; no conversation state or prompt is written to
disk. Unknown placeholders remain literal. Restoration happens before the
normal response adapters and receipt hashing; provider usage and prices remain
unchanged. Provider retries and fallbacks receive the same redacted request.

The worker includes the neural classifier and deterministic validators. It
scans long text using Rampart's overlapping token windows, redacts detected
geography as well as other categories, and masks repeat occurrences of values
detected elsewhere in the same request. The model and tokenizer are bundled by
immutable revision and SHA-256. Runtime model downloads are disabled.

## Supported shapes and bounds

- Text messages, system/instructions, text blocks, function definitions and
  schemas, function arguments/results, and request metadata are inspected.
- Function/field identifiers cannot be changed without breaking schemas. If
  Rampart detects an identifier in a fixed name, key, or numeric field, the
  request is rejected rather than sent unchanged.
- Images, audio, documents, remote files, opaque/signed thinking history,
  hosted tools/search, orchestration, predictions, and explicit prompt cache
  keys are unsupported when enabled. Unsupported or unknown request shapes
  return `400 deidentify_unsupported` before provider authorization.
- Enabled requests are limited to 256 KiB and 4,096 text fields. At most two
  workers run simultaneously per instance; overload, model failure, or the
  30-second processing deadline returns `503 deidentify_unavailable` before
  provider authorization. Native Messages uses its native error envelope.
- There is no heuristic-only fallback and no fallback to sending raw input.
- Disabled requests do not start a worker, initialize a model, acquire a slot,
  copy a prompt, or wrap the response. The opt-out branch allocates zero bytes.
  Enabled requests incur local processing time and use randomized placeholders,
  which can reduce upstream prompt-cache hits.

## Limitations

De-identification is not guaranteed anonymization, encryption, a provider ZDR
policy, or an assurance that all secrets are removed. Rampart can miss entities,
particularly non-Latin names and contextual identifiers, and can over-redact.
Inference from retained context is still possible. It does not inspect pixels,
audio, files, or external tool results it cannot read. Restoration covers exact
placeholders; a model that changes or paraphrases a token cannot be reliably
restored. The provider may also generate new personal information independently.

Rampart model/runtime are by National Design Studio, licensed under CC BY 4.0:
https://huggingface.co/nationaldesignstudio/rampart and
https://github.com/nationaldesignstudio/rampart.
TR adds enclave execution, request validation, randomized request-local tokens,
known-value consistency, and protocol-aware response restoration. These changes
are not an endorsement by the original authors. The image includes the model
card and both license copies. See `enclave-go/rampart/package-lock.json` and
`model-sha256.json` for pinned artifacts.

## Verification

`npm ci --ignore-scripts && npm run model && npm test` in `enclave-go/rampart`
tests the real model using synthetic data only. The scratch-image test also
runs with networking disabled. `TR_RAMPART_TEST_NODE=/absolute/path/to/node go
test -tags cloud_gcp,llm_multi ./cmd/enclave -run TestDeidentifyRealModelEndToEnd`
tests all three HTTP endpoints in JSON and streaming modes with a fake provider
that sees only masked input. No provider credentials or paid calls are needed.
