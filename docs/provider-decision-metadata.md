# Decision response metadata

`neurometric/structured-decisions` returns its provider-supplied `decision`
object at the top level of `/v1/chat/completions` responses, alongside
`choices` and `usage`. For example:

```json
{
  "decision": {
    "type": "choice",
    "answer": "billing",
    "confidence": 0.98,
    "probabilities": {"billing": 0.99, "technical": 0.01}
  }
}
```

The object is optional, and its fields depend on the task. Scores are reported
by the provider, not calibrated or endorsed by TrustedRouter.

With `stream: true`, one SSE chunk carries the top-level `decision` object
before the terminal finish chunk and `[DONE]`, even if usage streaming was not
requested. Clients should read this response extension in addition to content
deltas. Ordinary text-generation responses without a decision omit it.

Wharf currently omits this object from its upstream SSE. For this model only,
the enclave makes one bounded JSON upstream request and then emits JSON or SSE
to match the caller. The short answer is buffered; this is not incremental
upstream generation. Other Neurometric models continue using upstream SSE.

Decision data stays on the response path, outside usage, settlement, billing
metadata and logs. It does not cause another inference call or a separate fee.
The adapter accepts only an object (up to 64 KiB) from Neurometric; malformed
optional metadata is ignored without discarding the answer or usage.
