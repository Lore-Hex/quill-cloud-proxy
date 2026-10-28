# Reasoning output controls

Chat completions accept `include_reasoning` as a boolean compatibility option:

* `true` returns reasoning when the provider supplies it.
* `false` omits reasoning text, signatures, and raw reasoning traces from the
  public JSON or SSE response. It does not disable model thinking.
* Omitted or `null` preserves the existing default of returning available reasoning.

The modern `reasoning.exclude` boolean has the same output-only behavior and
takes precedence when both options are supplied. It also works on Responses.
Malformed values return a 400 identifying the offending parameter before billing.

```json
{
  "model": "z-ai/glm-5.2",
  "messages": [{"role": "user", "content": "What is 6 times 7?"}],
  "reasoning": {"effort": "high"},
  "include_reasoning": false
}
```

To disable thinking itself, use the model's supported `reasoning.enabled` or
effort control instead. Output visibility never changes the thinking budget,
token usage, billing, tool arguments, or internal tool-continuation state.
These visibility options are consumed inside the enclave, not sent as
unsupported parameters to upstream providers. Orchestration and web-search
responses follow the same output policy. Explicitly opted-in content broadcast
is a separate destination policy, not controlled by `include_reasoning`.
