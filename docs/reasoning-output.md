# Reasoning output controls

## Claude effort on chat completions

`POST https://api.trustedrouter.com/v1/chat/completions` accepts Anthropic's
`output_config.effort` spelling. For Claude Opus 5.5, this request reaches the
Anthropic transport with `output_config: {"effort":"high"}` and
`thinking: {"type":"adaptive"}`:

```json
{
  "model": "anthropic/claude-opus-5.5",
  "messages": [{"role": "user", "content": "What is 6 times 7?"}],
  "output_config": {"effort": "high"},
  "max_tokens": 4096
}
```

The accepted effort levels are `low`, `medium`, `high`, `xhigh`, and `max`;
availability depends on the selected model. JSON and streaming requests use the
same forwarding path. You may also include `thinking: {"type":"adaptive"}`.
With an OpenAI SDK, put `output_config` in `extra_body`.

Chat normalizes this option to its existing `reasoning.effort` control. Use only
one effort spelling per request. Invalid values, conflicting controls, disabled
thinking combined with this alias, and unimplemented `output_config` members
return 400 before billing authorization. `null` is treated as omitted.
Use `response_format` for structured chat output, not `output_config.format`.

Native `POST /v1/messages` already forwards `output_config` and `thinking`
without this translation. Responses API clients should continue using
`reasoning: {"effort":"high"}`. Effort changes reasoning work and token cost;
it is not a setting for hiding reasoning text.

Reference: [Anthropic effort documentation](https://platform.claude.com/docs/en/build-with-claude/effort).

## Thinking switches on chat completions

Chat completions accept three spellings of the switch that turns thinking on
or off. Each is normalized to `reasoning.enabled`, and none is forwarded as
sent:

* `thinking: {"type": "enabled"}` or `{"type": "disabled"}`, as DeepSeek and
  Z.ai document it. `adaptive` and `budget_tokens` are the Claude forms.
* `enable_thinking: true` or `false`.
* `chat_template_kwargs: {"enable_thinking": false}` or `{"thinking": false}`,
  as clients written for vLLM and SGLang servers send it. These two boolean
  keys are the only ones accepted. Any other key returns a 400 naming it
  (`chat_template_kwargs.<key>`), because the object is never sent to a
  provider. An empty object or `null` is treated as omitted.

A switch and `reasoning_effort` are different controls, one for whether the
model thinks and one for how much, and may be sent together:

```json
{
  "model": "z-ai/glm-5.2",
  "messages": [{"role": "user", "content": "What is 6 times 7?"}],
  "thinking": {"type": "enabled"},
  "reasoning_effort": "high"
}
```

* On with an effort is thinking at that effort: the same request as
  `reasoning: {"enabled": true, "effort": "high"}`.
* Off governs. With a disabled switch the effort is dropped and thinking stays
  off, as those providers' own APIs behave.
* On with `reasoning_effort: "none"` contradicts itself and returns 400.
* `thinking.budget_tokens` with `reasoning_effort` is two depth controls and
  returns 400.
* Adaptive thinking takes its effort from `output_config.effort` or
  `reasoning_effort`, not both.
* Send one switch. `thinking` beside `enable_thinking` or
  `chat_template_kwargs`, and any switch beside the `reasoning` object, return
  400. The boolean spellings may repeat each other when they agree.

Every refusal here happens before billing authorization.

## Reasoning visibility

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
