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

### Claude models: known limits

Nothing in this section is new behavior. It states what the gateway does
today, because a switch beside `reasoning_effort` now reaches it.

A Claude model takes the adaptive path when its ID contains one of
`claude-opus-4-6`, `claude-opus-4-7`, `claude-opus-4-8`, `claude-opus-5`,
`claude-sonnet-4-6`, `claude-sonnet-5` or `claude-fable-5`. A request that
names an effort is sent there with `thinking: {"type": "adaptive"}` and the
effort as `output_config.effort`. Every other Claude ID takes the budget
path, which includes Haiku 4.5, Sonnet 4.5 and Opus 4.5. On the budget path
the effort becomes a thinking budget:
1,024 tokens for `low`, 4,096 for `medium`, 8,192 for `high` and `xhigh`.
On alone is 4,096. Opus 4.5 is also sent the effort as
`output_config.effort`, as written.

On the budget path, `max`, `minimal` and an effort the gateway does not know
set no thinking budget. That holds beside an On switch too:
`thinking: {"type": "enabled"}` with `reasoning_effort: "max"` is the request
`reasoning: {"enabled": true, "effort": "max"}`, and it is sent with no
`thinking` at all. Opus 4.5 gets no thinking and `output_config.effort` set
to `max`, `minimal` or the unknown word as written, none of which Anthropic
documents for that model. The spelling with the effort outside the object,
`reasoning: {"enabled": true}` beside `reasoning_effort`, is read differently:
it thinks at 4,096 tokens whatever the effort says.

An explicit Off written as the `reasoning` object does not govern on the
budget path, except on Opus 4.5: `reasoning: {"enabled": false}` beside
`reasoning_effort: "high"` thinks at 8,192 tokens on Haiku 4.5 and Sonnet 4.5.
On Opus 4.5 the same request is sent `thinking: {"type": "disabled"}`. The
switch spellings are not affected, because a disabled switch drops the effort.

### OpenAI models that use tools

A first-party OpenAI request uses the Responses tool route when the model ID
is `gpt-5.5`, `gpt-5.6`, `gpt-6` or `gpt-6.N`, alone or with a `-` suffix,
except `gpt-5.5-pro`, and the request carries tools or tool history. That
route takes an effort and has no switch. It used to fail every request that
carried a switch, when its provider request was prepared. It now honors what
it can:

* On with an effort is that effort, sent as written. That includes `none`
  and a word OpenAI does not list: the request is the one the effort alone
  already sends, and if the model rejects it the next provider is tried.
* On alone is the request without the switch. These models reason by default.
* Off is sent as effort `none` for exactly these model IDs, each alone or
  followed by a `-YYYY-MM-DD` snapshot date: `gpt-5.5`, `gpt-5.6-luna`,
  `gpt-5.6-sol`, `gpt-5.6-terra`, `gpt-6-luna`, `gpt-6-sol` and
  `gpt-6.1-terra`. OpenAI documents `none` for them.

Everything else the route cannot honor keeps the failure it had, when the
provider request is prepared, after billing authorization. That is Off on
every other model ID of the route (for example `gpt-6-astra` and
`gpt-6.1-sol`, which document that they reject `none`, any `-pro` model, and
any member not listed above), and a thinking token budget
(`thinking.budget_tokens` or `reasoning.max_tokens`), which these models do
not take. A `reasoning` value that is not an object (`true`, `false` or a
string) and any other key inside the object (for example `reasoning.type`)
also fail there, as before: `reasoning: true` is not read as On, though
`reasoning: {"enabled": true}` is. The failure is retryable, as before: the request goes to the next
provider authorized for the model, which is sent the `reasoning` object
unchanged. If there is none, the caller gets the error and the hold is
refunded.

### Hosts outside the effort list

Some chat endpoints are known to read a top-level `reasoning_effort`, and are
always sent the effort there: Meta, OpenAI, Google AI Studio, DeepSeek, Z.ai,
Kimi, Mistral, Alibaba, Tencent, Tinfoil, Grok, Baseten, Crusoe, Cerebras,
Fireworks and Privatemode. Nothing in this section changes what they are
sent.

Every other OpenAI-compatible host is sent the reasoning fields as the
request holds them. For those hosts the effort of a switch plus effort
request goes inside the `reasoning` object,
`"reasoning": {"effort": "high", "enabled": true}`, while an effort sent alone
goes as top-level `"reasoning_effort": "high"`. So adding a switch to a
working `reasoning_effort` request changes where such a host finds the
effort, and an effort written only inside the object may be ignored there:
of the hosts observed, Together and Nebius, and probably Parasail, ignore it.

Six of those hosts were observed, and only these six are sent the effort
top-level as well: DeepInfra, Novita, Parasail, Together, Nebius and io.net.
The list is short on purpose. The top-level copy reaches requests that are
served today, so it goes only to hosts that were seen to take it. On these
six, when the request names an effort of `low`, `medium` or `high` and does
not turn reasoning off, the effort is sent as top-level `reasoning_effort`
wherever the request wrote it, and the `reasoning` object is sent exactly as
the request holds it:

* `reasoning_effort: "high"` alone is sent as written. This is unchanged.
* `reasoning: {"effort": "high"}`, with or without `"enabled": true`, is sent
  as that object and `"reasoning_effort": "high"`. Before, the object was
  sent alone.
* A switch beside an effort, for example `thinking: {"type": "enabled"}` with
  `reasoning_effort: "high"`, is sent as
  `"reasoning": {"effort": "high", "enabled": true}` and
  `"reasoning_effort": "high"`. So on these six hosts, adding a switch to a
  working `reasoning_effort` request does not change where the host finds
  the effort.
* Only `low`, `medium` and `high` are copied. Any other word inside the
  object (`none`, `off`, `minimal`, `xhigh`, `max`, `auto`, or one the gateway
  does not know) is sent inside the object alone, as before. Those were not
  observed, and a host that validates the top-level field could refuse them.
* Off governs. With `reasoning: {"enabled": false}` nothing is added, even
  beside an effort. This is unchanged.
* A request that names no effort is unchanged.

The same rule covers the other spellings that put an effort inside the
object: `output_config.effort` on chat completions, and `reasoning.effort` on
the Responses API. The top-level copy is the effort in lower case without
surrounding spaces, and the object keeps the caller's spelling. A blank
top-level `reasoning_effort` counts as absent. A native `POST /v1/messages`
request is passed through as before: its `thinking` object is forwarded as
written and no `reasoning_effort` is derived from it.

The evidence is a live probe through the production gateway on 2026-11-16,
with the model `openai/gpt-oss-120b`, the same puzzle each time, and one
request per cell. The numbers are completion tokens, which for this model are
almost all reasoning:

| host | top-level low | top-level high | object low | object high | both low | both high |
|---|---|---|---|---|---|---|
| deepinfra | 474 | 1029 | 436 | 1008 | 516 | 1431 |
| novita | 624 | 729 | 384 | 619 | 525 | 958 |
| parasail | 346 | 908 | 459 | 582 | 312 | 729 |
| together | 309 | 826 | 713 | 663 | 371 | 1057 |
| nebius | 394 | 828 | 526 | 580 | 385 | 922 |
| io-net | 350 | 719 | 374 | 842 | 372 | 820 |

"Object" is `"reasoning": {"effort": E, "enabled": true}` with no top-level
field. "Both" is the top-level field and the object together. All six honor
a top-level `reasoning_effort`. Together and Nebius, and probably Parasail,
ignore an effort that is only inside the object. All six accept both fields
together and honor the effort.

Each of the six was also sent a model that does not reason, with top-level
`reasoning_effort: "high"`, and all six answered 200: DeepInfra, Novita,
Parasail and io.net on a Llama 3.3 70B route, Together and Nebius on another
chat model that does not reason. So on these six hosts the added field does
not turn a working request into a refusal for a model that does not reason.

The remaining limits. The effort probe used one model, with one request per
cell, at `low` and `high`. No other host outside the effort list has been
observed: such a host may read the top-level field, the object, both or
neither, and until it is observed it is sent the fields as the request holds
them. Adding a host to the six needs an observation of that host: that it
honors a top-level effort, that it accepts both fields together, and that it
accepts the top-level field on a model that does not reason. A host that
rejects a request is a provider error like any other: the request goes to
the next provider authorized for the model.

### Open decisions

These are not decided by this release:

* (a) What `max`, `minimal` and unknown efforts should do on the Claude
  budget path. Two problems come with turning thinking on where it is off
  today. Anthropic documents thinking as incompatible with a `temperature`
  other than 1, `top_k`, a `top_p` below 0.95, forced tool use and prefill,
  so a request that returns 200 today could get a provider 400. A thinking
  budget also raises the `max_tokens` sent to the provider above what the
  hold was sized for (512 becomes 8,704 and 4,096 becomes 12,288 at 8,192
  tokens of budget), as `high` already does.
* (b) Whether an explicit Off written as the `reasoning` object should govern
  on the whole Claude budget path. Today
  `reasoning: {"enabled": false}` beside `reasoning_effort: "high"` thinks on
  Haiku 4.5 and Sonnet 4.5, and does not on Opus 4.5.
* (c) Whether to refuse, with a 400 before billing authorization, an Off and
  a token budget that the OpenAI Responses tool route cannot honor. No host of these models
  can stop their reasoning or take a token budget, so a refusal is the honest
  answer. The cost is that requests another host serves today, without the
  option honored, would start to fail.

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
