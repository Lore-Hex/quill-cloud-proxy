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

The accepted effort levels are `low`, `medium`, `high`, `xhigh`, and `max`. A
model that does not have a level is sent the nearest one it has; see
[Claude models](#claude-models). JSON and streaming requests use the
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

### Claude models

A reasoning effort is a request for depth. On a Claude model it never makes
the request fail and it is never ignored: each model is sent the nearest thing
it has. The gateway reads the class of a model from its ID after routing has
chosen the model, so a fallback model is sent its own class's request. The
same rules hold on every Claude route: Anthropic, Bedrock and Vertex.

| Class | Models | How it thinks | Efforts it has |
| --- | --- | --- | --- |
| Full | Opus 4.7, 4.8, 5 and 5.5, Sonnet 5 and 5.5, Haiku 5.5, Fable 5.x, Mythos 5.x | adaptive | `low`, `medium`, `high`, `xhigh`, `max` |
| 4.6 | Opus 4.6, Sonnet 4.6 | adaptive | `low`, `medium`, `high`, `max` |
| Opus 4.5 | Opus 4.5 | token budget, plus an effort | `low`, `medium`, `high` |
| Budget | every other Claude model: Haiku 4.5, Sonnet 4.5, Opus 4 and 4.1, Sonnet 4, the 3.x models | token budget | none |

A model is in the Full class when its ID, lowercased and with `.` read as
`-`, contains `claude-opus-4-7`, `claude-opus-4-8`, `claude-opus-5`,
`claude-sonnet-5`, `claude-haiku-5`, `claude-fable-5` or `claude-mythos-5`. It
is in the 4.6 class when it contains `claude-opus-4-6` or `claude-sonnet-4-6`,
and it is Opus 4.5 when it contains `claude-opus-4-5`. Every other Claude ID
is in the Budget class. A test fails when a route table names a Claude model
that has not been given a class, so a new model cannot land in the Budget
class unnoticed.

An adaptive model is sent `thinking: {"type": "adaptive"}` and the effort as
`output_config.effort`. A budget model is sent
`thinking: {"type": "enabled", "budget_tokens": N}`. This is what each effort
sends:

| Effort | Full | 4.6 | Opus 4.5 | Budget |
| --- | --- | --- | --- | --- |
| `minimal` | effort `low` | effort `low` | effort `low`, no thinking | no thinking |
| `low` | effort `low` | effort `low` | effort `low`, 1,024 tokens | 1,024 tokens |
| `medium` | effort `medium` | effort `medium` | effort `medium`, 4,096 tokens | 4,096 tokens |
| `high` | effort `high` | effort `high` | effort `high`, 8,192 tokens | 8,192 tokens |
| `xhigh` | effort `xhigh` | effort `high` | effort `high`, 8,192 tokens | 8,192 tokens |
| `max` | effort `max` | effort `max` | effort `high`, 8,192 tokens | 8,192 tokens |

An effort the model does not have becomes the nearest one it has, rounding
down. `minimal` is below every ladder. It becomes the lowest effort where the
model has an effort field. Where the only control is a token budget it sets
no thinking, because the smallest budget Anthropic takes is 1,024 tokens.

The switch and the effort work together:

* Off governs on every class. `reasoning: {"enabled": false}`, or any switch
  spelling of Off, sends no thinking, even beside an effort or a token
  budget. The Budget class is sent no `thinking` field. Opus 4.5 and the
  adaptive classes are sent `thinking: {"type": "disabled"}`. Sonnet 5.5 is
  sent `thinking: {"type": "between_tools"}`, the Off that Anthropic names
  for that model: it does not think before responding, and the short updates
  it writes between tool calls come back as thinking blocks. An effort of
  `none` is the same request as Off. The `max_tokens` sent is the caller's
  own, with no room added for a budget that is not sent.
* On beside an effort is that effort, wherever the effort is written.
  `reasoning: {"enabled": true}` beside `reasoning_effort: "low"` sends what
  `reasoning_effort: "low"` alone sends, and so does
  `reasoning: {"enabled": true, "effort": "low"}`.
* On alone, with no effort, is a 4,096 token budget.
* A token budget the caller names (`thinking.budget_tokens` or
  `reasoning.max_tokens`) is sent as written, and the provider judges it.

Budget thinking is sent as a request Anthropic accepts. This applies to Opus
4.5 and the Budget class, whether the budget came from an effort, from On or
from a budget the caller named:

* Anthropic refuses budget thinking beside a `temperature` other than 1,
  beside `top_k`, and beside a `top_p` below 0.95. The gateway does not send
  those fields with a thinking budget. A `temperature` of exactly 1 and a
  `top_p` of 0.95 or more are sent. A request with no thinking keeps all of
  its sampling fields.
* A forced tool choice or an assistant prefill beats an effort. Anthropic
  refuses thinking when `tool_choice` forces a tool (`"required"`, or a named
  function) and when the last message is from the assistant. In those
  requests thinking that only an effort asked for is not sent, and
  `max_tokens` is not raised for it. Opus 4.5 is still sent its effort.
  Thinking the caller asked for explicitly, with On or with a token budget,
  is still sent, and the provider judges it.

The adaptive classes are unchanged here: with an effort they are sent no
`temperature` and no `top_p`, and `top_k` is sent as written. An adaptive
model whose caller set no output limit is sent `max_tokens` of 32,000,
because adaptive thinking counts against the limit.

Limits that remain:

* Opus 5.5 and Fable 5.x cannot be turned off. Off sends them
  `thinking: {"type": "disabled"}`, and Anthropic refuses that for those
  models.
* On alone, with no effort, is a 4,096 token budget on every class. Haiku 5.5
  refuses budget thinking, so On alone fails there. On beside an effort
  works.
* A thinking budget raises the `max_tokens` sent to the provider above what
  the hold was sized for, when the budget is not below the output limit (512
  becomes 8,704 and 4,096 becomes 12,288 at 8,192 tokens of budget). `high`
  has always done this. `max` on the Budget class now does too.
* An effort the gateway does not know is not on any ladder. It is sent as
  written in `output_config.effort` to the adaptive classes and to Opus 4.5,
  and Anthropic refuses a word that is not one of its own. It sets no
  thinking on Opus 4.5 and on the Budget class.
* Off is the object `reasoning: {"enabled": false}` or a switch. A bare
  `reasoning: false` is not read as Off.

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

### Hosts outside the effort list: known limit

Some chat endpoints are known to read a top-level `reasoning_effort`, and are
always sent the effort there: Meta, OpenAI, Google AI Studio, DeepSeek, Z.ai,
Kimi, Mistral, Alibaba, Tencent, Tinfoil, Grok, Baseten, Crusoe, Cerebras,
Fireworks and Privatemode. Every other OpenAI-compatible host is sent the
reasoning fields as the request holds them. For those hosts the effort of a
switch plus effort request goes inside the `reasoning` object,
`"reasoning": {"effort": "high", "enabled": true}`, while an effort sent alone
goes as top-level `"reasoning_effort": "high"`. So adding a switch to a
working `reasoning_effort` request changes where such a host finds the
effort. Which of the two each of those hosts reads has not been observed.

### Open decisions

These are not decided by this release:

* (c) Whether to refuse, with a 400 before billing authorization, an Off and
  a token budget that the OpenAI Responses tool route cannot honor. No host of these models
  can stop their reasoning or take a token budget, so a refusal is the honest
  answer. The cost is that requests another host serves today, without the
  option honored, would start to fail.
* (d) Where the effort of a switch plus effort request should go on hosts
  outside the effort list: inside the `reasoning` object as today, top-level
  as an effort alone goes, or both. It needs a live probe of those hosts.

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
