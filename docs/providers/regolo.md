# Regolo Streaming Usage

Regolo's native streaming API reports visible completion tokens separately from
`completion_tokens_details.reasoning_tokens`. Its `total_tokens` also excludes
that reasoning. Non-streaming JSON uses inclusive completion counts instead.

Verified directly against `https://api.regolo.ai/v1/chat/completions` on
September 14, 2026, using a synthetic exact-PONG prompt:

| Native streaming model | Completion | Reasoning | Billable output |
| --- | ---: | ---: | ---: |
| qwen3.5-9b | 3 | 167 | 170 |
| glm5.2 | 2 | 137 | 139 |
| qwen3.5-122b | 3 | 140 | 143 |
| qwen3.8-27b | 3 | 37 | 40 |
| gpt-oss-20b | 2 | 28 | 30 |

Regolo's [reasoning documentation](https://docs.regolo.ai/models/features/reasoning/)
states that reasoning is billed at output rates. The gateway always invokes
these providers through their streaming path, including for a non-streaming
client request. Normalize Regolo's usage before either response adaptation or
settlement, preserving the reasoning subtotal for diagnostics.

Do not apply this addition to other OpenAI-compatible providers: their
completion counts generally already include reasoning. The provider-scoped
regression test checks both behaviors and repeated cumulative usage reports.
Recheck native streaming and JSON usage when Regolo changes its accounting
contract; an upstream switch to inclusive SSE counts requires updating this
normalization to avoid double billing.
