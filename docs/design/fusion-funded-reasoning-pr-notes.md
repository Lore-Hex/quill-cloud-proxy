# Fund fusion reasoning budgets independently of the final answer

Panel members and judges now request an explicit `max_tokens` equal to the positive synth/preset `config.MaxCompletionTokens` override, or `fusionPanelReasoningTokens = 32768`. Caller `max_tokens`, including unset, zero, small, and large values, no longer supplies the inner budget. Selector, mapper, map part, and reducer requests use the same rule. Before authorization, each non-final fusion limit is reduced to a known positive output maximum in the enclave's existing public model catalog cache (`top_provider.max_completion_tokens` or `max_output_tokens`, taking the smaller if both exist). Unknown/absent/null metadata leaves the explicit configured/default limit in place. Context length is not treated as an output limit. This lookup does not fetch a catalog or invent hardcoded provider maxima.

Authorization receives the explicit **total output allowance**, including any catalog cap; reasoning and visible output must both fit inside it. Before authorization, inner requests copy and clamp inherited numeric reasoning hints (`max_tokens`, `thinking_budget`, `budget_tokens`), including dynamic thinking, below the total. An internal, non-wire limit also bounds adapter-derived thinking budgets while preserving model-specific effort/adaptive modes. Anthropic/Bedrock therefore cannot use `anthropicMaxTokensForThinking` to expand the funded total; Gemini's numeric thinking configuration fits inside `maxOutputTokens`, and funded inner calls retain that output limit even on image-capable Gemini paths; OpenAI-compatible `max_tokens`/`max_completion_tokens` retain that total. Explicit thinking is disabled when the total cannot accommodate Anthropic's 1,024-token thinking minimum plus visible output. The caller's reasoning object is never mutated.

The whole panel obtains holds **concurrently**, then waits for every admission result before any member starts. If one admission fails, every successful admission is refunded, including success arriving after the failure. Refunds use the control-plane client's cancellation-independent contexts. Holds already refunded inside authorization/option validation are not refunded twice. Admission relies on atomic control-plane reservations, as concurrent independent requests already do. Successful admission executes members concurrently. Judge, selector, map/reduce stages, fallback attempts, and rescues continue to authorize individually before execution. A provider failure after admission can still leave a partial panel, as before.

This deliberately changes balance compatibility: the usual per-member output reservation rises from **2,048 to 32,768 tokens (16×)**. The old unset default was 1,200. Six uncapped default members reserve **196,608 output tokens**, previously at most 12,288, plus their respective input estimates, each priced for its own model. A 60,000-token final-answer limit no longer requests six 60,000-token panel holds; an explicit synth override of 60,000 still does, subject to known member caps. Short eventual answers do not excuse an insufficient initial balance. The request is refused before starting its panel, rather than silently losing underfunded members. This compatibility decision applies to the released preset versions as well as rolling aliases; their model graphs and prompts are unchanged.

The `fusion.final` answer request retains the caller's positive explicit `max_tokens` and now constrains inherited reasoning inside that same total before authorization. We chose **reasoning-budget shaping**, not an increased reservation: the caller's limit remains an upper bound on visible output and cannot become a larger provider allowance. Reasoning and visible output share that total, so this does not promise the entire cap as visible text. In the reported case, `max_tokens=8192` with inherited `reasoning.max_tokens=32768` now authorizes and dispatches 8,192, with thinking bounded to 8,191, rather than dispatching 40,960. Final requests do not inherit the 32,768 default, synth override, or catalog clamp. Unset and nonpositive final limits retain their existing authorization estimates and wire semantics. For nested advisor fusion, the inner panel/judge have the independent reasoning budget; its final advice still uses `AdvisorMaxTokens` (normally 4,096) with the same explicit-limit guarantee. This is not a new global spending guard on unset final or ordinary direct requests. Provider compliance with explicit token limits, control-plane pricing/input estimates, and successful settlement remain existing contracts; the tests do not claim to prove external control-plane or provider implementations.

## Affected presets and stages

All names below have the `trustedrouter/` prefix unless stated otherwise.

| Family | Names affected |
| --- | --- |
| Generic orchestration | `synth`, `synth-code`, `fusion`, `fusion-code`, `selector`, `mapreduce`; their plugin/tool forms and custom panels |
| Iris | `iris`, `iris-1.0`, `iris-2.0`, `iris-3.0`, `iris-code`, `iris-code-1.0` |
| Prometheus | `prometheus`, `prometheus-1.0`, `prometheus-1.0-1m`, `prometheus-2.0`, `prometheus-3.0`, `prometheus-4.0`, `prometheus-code`, `prometheus-code-1.0` |
| Zeus | `zeus`, `zeus-1.0`, `zeus-1.0-mini`, `zeus-2.0`, `zeus-3.0`, `zeus-code`, `zeus-code-1.0` |
| OpenPatcher synthesis | `openpatcher-s1`, `openpatcher-s2`, `openpatcher-s3` |
| Liberty synthesis | `liberty-1.0`, `liberty-1.0-1m` |

The affected internal preset labels are `budget`, `budget-1.0`, `budget-2.0`, `budget-3.0`, `quality`, `quality-1.0`, `quality-1m`, `quality-2.0`, `quality-3.0`, `quality-4.0`, `frontier`, `frontier-1.0`, `frontier-2.0`, `frontier-3.0`, `frontier-mini`, `openpatcher-s1`, `openpatcher-s2`, `openpatcher-s3`, `liberty-1.0`, and `liberty-1.0-1m`. The generic synth plugin accepts `budget`, `quality`, and `frontier`; the other labels identify the named model graphs.

The same change applies when these graphs run inside advisor orchestration: `plato`, `plato-1.0`, `plato-3.0`, `plato-4.0`, `plato-pro`, `plato-pro-1.0`, `plato-pro-2.0`; `aristotle`, `aristotle-1.0`, `aristotle-1.1`, `aristotle-2.0`; `socrates`, `socrates-1.0`, `socrates-1.1`, `socrates-2.0`, `socrates-3.0`, `socrates-pro`, `socrates-pro-1.0`, `socrates-pro-plus`, `socrates-pro-plus-1.0`; `openpatcher-a1`, `openpatcher-fast1`, `openpatcher-g1`, `openpatcher-g2`, `openpatcher-g3`; `athena`, `athena-1.0`, `athena-2.0`; `liberty-2.0`, `liberty-3.0`, and `parasail/liberty-2.0`. Custom `advisor` configurations inherit it whenever they invoke a fusion graph. Ordinary advisor/worker calls retain their own limits and timeouts; their positive explicit limits now constrain inherited reasoning through the shared inner-call authorization boundary.

Independent default/catalog-budget stages: `fusion.panel`, `fusion.judge`, `fusion.selector`, `fusion.mapreduce.mapper`, `fusion.mapreduce.part`, `fusion.mapreduce.reducer`. The explicit authorization-versus-wire constraint also covers `fusion.final` and every other route through the inner-call helper. Both streaming final implementations and collected final calls retain the fusion HTTP timeout opt-in. Selector still returns the selected panel answer verbatim; the reducer uses the explicitly requested common inner-stage rule.

The **GLM-5.2 synth-code-only overthinking guards are unchanged**: panel threshold 1,000 thinking tokens, final threshold 2,000; same-model rescue caps 800 and 1,600 respectively. Their gating, rescue instructions, and fallback behavior remain unchanged. The catalog clamp only reduces a known lower inner maximum; it never raises a rescue cap to 32,768.

## Remaining time bounds; no infrastructure changes

- Fusion upstream HTTP attempts keep a **5-minute idle watchdog** and **30-minute total ceiling per HTTP attempt**, replacing the ordinary **10-minute total client timeout**. Progress is upstream bytes, including raw SSE comments. Retries start new HTTP timers, not a new reusable parent context. This is not a 30-minute orchestration guarantee or whole-orchestration deadline.
- `provider_stream.go` retains **20 seconds** to the first translated write on earlier candidates (`QUILL_FIRST_BYTE_TIMEOUT_SECONDS`) and normally **300 seconds** on the last/only candidate (`QUILL_FINAL_FIRST_BYTE_TIMEOUT_SECONDS`). Paths that disable the long-last-candidate allowance retain 20 seconds there too. Raw SSE comments consumed by a translating adapter do not satisfy that guard. Silent reasoning can therefore fail much earlier than 30 minutes.
- The raw enclave connection retains **30 seconds per response write**, resetting for each write, rather than a 30-second total response deadline. Request headers have **10 seconds**; keep-alive idle time is normally **60 seconds** when enabled (configurable), between requests. These read deadlines are cleared while processing the current request. Legacy keep-alive mode uses the **10-second** request-read timeout between requests; disabling keep-alive closes after the response.
- The parent pump has no total `io.Copy` deadline and requests TCP keep-alives every **60 seconds**. AWS NLB TCP idle timeout defaults to **350 seconds** and keep-alive packets can refresh it; this is not a reliable absolute request ceiling. See [AWS connection idle timeout documentation](https://docs.aws.amazon.com/elasticloadbalancing/latest/network/network-load-balancers.html#connection-idle-timeout).
- Ordinary advisor worker invoke deadlines default to **60 seconds**, ordinary advisor calls to **90 seconds**, each configurable from **1 to 180 seconds**. The advisor dispatcher intentionally does not wrap nested fusion with those direct-call deadlines. Any existing parent context deadline still wins. Caller SDK/browser/proxy deadlines can be shorter; their deployed/client-specific values cannot be inferred from this checkout.

## Validation (round 3)

The socket-free balance fake prices each member, holds concurrent reservations, refuses insufficient funds, refunds unused holds, and checks settlement input/output against its specific authorization. The worst-case provider now checks `AnthropicDispatchMaxTokens()` as well as the shared total. All six inner stage builders are exercised with inherited 32,768-token reasoning, configured/default totals, known/unknown catalog caps, and tiny budgets (including 1, 1,024, and 1,025). Parent reasoning remains unchanged.

Native wire tests serialize the production Anthropic, Bedrock, Gemini, and OpenAI-compatible projections and compare their output limits with `max_output_tokens` captured from a real `AuthorizeWithRoute` call against a socket-free control-plane fake. This is layered coverage: the orchestration tests exercise the actual stage builders and catalog clamp; the native tests exercise the same reasoning constraint helper, actual authorization serialization, and provider serializers. Cases cover numeric aliases, dynamic thinking, effort hints, catalog-sized limits, configured limits, image-capable Gemini paths, and the original 32,768 → 65,536 Anthropic regression. Adaptive Anthropic effort and Gemini's model-specific effort budgets have explicit preservation checks. No external provider/control-plane implementation is exercised.

The six-member admission fake blocks every authorization until all six are in flight, so a sequential implementation fails. Success checks that all six holds exist before each provider invocation. Failure waits for one denial, cancels the parent, then allows the last successful authorization to return; all five successes must be refunded exactly once and no provider may start.

Existing end-to-end final-limit and timeout regressions remain included. Validation uses `GOTOOLCHAIN=auto` and writable `GOCACHE=/tmp/qcp-go-cache`. For each CI tag pair: `go build -tags "$tags" ./...`, `go vet -tags "$tags" ./...`, focused race tests over orchestration, adapter, native-provider, stream timeout, and catalog-limit packages, then `go test -race -tags "$tags" ./... -count=1 -timeout=90s`.

| CI tag pair | Build | Vet | Focused race regressions | Full race suite |
| --- | --- | --- | --- | --- |
| `cloud_aws,llm_bedrock` | Pass | Pass | Pass | Socket binding blocked |
| `cloud_aws,llm_multi` | Pass | Pass | Pass | Socket binding blocked |
| `cloud_azure,llm_multi` | Pass | Pass | Pass | Socket binding blocked |
| `cloud_gcp,llm_vertex` | Pass | Pass | Pass | Socket binding blocked |
| `cloud_gcp,llm_multi` | Pass | Pass | Pass | Socket binding blocked |

All round-3 checks above were run on the round-3 source with Go 1.24.0 selected by `GOTOOLCHAIN=auto`. The focused race runs include the new `TestFundedInner*`, `TestConstrainReasoningBudget`, and `TestFusionPanelConcurrentAdmission` tests, all six stage budget/cap checks, end-to-end final-limit and orchestration timeout tests, and existing adapter/serializer checks. Separate race runs of the GLM panel/final rescue guards and native Anthropic effort/fallback preservation tests also pass under all five pairs.

The full suites are **incomplete**: `bind: operation not permitted` prevents socket-dependent tests in `cmd/enclave`, `cmd/parent-pump`, `internal/broadcast`, `internal/byokcache`, `internal/enclavetls`, `internal/llm`, and `internal/trustedrouter` in all five pairs; Azure additionally blocks `internal/bootstrap`. No other failure category appeared. The CI linter was not run. Validation logs are in `/tmp/qcp-round3-validation/<tag-pair>/` in this workspace environment.

`git diff --check` passes. No infrastructure was changed and no commit was created.


## Final-limit finding: route audit and regressions (round 4)

The only behavioral change in this follow-up is moving the positive explicit-limit constraint outside the non-final-fusion condition in `authorizeFusionCall`. Default insertion and catalog clamping remain inside that condition. No settlement, cancellation, refund, or admission logic was changed.

The route audit grepped every `runFusionCall*`, `runAuthorizedFusionCallAttempt`, `authorizeFusionCall`, and `AuthorizeWithRoute` call site, plus dynamic web-search route construction. The explicit-limit constraint is route-independent and runs before billing-route decoration:

- Fusion: `fusion.panel`, `fusion.judge`, `fusion.selector`, `fusion.mapreduce.mapper`, `fusion.mapreduce.part`, `fusion.mapreduce.reducer`, `fusion.final`.
- Advisor: `advisor.worker`, `advisor.advisor`, `advisor.context_summary`, `advisor.advisor_final`.
- Subagent: `subagent.controller`, `subagent.worker`.
- Decide completion calls: `decide`.
- Web search: `responses.web_search.planner`, `responses.web_search.final`, `chat.completions.web_search.planner`, `chat.completions.web_search.final`, and configurable route prefixes.
- Partner billing decorates these already-constrained logical routes with `partner.parasail.liberty-2.0.internal.`; fallback attempts and same-model rescues re-enter the same authorization boundary. Concurrent panel execution uses requests already constrained during admission.

Other authorization sites are ordinary top-level/direct or native-batch requests, image/embedding requests, partner aggregate billing, and the fixed-price `responses.polyphemus.select` model-selection API. The latter dispatches a selector, not a token-generating inner completion. None is an additional inner completion path that bypasses this helper.

`TestFusionFinalAuthorizationVersusWire` runs the actual collected final, streaming final, and observed-streaming final entry points. At the provider boundary it serializes the dispatched request with the production Anthropic, Bedrock, or Gemini projection and compares the wire total and numeric thinking budget against the real `AuthorizeWithRoute` payload captured by the socket-free control-plane fake. Three small exported projection wrappers make those existing serializers callable from orchestration tests; serializer behavior is unchanged. These tests do not merely reapply the constraint helper to a synthetic request.

Cases include the reported 8,192/32,768 mismatch, totals 1/1,024/1,025/60,000, inherited numeric aliases, dynamic thinking, effort-derived thinking, adaptive Anthropic, Gemini 2.5/3.1 and image-capable models, and unchanged unset/zero behavior. They also check visible response delivery and that the caller's request/reasoning remains unchanged. `TestFusionFinalPreservesCallerLimitWithCatalog` verifies that a lower cached catalog cap does not change the caller's final limit. `TestInnerRouteExplicitAuthorizationVersusWire` covers the audited inner route names, configurable/future names, and conflicting token-limit aliases.

An overlay run using the original round-3 `fusion.go` with the new tests fails in both collected and observed-streaming finals: native Anthropic and Bedrock serialize 40,960 against an 8,192 authorization; Gemini serializes a 32,768 thinking budget against an 8,192 total. The same regressions pass with the fix. The before-fix log is `/tmp/qcp-final-budget-before.log`; the route audit is `/tmp/qcp-final-budget-route-audit.txt`.

### Validation (round 4)

On the final source, `GOTOOLCHAIN=auto` selected Go 1.24.0 (`darwin/arm64`), with writable `GOCACHE=/tmp/qcp-go-cache`. Each CI tag pair ran `go build -tags "$tags" ./...`, `go vet -tags "$tags" ./...`, the focused regressions with `-race -count=1 -timeout=90s`, and `go test -race -tags "$tags" ./... -count=1 -timeout=90s`.

| CI tag pair | Build | Vet | Focused race regressions | Full race suite |
| --- | --- | --- | --- | --- |
| `cloud_aws,llm_bedrock` | Pass | Pass | Pass | Socket binding blocked |
| `cloud_aws,llm_multi` | Pass | Pass | Pass | Socket binding blocked |
| `cloud_azure,llm_multi` | Pass | Pass | Pass | Socket binding blocked |
| `cloud_gcp,llm_vertex` | Pass | Pass | Pass | Socket binding blocked |
| `cloud_gcp,llm_multi` | Pass | Pass | Pass | Socket binding blocked |

The focused runs include the new final/route/catalog regressions, all existing funded-inner native wire checks available under each tag pair, reasoning constraints, concurrent panel admission, six-stage budgets/catalog caps, end-to-end final-limit checks, HTTP timeout checks, GLM panel/final rescue guards, and Anthropic effort/fallback preservation. Bedrock projections run with `cloud_aws`; Gemini projections run with `llm_multi`; Anthropic projections run under all five pairs.

Full-suite failures are limited to `bind: operation not permitted` in `cmd/enclave`, `cmd/parent-pump`, `internal/broadcast`, `internal/byokcache`, `internal/enclavetls`, `internal/llm`, and `internal/trustedrouter`, plus `internal/bootstrap` on Azure. No race reports, test timeouts, or other failure categories appeared. Socket-dependent coverage therefore remains incomplete. The CI linter was not run. Commands, results, and logs are saved in `/tmp/qcp-final-budget-validation/<tag-pair>/`, with a combined `results.json` in that directory's parent.

`git diff --check` passes. Settlement remains untouched. No commit was created.
