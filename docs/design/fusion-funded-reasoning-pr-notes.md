# Fund fusion reasoning budgets independently of the final answer

Panel members and judges now request an explicit `max_tokens` equal to the positive synth/preset `config.MaxCompletionTokens` override, or `fusionPanelReasoningTokens = 32768`. Caller `max_tokens`, including unset, zero, small, and large values, no longer supplies the inner budget. Selector, mapper, map part, and reducer requests use the same rule. Before authorization, each inner limit is reduced to a known positive output maximum in the enclave's existing public model catalog cache (`top_provider.max_completion_tokens` or `max_output_tokens`, taking the smaller if both exist). Unknown/absent/null metadata leaves the explicit configured/default limit in place. Context length is not treated as an output limit. This lookup does not fetch a catalog or invent hardcoded provider maxima.

Authorization receives exactly the explicit value subsequently passed to the provider adapter, including any catalog cap. The whole panel obtains holds before any member starts; admission failure releases earlier holds and returns the authorization error. Successful admission still executes members concurrently. Judge, selector, map/reduce stages, fallback attempts, and rescues continue to authorize individually before execution. A provider failure after admission can still leave a partial panel, as before.

This deliberately changes balance compatibility: the usual per-member output reservation rises from **2,048 to 32,768 tokens (16×)**. The old unset default was 1,200. Six uncapped default members reserve **196,608 output tokens**, previously at most 12,288, plus their respective input estimates, each priced for its own model. A 60,000-token final-answer limit no longer requests six 60,000-token panel holds; an explicit synth override of 60,000 still does, subject to known member caps. Short eventual answers do not excuse an insufficient initial balance. The request is refused before starting its panel, rather than silently losing underfunded members. This compatibility decision applies to the released preset versions as well as rolling aliases; their model graphs and prompts are unchanged.

The `fusion.final` answer request retains the caller's limit and existing unset semantics. For nested advisor fusion, the inner panel/judge now have the independent reasoning budget; its final advice still uses `AdvisorMaxTokens` (normally 4,096). The funding guarantee added here concerns the explicit inner reasoning requests, not a new global spending guard on unset final/direct requests. Provider compliance with explicit token limits, control-plane pricing/input estimates, and successful settlement remain existing contracts; the tests do not claim to prove external control-plane or provider implementations.

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

The same change applies when these graphs run inside advisor orchestration: `plato`, `plato-1.0`, `plato-3.0`, `plato-4.0`, `plato-pro`, `plato-pro-1.0`, `plato-pro-2.0`; `aristotle`, `aristotle-1.0`, `aristotle-1.1`, `aristotle-2.0`; `socrates`, `socrates-1.0`, `socrates-1.1`, `socrates-2.0`, `socrates-3.0`, `socrates-pro`, `socrates-pro-1.0`, `socrates-pro-plus`, `socrates-pro-plus-1.0`; `openpatcher-a1`, `openpatcher-fast1`, `openpatcher-g1`, `openpatcher-g2`, `openpatcher-g3`; `athena`, `athena-1.0`, `athena-2.0`; `liberty-2.0`, `liberty-3.0`, and `parasail/liberty-2.0`. Custom `advisor` configurations inherit it whenever they invoke a fusion graph. Ordinary direct advisor/worker calls retain their own limits and timeouts.

Changed token-budget stages: `fusion.panel`, `fusion.judge`, `fusion.selector`, `fusion.mapreduce.mapper`, `fusion.mapreduce.part`, `fusion.mapreduce.reducer`. Both streaming final implementations and collected final calls retain the fusion HTTP timeout opt-in. Selector still returns the selected panel answer verbatim; the reducer uses the explicitly requested common inner-stage rule.

The **GLM-5.2 synth-code-only overthinking guards are unchanged**: panel threshold 1,000 thinking tokens, final threshold 2,000; same-model rescue caps 800 and 1,600 respectively. Their gating, rescue instructions, and fallback behavior remain unchanged. The catalog clamp only reduces a known lower inner maximum; it never raises a rescue cap to 32,768.

## Remaining time bounds; no infrastructure changes

- Fusion upstream HTTP attempts keep a **5-minute idle watchdog** and **30-minute total ceiling per HTTP attempt**, replacing the ordinary **10-minute total client timeout**. Progress is upstream bytes, including raw SSE comments. Retries start new HTTP timers, not a new reusable parent context. This is not a 30-minute orchestration guarantee or whole-orchestration deadline.
- `provider_stream.go` retains **20 seconds** to the first translated write on earlier candidates (`QUILL_FIRST_BYTE_TIMEOUT_SECONDS`) and normally **300 seconds** on the last/only candidate (`QUILL_FINAL_FIRST_BYTE_TIMEOUT_SECONDS`). Paths that disable the long-last-candidate allowance retain 20 seconds there too. Raw SSE comments consumed by a translating adapter do not satisfy that guard. Silent reasoning can therefore fail much earlier than 30 minutes.
- The raw enclave connection retains **30 seconds per response write**, resetting for each write, rather than a 30-second total response deadline. Request headers have **10 seconds**; keep-alive idle time is normally **60 seconds** when enabled (configurable), between requests. These read deadlines are cleared while processing the current request. Legacy keep-alive mode uses the **10-second** request-read timeout between requests; disabling keep-alive closes after the response.
- The parent pump has no total `io.Copy` deadline and requests TCP keep-alives every **60 seconds**. AWS NLB TCP idle timeout defaults to **350 seconds** and keep-alive packets can refresh it; this is not a reliable absolute request ceiling. See [AWS connection idle timeout documentation](https://docs.aws.amazon.com/elasticloadbalancing/latest/network/network-load-balancers.html#connection-idle-timeout).
- Ordinary advisor worker invoke deadlines default to **60 seconds**, ordinary advisor calls to **90 seconds**, each configurable from **1 to 180 seconds**. The advisor dispatcher intentionally does not wrap nested fusion with those direct-call deadlines. Any existing parent context deadline still wins. Caller SDK/browser/proxy deadlines can be shorter; their deployed/client-specific values cannot be inferred from this checkout.

## Validation

The socket-free balance fake prices each member, holds concurrent reservations, refuses insufficient funds, refunds unused holds, and checks settlement input/output against its specific authorization. The successful worst-case provider reports the entire explicit output allowance, including reasoning. Coverage includes all six inner stage builders, configured/default limits, and known/unknown catalog caps. End-to-end handler tests verify the final caller limit remains separate.

Orchestration HTTP tests obtain their timeout context only from production code: panel, judge, both streaming-final paths, fusion nested under an advisor, a failed judge HTTP attempt followed by fallback, and unchanged ordinary calls. The HTTP provider streams longer than its short baseline timeout and records the actual request deadline. The adapter test also verifies the explicit 32,768-token bound is on the OpenAI-compatible wire. Existing streamhttp idle/total/cancellation/Close tests remain in place. Existing GLM rescue regressions use a socket-free gateway to run in this sandbox.

Validation used `GOTOOLCHAIN=auto` and a writable `GOCACHE=/tmp/qcp-go-cache` (the default cache was outside the sandbox's writable roots). For each CI tag pair below: `go build -tags "$tags" ./...`, `go vet -tags "$tags" ./...`, focused `go test -race -tags "$tags"` over `./cmd/enclave ./internal/llm ./internal/streamhttp ./internal/trustedrouter`, and an attempted `go test -race -tags "$tags" ./... -count=1 -timeout=90s`.

| CI tag pair | Build | Vet | Focused race regressions | Full race suite |
| --- | --- | --- | --- | --- |
| `cloud_aws,llm_bedrock` | Pass | Pass | Pass | Socket binding blocked |
| `cloud_aws,llm_multi` | Pass | Pass | Pass | Socket binding blocked |
| `cloud_azure,llm_multi` | Pass | Pass | Pass | Socket binding blocked |
| `cloud_gcp,llm_vertex` | Pass | Pass | Pass | Socket binding blocked |
| `cloud_gcp,llm_multi` | Pass | Pass | Pass | Socket binding blocked |

Each focused run passed **13 top-level tests and 42 subtests**. The full suites are **incomplete**: `bind: operation not permitted` prevents socket-dependent tests in `cmd/enclave`, `cmd/parent-pump`, `internal/broadcast`, `internal/byokcache`, `internal/enclavetls`, `internal/llm`, and `internal/trustedrouter` in all five pairs; Azure additionally blocks `internal/bootstrap`. No other package failure category appeared. The full-suite attempts preceded only the final timing-preservation refactor and extra reservation assertions; build/vet/focused race checks were rerun on the final source.

Mutation verification removed each production `WithFusionTimeout` separately and ran `TestFusionOrchestrationHTTPTimeouts`: removing the collected call opt-in failed panel/judge, observed streaming final, nested advisor, and retry subtests; removing the standalone streaming-final opt-in failed its subtest. Both calls were restored. `git diff --check` passes. No infrastructure was changed and no commit was created.
