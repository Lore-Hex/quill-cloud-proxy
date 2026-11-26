package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

// applyCacheUsage is the one place the one-hour count is bounded: it is a
// subset of the cache writes, so settlement never sees more than the total.
func TestApplyCacheUsageBoundsOneHourCacheWrites(t *testing.T) {
	for _, tc := range []struct {
		name                    string
		creation, oneHour, want int
	}{
		{"none", 2000, 0, 0},
		{"part", 2000, 800, 800},
		{"all", 2000, 2000, 2000},
		{"above the total", 2000, 3000, 2000},
		{"without any cache writes", 0, 800, 0},
		{"negative", 2000, -800, 0},
		{"negative total", -1, 800, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			usage := trustedrouter.Usage{}
			applyCacheUsage(&usage, adapter.StreamResult{Usage: &adapter.StreamUsage{
				InputTokens: 14, OutputTokens: 6, CacheReadInputTokens: 6081,
				CacheCreationInputTokens: tc.creation, CacheCreation1hInputTokens: tc.oneHour, InputExcludesCache: true,
			}})
			if usage.CacheCreation1hInputTokens != tc.want {
				t.Fatalf("CacheCreation1hInputTokens = %d, want %d", usage.CacheCreation1hInputTokens, tc.want)
			}
			// The neighbouring fields are copied as before.
			if usage.CacheCreationInputTokens != tc.creation || usage.CacheReadInputTokens != 6081 || !usage.InputExcludesCache {
				t.Fatalf("usage = %+v", usage)
			}
		})
	}
	usage := trustedrouter.Usage{}
	applyCacheUsage(&usage, adapter.StreamResult{})
	if usage.CacheCreation1hInputTokens != 0 {
		t.Fatalf("no usage object: %+v", usage)
	}
}

// oneHourCacheLLM replies with a native Anthropic stream whose message_start
// usage is given verbatim; message_delta repeats the totals without a breakdown.
type oneHourCacheLLM struct{ startUsage string }

func (f *oneHourCacheLLM) InvokeStreaming(_ context.Context, _ *types.OpenAIChatRequest, _ *types.AnthropicMessagesRequest, out io.Writer, _ ...llm.InvokeOptions) error {
	_, err := fmt.Fprintf(out, `event: message_start
data: {"type":"message_start","message":{"id":"msg_1h","type":"message","role":"assistant","content":[],"model":"claude","stop_reason":null,"usage":%s}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hello"}}

event: message_delta
data: {"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"input_tokens":14,"cache_creation_input_tokens":2000,"cache_read_input_tokens":6081,"output_tokens":6}}

event: message_stop
data: {"type":"message_stop"}

`, f.startUsage)
	return err
}

// With costReportingAuthorization's rates (input 1, output 3, cache read 0.1,
// cache write 1.25 microdollars per token, request fee 7):
//
//	fee 7 + input 14 + output 18 + cache read 6081*0.1 = 608.1 -> 608
//	all 2000 writes at 1.25                              = 2500 -> 3147
//	1200 writes at 1.25 = 1500, 800 one-hour at 2 = 1600        -> 3747
const (
	fiveMinuteWritesCost = 7 + 14 + 18 + 608 + 2500
	oneHourWritesCost    = 7 + 14 + 18 + 608 + 1500 + 1600
)

// A provider-reported one-hour count reaches the settle body, and the local
// price that annotates usage.cost, on every route and both response modes.
// Without the breakdown the settle carries no such key.
func TestOneHourCacheWritesReachSettleAndLocalCostOnEveryRoute(t *testing.T) {
	t.Setenv("QUILL_USAGE_HEARTBEAT", "off")
	originalQueue := settlementRetries
	t.Cleanup(func() { settlementRetries = originalQueue })
	for _, tc := range []struct {
		name       string
		startUsage string
		oneHour    any // the settle body's value; nil when the key must be absent
		cost       int
	}{
		{"one-hour writes", `{"input_tokens":14,"cache_creation_input_tokens":2000,"cache_read_input_tokens":6081,"cache_creation":{"ephemeral_5m_input_tokens":1200,"ephemeral_1h_input_tokens":800},"output_tokens":1}`, float64(800), oneHourWritesCost},
		{"count above the total is bounded", `{"input_tokens":14,"cache_creation_input_tokens":2000,"cache_read_input_tokens":6081,"cache_creation":{"ephemeral_1h_input_tokens":9000},"output_tokens":1}`, float64(2000), 7 + 14 + 18 + 608 + 4000},
		{"five-minute writes only", `{"input_tokens":14,"cache_creation_input_tokens":2000,"cache_read_input_tokens":6081,"cache_creation":{"ephemeral_5m_input_tokens":2000,"ephemeral_1h_input_tokens":0},"output_tokens":1}`, nil, fiveMinuteWritesCost},
		{"no breakdown", `{"input_tokens":14,"cache_creation_input_tokens":2000,"cache_read_input_tokens":6081,"output_tokens":1}`, nil, fiveMinuteWritesCost},
	} {
		for _, route := range []string{"chat.completions", "responses", "messages"} {
			for _, stream := range []bool{false, true} {
				// "settled": the control plane returns its price. "unpriced": it
				// returns none, so usage.cost is the gateway's own local price.
				for _, scenario := range []string{"settled", "unpriced"} {
					t.Run(fmt.Sprintf("%s/%s/stream=%t/%s", tc.name, route, stream, scenario), func(t *testing.T) {
						settlementRetries = &settlementRetryQueue{jobs: make(chan settlementRetryJob, 100)}
						auth := costReportingAuthorization()
						auth.AuthorizationID = "cost-auth-1h"
						var out bytes.Buffer
						var settleBodies []map[string]any
						var settleModes []string
						gateway := trustedrouter.New("http://127.0.0.1:18080", "test", &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
							body := ""
							switch r.URL.Path {
							case "/internal/gateway/authorize":
								encoded, _ := json.Marshal(map[string]any{"data": auth})
								body = string(encoded)
							case "/internal/gateway/settle":
								var wire map[string]any
								if err := json.NewDecoder(r.Body).Decode(&wire); err != nil {
									t.Fatal(err)
								}
								settleBodies = append(settleBodies, wire)
								settleModes = append(settleModes, r.Header.Get("X-TR-Settlement-Mode"))
								body = fmt.Sprintf(`{"data":{"cost_microdollars":%d,"disposition":"finalized"}}`, tc.cost)
								if scenario == "unpriced" {
									body = `{"data":{}}`
								}
							default:
								t.Fatalf("unexpected path %s", r.URL.Path)
							}
							return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
						})})
						req := &types.OpenAIChatRequest{Model: "test-model", Stream: stream, StreamOptions: &types.ChatStreamOptions{IncludeUsage: true}, Messages: []types.OpenAIChatMessage{{Role: "user", Content: "hi"}}}
						options := []llm.InvokeOptions{{Model: "test-model", Provider: "anthropic", EndpointID: "served"}}
						provider := &oneHourCacheLLM{startUsage: tc.startUsage}
						logs := captureStderr(t, func() {
							if route == "messages" {
								body := []byte(fmt.Sprintf(`{"model":"test-model","max_tokens":32,"stream":%t,"messages":[{"role":"user","content":"hi"}]}`, stream))
								serveMessages(context.Background(), &out, provider, body, gateway, nil, "test-key", "", "cost-reporting-1h", requestAttributionHeaders{})
							} else if stream {
								serveStreaming(context.Background(), &out, provider, req, &types.AnthropicMessagesRequest{}, options, gateway, auth, nil, time.Now(), nil, route, "cost-reporting-1h", "test-model")
							} else if route == "responses" {
								serveResponsesNonStreaming(context.Background(), &out, provider, req, &types.AnthropicMessagesRequest{}, options, gateway, auth, nil, time.Now(), nil, "cost-reporting-1h", "test-model")
							} else {
								serveChatNonStreaming(context.Background(), &out, provider, req, &types.AnthropicMessagesRequest{}, options, gateway, auth, nil, time.Now(), nil, "cost-reporting-1h", "test-model")
							}
						})
						if len(settleBodies) != 1 || len(settlementRetries.jobs) != 0 {
							t.Fatalf("settles = %d, queued retries = %d", len(settleBodies), len(settlementRetries.jobs))
						}
						settle := settleBodies[0]
						if settleModes[0] != "" {
							t.Fatalf("settlement mode header = %q, want a synchronous settle", settleModes[0])
						}
						if settle["actual_input_tokens"] != float64(14) || settle["actual_output_tokens"] != float64(6) || settle["cache_read_input_tokens"] != float64(6081) || settle["cache_creation_input_tokens"] != float64(2000) || settle["route_type"] != route || settle["usage_estimated"] != false {
							t.Fatalf("settle body = %#v", settle)
						}
						if got, present := settle["cache_creation_1h_input_tokens"]; got != tc.oneHour || present != (tc.oneHour != nil) {
							t.Fatalf("cache_creation_1h_input_tokens = %v (present %v), want %v; body = %#v", got, present, tc.oneHour, settle)
						}
						// The local price equals the control plane's, so nothing is logged.
						for _, line := range strings.Split(logs, "\n") {
							if strings.Contains(line, "usage_cost_mismatch") && strings.Contains(line, "cost-auth-1h") {
								t.Fatalf("local price disagreed with the settled price: %s", line)
							}
						}
						response, err := http.ReadResponse(bufio.NewReader(&out), nil)
						if err != nil {
							t.Fatal(err)
						}
						body, err := io.ReadAll(response.Body)
						response.Body.Close()
						if err != nil || response.StatusCode != 200 {
							t.Fatalf("status = %d, err = %v: %s", response.StatusCode, err, body)
						}
						usage := oneHourFinalUsage(t, body, route, stream)
						for _, key := range []string{"cost_microdollars", "total_cost_microdollars"} {
							if usage[key] != float64(tc.cost) {
								t.Fatalf("%s = %v, want %d; body = %s", key, usage[key], tc.cost, body)
							}
						}
						// The gateway adds no one-hour count of its own to any reply. Only
						// the streamed Messages relay forwards the provider's own breakdown.
						if bytes.Contains(body, []byte("cache_creation_1h")) {
							t.Fatalf("one-hour count in public response: %s", body)
						}
						if !(route == "messages" && stream) && bytes.Contains(body, []byte("ephemeral_1h_input_tokens")) {
							t.Fatalf("provider breakdown in a translated response: %s", body)
						}
					})
				}
			}
		}
	}
}

// oneHourFinalUsage returns the reply's terminal usage object.
func oneHourFinalUsage(t *testing.T, body []byte, route string, stream bool) map[string]any {
	t.Helper()
	var payload map[string]any
	if !stream {
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Fatal(err)
		}
		usage, _ := payload["usage"].(map[string]any)
		if usage == nil {
			t.Fatalf("no usage: %s", body)
		}
		return usage
	}
	var usage map[string]any
	for _, line := range strings.Split(string(body), "\n") {
		if !strings.HasPrefix(line, "data: {") {
			continue
		}
		payload = nil
		if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &payload); err != nil {
			t.Fatal(err)
		}
		var candidate map[string]any
		switch route {
		case "chat.completions":
			candidate, _ = payload["usage"].(map[string]any)
		case "responses":
			if payload["type"] == "response.completed" {
				response, _ := payload["response"].(map[string]any)
				candidate, _ = response["usage"].(map[string]any)
			}
		case "messages":
			if payload["type"] == "message_delta" {
				candidate, _ = payload["usage"].(map[string]any)
			}
		}
		if candidate != nil {
			usage = candidate
		}
	}
	if usage == nil {
		t.Fatalf("no terminal usage: %s", body)
	}
	return usage
}

// The local price follows the control plane's rule: the one-hour subset at
// twice the selected tier's input rate. A settled price that used the
// five-minute rate for every write is reported as a mismatch.
func TestReportedSettlementPricesOneHourCacheWrites(t *testing.T) {
	usage := trustedrouter.Usage{RouteType: "messages", SelectedEndpoint: "served", SelectedModel: "test-model", InputTokens: 14, OutputTokens: 6, CacheReadInputTokens: 6081, CacheCreationInputTokens: 2000, CacheCreation1hInputTokens: 800, InputExcludesCache: true}
	auth := costReportingAuthorization()
	auth.AuthorizationID = "cost-auth-1h-unit"
	if got := reportedSettlement(nil, auth, usage, nil); !got.HasCost() || got.CostMicrodollars != oneHourWritesCost {
		t.Fatalf("local price = %+v, want %d", got, oneHourWritesCost)
	}
	withoutCount := usage
	withoutCount.CacheCreation1hInputTokens = 0
	if got := reportedSettlement(nil, auth, withoutCount, nil); !got.HasCost() || got.CostMicrodollars != fiveMinuteWritesCost {
		t.Fatalf("local price without a one-hour count = %+v, want %d", got, fiveMinuteWritesCost)
	}
	// A provider whose prompt count includes the cache prices the same writes.
	openAI := costReportingAuthorization()
	openAI.Provider = "openai"
	inclusive := usage
	inclusive.InputTokens, inclusive.InputExcludesCache = 14+6081+2000, false
	if got := reportedSettlement(nil, openAI, inclusive, nil); !got.HasCost() || got.CostMicrodollars != oneHourWritesCost {
		t.Fatalf("cache-inclusive local price = %+v, want %d", got, oneHourWritesCost)
	}
	for _, settled := range []int{oneHourWritesCost, fiveMinuteWritesCost} {
		settlement := &trustedrouter.SettleResult{CostMicrodollars: settled, CostMicrodollarsKnown: true}
		logs := captureStderr(t, func() {
			if got := reportedSettlement(settlement, auth, usage, nil); got != settlement {
				t.Fatalf("settlement changed: %+v", got)
			}
		})
		var mismatches []string
		for _, line := range strings.Split(logs, "\n") {
			if strings.Contains(line, "cost-auth-1h-unit") {
				mismatches = append(mismatches, line)
			}
		}
		want := []string(nil)
		if settled != oneHourWritesCost {
			want = []string{fmt.Sprintf(`enclave.usage_cost_mismatch level=error authorization_id="cost-auth-1h-unit" endpoint_id="served" local_cost_microdollars=%d settled_cost_microdollars=%d`, oneHourWritesCost, settled)}
		}
		if strings.Join(mismatches, "\n") != strings.Join(want, "\n") {
			t.Fatalf("settled %d: log = %q, want %q", settled, mismatches, want)
		}
	}
}

// A parent's one-hour count is the sum of its children's, as its cache-write
// total is.
func TestFusionAggregateSumsOneHourCacheWrites(t *testing.T) {
	child := func(creation, oneHour int) fusionCallResult {
		return fusionCallResult{Result: adapter.StreamResult{Usage: &adapter.StreamUsage{
			InputTokens: 10, OutputTokens: 5, CacheCreationInputTokens: creation, CacheCreation1hInputTokens: oneHour, InputExcludesCache: true,
		}}}
	}
	parent := fusionAggregateStreamUsage(100, 50, []fusionCallResult{child(2000, 800)}, []fusionCallResult{child(500, 500), child(300, 0), {}})
	if parent == nil || parent.CacheCreationInputTokens != 2800 || parent.CacheCreation1hInputTokens != 1300 {
		t.Fatalf("parent usage = %+v, want 2800 cache writes with 1300 for one hour", parent)
	}
	// A nested parent sums its children's parents the same way.
	nested := fusionAggregateStreamUsage(1, 1, []fusionCallResult{{Result: adapter.StreamResult{Usage: parent}}, child(10, 10)})
	if nested == nil || nested.CacheCreationInputTokens != 2810 || nested.CacheCreation1hInputTokens != 1310 {
		t.Fatalf("nested usage = %+v", nested)
	}
	// Children without one-hour writes leave the aggregate as it was.
	plain := fusionAggregateStreamUsage(100, 50, []fusionCallResult{child(2000, 0), child(500, 0)})
	if plain == nil || *plain != (adapter.StreamUsage{InputTokens: 100, OutputTokens: 50, CacheCreationInputTokens: 2500}) {
		t.Fatalf("aggregate without one-hour writes = %+v", plain)
	}
	// The count alone does not make an aggregate, as before.
	if got := fusionAggregateStreamUsage(100, 50, []fusionCallResult{child(0, 7)}); got != nil {
		t.Fatalf("aggregate from a one-hour count alone = %+v", got)
	}
}

// The web-search aggregate takes its cache writes from the final call only,
// and the one-hour count with them.
func TestWebSearchAggregateCarriesFinalCallOneHourCacheWrites(t *testing.T) {
	outcome := responsesWebSearchOutcome{InputTokens: 30, OutputTokens: 9}
	outcome.Final.Result.Usage = &adapter.StreamUsage{CacheCreationInputTokens: 2000, CacheCreation1hInputTokens: 800, InputExcludesCache: true}
	usage := aggregateWebSearchStreamUsage(outcome)
	if usage.CacheCreationInputTokens != 2000 || usage.CacheCreation1hInputTokens != 800 {
		t.Fatalf("usage = %+v", usage)
	}
}

// A queued settle retry keeps the one-hour count: compaction freezes the same
// body with the one added key, and the retry sends those bytes synchronously.
func TestSettlementRetryKeepsOneHourCacheWrites(t *testing.T) {
	for _, tc := range frozenRetryCases() {
		if tc.name != "stream_settle_failure" {
			continue
		}
		const total = `"cache_creation_input_tokens":5,`
		if strings.Count(tc.wantBody, total) != 1 {
			t.Fatalf("golden retry body has no cache writes: %s", tc.wantBody)
		}
		wantBody := strings.Replace(tc.wantBody, total, `"cache_creation_1h_input_tokens":3,`+total, 1)
		gateway, captured := frozenRetryGateway(t, nil)
		q := &settlementRetryQueue{jobs: make(chan settlementRetryJob, 2), maxAttempts: 1}
		job := tc.job()
		job.trGateway = gateway
		job.usage.CacheCreation1hInputTokens = 3
		if !q.Enqueue(job) {
			t.Fatal("retry was not accepted")
		}
		queued := <-q.jobs
		if queued.frozenErr != nil || queued.frozen == nil || string(queued.frozen.Body) != wantBody {
			t.Fatalf("frozen retry (err %v)\n got: %s\nwant: %s", queued.frozenErr, queued.frozen.Body, wantBody)
		}
		q.process(t.Context(), queued)
		got := captured()
		if len(got) != 1 || got[0].path != "/internal/gateway/settle" || got[0].body != wantBody || got[0].header.Get("X-TR-Settlement-Mode") != "" {
			t.Fatalf("retry requests = %+v", got)
		}
		return
	}
	t.Fatal("no stream settle retry case")
}
