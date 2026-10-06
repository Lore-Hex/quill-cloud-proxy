package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func costReportingAuthorization() *trustedrouter.Authorization {
	return &trustedrouter.Authorization{
		AuthorizationID: "cost-auth", Model: "test-model", Provider: "anthropic", EndpointID: "served", UsageType: "Credits",
		StageD: trustedrouter.StageDEligibility{Eligible: true}, CandidateCostReporting: true,
		CandidatePrices: []trustedrouter.CandidatePrice{{EndpointID: "served", PriceHistoryVersion: 1, Rounding: "half_up_per_million", RequestFeeMicro: 7,
			Rates: trustedrouter.PriceRates{InputMicroPerMillion: 1_000_000, OutputMicroPerMillion: 3_000_000, CachedInputMicroPerMillion: 100_000, CacheCreationMicroPerMillion: 1_250_000}}},
	}
}

func TestUsageCostAcrossResponseFormats(t *testing.T) {
	t.Setenv("QUILL_USAGE_HEARTBEAT", "off")
	t.Setenv("QUILL_SETTLE_BEFORE_TERMINAL_MS", "5")
	originalQueue := settlementRetries
	settlementRetries = &settlementRetryQueue{jobs: make(chan settlementRetryJob, 100)}
	t.Cleanup(func() { settlementRetries = originalQueue })
	for _, route := range []string{"chat.completions", "responses", "messages"} {
		for _, stream := range []bool{false, true} {
			for _, scenario := range []string{"settled", "mismatch", "zero", "late", "error", "no-promise-error", "rejected", "durable", "missing", "ineligible-missing", "ineligible-late", "snapshot-not-authoritative"} {
				t.Run(fmt.Sprintf("%s/stream=%t/%s", route, stream, scenario), func(t *testing.T) {
					auth := costReportingAuthorization()
					if strings.HasPrefix(scenario, "ineligible") {
						auth.StageD.Eligible = false
					}
					if scenario == "snapshot-not-authoritative" || scenario == "no-promise-error" {
						auth.CandidateCostReporting = false
					}
					var out bytes.Buffer
					settles := 0
					var billed trustedrouter.Usage
					gateway := trustedrouter.New("http://127.0.0.1:18080", "test", &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
						body := ""
						status := 200
						switch r.URL.Path {
						case "/internal/gateway/authorize":
							encoded, _ := json.Marshal(map[string]any{"data": auth})
							body = string(encoded)
						case "/internal/gateway/settle":
							settles++
							var wire struct {
								Input    int    `json:"actual_input_tokens"`
								Output   int    `json:"actual_output_tokens"`
								Endpoint string `json:"selected_endpoint"`
								Route    string `json:"route_type"`
							}
							if err := json.NewDecoder(r.Body).Decode(&wire); err != nil {
								t.Fatal(err)
							}
							billed = trustedrouter.Usage{InputTokens: wire.Input, OutputTokens: wire.Output, SelectedEndpoint: wire.Endpoint, RouteType: wire.Route}
							if stream && (!strings.Contains(out.String(), "Hello") || strings.Contains(out.String(), "[DONE]") || strings.Contains(out.String(), "event: message_stop")) {
								t.Fatalf("terminal/answer ordering before settle: %s", out.String())
							}
							if strings.HasSuffix(scenario, "late") {
								if stream || scenario == "late" {
									deadline, ok := r.Context().Deadline()
									if !ok || time.Until(deadline) > 5*time.Millisecond {
										t.Fatal("terminal settlement has no bounded wait")
									}
									<-r.Context().Done()
									return nil, r.Context().Err()
								}
								time.Sleep(10 * time.Millisecond)
							}
							body = `{"data":{"cost_microdollars":15,"disposition":"finalized"}}`
							switch scenario {
							case "mismatch":
								body = `{"data":{"cost_microdollars":97,"disposition":"finalized"}}`
							case "zero":
								body = `{"data":{"cost_microdollars":0}}`
							case "error", "no-promise-error":
								status = 503
								body = `{"error":{"message":"fixture settlement error"}}`
							case "rejected":
								status = 400
								body = `{"error":{"message":"fixture rejected settlement"}}`
							case "durable":
								body = `{"data":{"cost_microdollars":83,"disposition":"intent_durable","finalization_outcome":"pending"}}`
							case "missing", "ineligible-missing", "snapshot-not-authoritative":
								body = `{"data":{"disposition":"intent_durable","finalization_outcome":"pending"}}`
							}
						default:
							t.Fatalf("unexpected path %s", r.URL.Path)
						}
						return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
					})})
					req := &types.OpenAIChatRequest{Model: "test-model", Stream: stream, StreamOptions: &types.ChatStreamOptions{IncludeUsage: true}, Messages: []types.OpenAIChatMessage{{Role: "user", Content: "hi"}}}
					options := []llm.InvokeOptions{{Model: "test-model", Provider: "anthropic", EndpointID: "served"}}
					provider := &fakeStreamingLLM{}
					if route == "messages" {
						body := []byte(fmt.Sprintf(`{"model":"test-model","max_tokens":32,"stream":%t,"messages":[{"role":"user","content":"hi"}]}`, stream))
						serveMessages(context.Background(), &out, provider, body, gateway, nil, "test-key", "", "cost-reporting", requestAttributionHeaders{})
					} else if stream {
						serveStreaming(context.Background(), &out, provider, req, &types.AnthropicMessagesRequest{}, options, gateway, auth, nil, time.Now(), nil, route, "cost-reporting", "test-model")
					} else if route == "responses" {
						serveResponsesNonStreaming(context.Background(), &out, provider, req, &types.AnthropicMessagesRequest{}, options, gateway, auth, nil, time.Now(), nil, "cost-reporting", "test-model")
					} else {
						serveChatNonStreaming(context.Background(), &out, provider, req, &types.AnthropicMessagesRequest{}, options, gateway, auth, nil, time.Now(), nil, "cost-reporting", "test-model")
					}
					if settles != 1 || billed.InputTokens != 2 || billed.OutputTokens != 2 || billed.SelectedEndpoint != "served" || billed.RouteType != route {
						t.Fatalf("settlement changed: count=%d usage=%+v", settles, billed)
					}
					wantRetries := 0
					if scenario == "error" || scenario == "late" ||
						(stream && (scenario == "no-promise-error" || scenario == "ineligible-late" || scenario == "rejected")) {
						wantRetries = 1
					}
					if len(settlementRetries.jobs) != wantRetries {
						t.Fatalf("retries = %d, want %d", len(settlementRetries.jobs), wantRetries)
					}
					if wantRetries == 1 {
						job := <-settlementRetries.jobs
						if job.usage.InputTokens != 2 || job.usage.OutputTokens != 2 || job.usage.SelectedEndpoint != "served" || job.usage.RouteType != route || job.requestLogID != "cost-reporting" {
							t.Fatalf("retry changed usage or request attribution: %+v", job)
						}
					}
					response, err := http.ReadResponse(bufio.NewReader(&out), nil)
					if err != nil {
						t.Fatal(err)
					}
					body, err := io.ReadAll(response.Body)
					response.Body.Close()
					if err != nil {
						t.Fatal(err)
					}
					if (scenario == "no-promise-error" || scenario == "rejected") && !stream {
						if response.StatusCode != 502 || bytes.Contains(body, []byte("cost_microdollars")) {
							t.Fatalf("error response = %d %s", response.StatusCode, body)
						}
						return
					}
					if response.StatusCode != 200 {
						t.Fatalf("status = %d: %s", response.StatusCode, body)
					}
					usage := finalCostUsage(t, body, route, stream)
					var want any = float64(15)
					switch scenario {
					case "mismatch":
						want = float64(97)
					case "zero":
						want = float64(0)
					case "durable":
						want = float64(83)
					case "error":
						want = float64(15)
					case "late":
						if stream {
							want = float64(15)
						}
					case "missing", "ineligible-missing", "rejected", "snapshot-not-authoritative", "no-promise-error":
						want = nil
					case "ineligible-late":
						if stream {
							want = nil
						}
					}
					for _, key := range []string{"cost_microdollars", "total_cost_microdollars"} {
						value, present := usage[key]
						if value != want || present != (want != nil) {
							t.Fatalf("%s = %v (present %v), want %v; body=%s", key, value, present, want, body)
						}
					}
				})
			}
		}
	}
}

func finalCostUsage(t *testing.T, body []byte, route string, stream bool) map[string]any {
	t.Helper()
	var payload map[string]any
	if !stream {
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Fatal(err)
		}
		return payload["usage"].(map[string]any)
	}
	found := 0
	var usage map[string]any
	var events []string
	for _, block := range strings.Split(string(body), "\n\n") {
		for _, line := range strings.Split(block, "\n") {
			if strings.HasPrefix(line, "event: ") {
				events = append(events, strings.TrimPrefix(line, "event: "))
			}
			if !strings.HasPrefix(line, "data: {") {
				continue
			}
			if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &payload); err != nil {
				t.Fatal(err)
			}
			var candidate map[string]any
			switch route {
			case "chat.completions":
				candidate, _ = payload["usage"].(map[string]any)
			case "responses":
				if payload["type"] == "response.completed" {
					candidate = payload["response"].(map[string]any)["usage"].(map[string]any)
				}
			case "messages":
				if payload["type"] == "message_delta" {
					candidate, _ = payload["usage"].(map[string]any)
				}
			}
			if candidate != nil {
				usage = candidate
				found++
			}
			payload = nil
		}
	}
	if found != 1 {
		t.Fatalf("terminal usage count = %d: %s", found, body)
	}
	if route == "messages" {
		want := []string{"message_start", "content_block_delta", "content_block_delta", "message_delta", "message_stop"}
		if !reflect.DeepEqual(events, want) {
			t.Fatalf("event order = %v", events)
		}
	} else if !strings.HasSuffix(string(body), "data: [DONE]\n\n") || strings.Count(string(body), "data: [DONE]") != 1 {
		t.Fatalf("DONE ordering: %s", body)
	}
	return usage
}

func TestReportedSettlementUsesServedCandidateAndCacheConvention(t *testing.T) {
	for _, tc := range []struct {
		provider string
		cost     int
	}{{"anthropic", 44}, {"openai", 36}} {
		t.Run(tc.provider, func(t *testing.T) {
			auth := costReportingAuthorization()
			auth.RouteCandidates = []trustedrouter.RouteCandidate{{EndpointID: "fallback", Model: "fallback-model", Provider: tc.provider, UsageType: "Credits"}}
			price := auth.CandidatePrices[0]
			price.EndpointID = "fallback"
			auth.CandidatePrices = append(auth.CandidatePrices, price)
			auth.CandidatePrices[0].RequestFeeMicro = 9999
			usage := trustedrouter.Usage{RouteType: "responses", SelectedEndpoint: "fallback", SelectedModel: "fallback-model", InputTokens: 20, OutputTokens: 4, CacheReadInputTokens: 5, CacheCreationInputTokens: 3}
			result := reportedSettlement(nil, auth, usage, nil)
			if !result.HasCost() || result.CostMicrodollars != tc.cost {
				t.Fatalf("cost = %+v, want %d", result, tc.cost)
			}
		})
	}
}

func TestReportedSettlementOmitsUnprovableCost(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(**trustedrouter.Authorization, *trustedrouter.Usage, **trustedrouter.SettleResult)
	}{
		{"no-authorization", func(a **trustedrouter.Authorization, _ *trustedrouter.Usage, _ **trustedrouter.SettleResult) {
			*a = nil
		}},
		{"ineligible", func(a **trustedrouter.Authorization, _ *trustedrouter.Usage, _ **trustedrouter.SettleResult) {
			(*a).StageD.Eligible = false
		}},
		{"surcharge-or-old-authorization", func(a **trustedrouter.Authorization, _ *trustedrouter.Usage, _ **trustedrouter.SettleResult) {
			(*a).CandidateCostReporting = false
		}},
		{"no-price", func(a **trustedrouter.Authorization, _ *trustedrouter.Usage, _ **trustedrouter.SettleResult) {
			(*a).CandidatePrices = nil
		}},
		{"unknown-endpoint", func(a **trustedrouter.Authorization, u *trustedrouter.Usage, _ **trustedrouter.SettleResult) {
			(*a).EndpointID = ""
			(*a).CandidatePrices[0].EndpointID = ""
			u.SelectedEndpoint = ""
		}},
		{"missing-provider", func(a **trustedrouter.Authorization, _ *trustedrouter.Usage, _ **trustedrouter.SettleResult) {
			(*a).Provider = ""
		}},
		{"model-mismatch", func(_ **trustedrouter.Authorization, u *trustedrouter.Usage, _ **trustedrouter.SettleResult) {
			u.SelectedModel = "other"
		}},
		{"byok", func(a **trustedrouter.Authorization, _ *trustedrouter.Usage, _ **trustedrouter.SettleResult) {
			(*a).UsageType = "BYOK"
		}},
		{"video", func(_ **trustedrouter.Authorization, u *trustedrouter.Usage, _ **trustedrouter.SettleResult) {
			u.RouteType = "videos"
		}},
		{"heartbeat-lost", func(_ **trustedrouter.Authorization, u *trustedrouter.Usage, _ **trustedrouter.SettleResult) {
			u.FinishReason = "heartbeat_lost"
		}},
		{"additional-cost", func(_ **trustedrouter.Authorization, u *trustedrouter.Usage, _ **trustedrouter.SettleResult) {
			u.AdditionalCostMicrodollars = 10
		}},
		{"negative-input", func(a **trustedrouter.Authorization, u *trustedrouter.Usage, _ **trustedrouter.SettleResult) {
			(*a).Provider = "openai"
			u.InputTokens = -1
		}},
		{"negative-read", func(_ **trustedrouter.Authorization, u *trustedrouter.Usage, _ **trustedrouter.SettleResult) {
			u.CacheReadInputTokens = -1
		}},
		{"negative-write", func(_ **trustedrouter.Authorization, u *trustedrouter.Usage, _ **trustedrouter.SettleResult) {
			u.CacheCreationInputTokens = -1
		}},
		{"invalid-price", func(a **trustedrouter.Authorization, _ *trustedrouter.Usage, _ **trustedrouter.SettleResult) {
			(*a).CandidatePrices[0].Rounding = "unknown"
		}},
		{"replay", func(_ **trustedrouter.Authorization, _ *trustedrouter.Usage, s **trustedrouter.SettleResult) {
			*s = &trustedrouter.SettleResult{AlreadySettled: true}
		}},
		{"settled-unknown", func(_ **trustedrouter.Authorization, _ *trustedrouter.Usage, s **trustedrouter.SettleResult) {
			*s = &trustedrouter.SettleResult{Settled: true}
		}},
		{"reaped-unknown", func(_ **trustedrouter.Authorization, _ *trustedrouter.Usage, s **trustedrouter.SettleResult) {
			*s = &trustedrouter.SettleResult{Disposition: trustedrouter.DispositionReapedSnapshot}
		}},
		{"refunded-unknown", func(_ **trustedrouter.Authorization, _ *trustedrouter.Usage, s **trustedrouter.SettleResult) {
			*s = &trustedrouter.SettleResult{FinalizationOutcome: "refunded"}
		}},
		{"durable-unknown", func(_ **trustedrouter.Authorization, _ *trustedrouter.Usage, s **trustedrouter.SettleResult) {
			*s = &trustedrouter.SettleResult{Disposition: trustedrouter.DispositionIntentDurable, FinalizationOutcome: "pending"}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			auth := costReportingAuthorization()
			usage := trustedrouter.Usage{InputTokens: 2, OutputTokens: 2, SelectedEndpoint: "served", SelectedModel: "test-model", RouteType: "chat.completions"}
			var settlement *trustedrouter.SettleResult
			tc.change(&auth, &usage, &settlement)
			got := reportedSettlement(settlement, auth, usage, nil)
			if got.HasCost() {
				t.Fatalf("invented cost: %+v", got)
			}
			fields := map[string]any{}
			annotateUsageCost(fields, got)
			if len(fields) != 0 {
				t.Fatalf("invented usage: %+v", fields)
			}
		})
	}
}

func TestStageDTerminalCostUsesSettlementOrExactCandidate(t *testing.T) {
	if defaultSettleBeforeTerminal != 2*time.Second {
		t.Fatalf("settlement budget = %s", defaultSettleBeforeTerminal)
	}
	t.Setenv("QUILL_USAGE_HEARTBEAT", "on")
	t.Setenv("QUILL_TERMINATE_AT_CAP", "off")
	t.Setenv("QUILL_SETTLE_BEFORE_TERMINAL_MS", "5")
	for _, route := range []string{"chat.completions", "responses"} {
		for _, scenario := range []string{"settled", "late", "error", "durable", "reaped"} {
			t.Run(route+"/"+scenario, func(t *testing.T) {
				auth := costReportingAuthorization()
				settles := 0
				gateway := stageDStreamingGateway(t, func(r *http.Request) (*http.Response, error) {
					body := ""
					status := 200
					switch {
					case r.URL.Path == trustedrouter.HeartbeatPath:
						body = string(enclaveStageDFixture(t, "heartbeat_response_accepted.json"))
					case r.URL.Path == "/internal/gateway/settle":
						settles++
						if scenario == "late" || scenario == "reaped" {
							<-r.Context().Done()
							return nil, r.Context().Err()
						}
						body = `{"data":{"cost_microdollars":97,"disposition":"finalized"}}`
						if scenario == "durable" {
							body = `{"data":{"cost_microdollars":83,"disposition":"intent_durable"}}`
						}
						if scenario == "error" {
							status = 503
							body = `{"error":{"message":"fixture unavailable"}}`
						}
					case strings.HasSuffix(r.URL.Path, "/disposition"):
						body = `{"data":{"disposition":"intent_durable"}}`
						if scenario == "reaped" {
							body = `{"data":{"disposition":"reaped_snapshot"}}`
						}
					default:
						t.Fatalf("unexpected path %s", r.URL.Path)
					}
					return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
				})
				var out bytes.Buffer
				serveStreaming(t.Context(), &out, &fakeStreamingLLM{}, &types.OpenAIChatRequest{Model: "test-model", Stream: true, StreamOptions: &types.ChatStreamOptions{IncludeUsage: true}}, &types.AnthropicMessagesRequest{}, []llm.InvokeOptions{{Model: "test-model", Provider: "anthropic", EndpointID: "served"}}, gateway, auth, nil, time.Now(), nil, route, "stage-d-cost", "test-model")
				if settles != 1 {
					t.Fatalf("settles = %d", settles)
				}
				response, err := http.ReadResponse(bufio.NewReader(&out), nil)
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(response.Body)
				response.Body.Close()
				if err != nil {
					t.Fatal(err)
				}
				usage := finalCostUsage(t, body, route, true)
				var want any = float64(15)
				if scenario == "settled" {
					want = float64(97)
				}
				if scenario == "durable" {
					want = float64(83)
				}
				if scenario == "reaped" {
					want = nil
				}
				if usage["cost_microdollars"] != want || usage["total_cost_microdollars"] != want {
					t.Fatalf("usage = %+v; want cost %v", usage, want)
				}
			})
		}
	}
}

func TestReportedSettlementPreservesZeroAndPrivateTierBasis(t *testing.T) {
	for _, tc := range []struct {
		name, provider, model                    string
		input, cached, creation, tier, fee, want int
	}{
		{"free", "anthropic", "test-model", 0, 0, 0, 0, 0, 0},
		{"overreported-cache", "openai", "test-model", 1, 5, 0, 0, 7, 8},
		{"fugu-private-tier", "sakana", "sakana-ai/fugu-ultra-v1.1", 101, 0, 0, 100, 7, 108},
		{"other-provider-ignores-private-tier", "anthropic", "sakana-ai/fugu-ultra-v1.1", 101, 0, 0, 100, 7, 209},
		{"other-model-ignores-private-tier", "sakana", "other-model", 101, 0, 0, 100, 7, 209},
	} {
		t.Run(tc.name, func(t *testing.T) {
			auth := costReportingAuthorization()
			auth.Provider = tc.provider
			auth.Model = tc.model
			price := &auth.CandidatePrices[0]
			price.RequestFeeMicro = int64(tc.fee)
			bound := int64(100)
			price.Tiers = []trustedrouter.PriceTier{{MaxPromptTokens: &bound, Rates: price.Rates}, {Rates: trustedrouter.PriceRates{InputMicroPerMillion: 2_000_000}}}
			usage := trustedrouter.Usage{RouteType: "responses", SelectedEndpoint: "served", SelectedModel: tc.model, InputTokens: tc.input, CacheReadInputTokens: tc.cached, CacheCreationInputTokens: tc.creation, PriceTierInputTokens: tc.tier}
			unknown := &trustedrouter.SettleResult{}
			got := reportedSettlement(unknown, auth, usage, nil)
			if !got.HasCost() || got.CostMicrodollars != tc.want {
				t.Fatalf("reported = %+v; want %d", got, tc.want)
			}
			if unknown.HasCost() {
				t.Fatal("reporting mutated the settlement")
			}
		})
	}
}

func TestUnknownCostDiscardsProviderPriceFields(t *testing.T) {
	var absentUsage map[string]any
	annotateUsageCost(absentUsage, &trustedrouter.SettleResult{CostMicrodollars: 17})
	if absentUsage != nil {
		t.Fatalf("invented an unrequested usage object: %+v", absentUsage)
	}
	for _, settlement := range []*trustedrouter.SettleResult{nil, {Disposition: "intent_durable"}} {
		usage := map[string]any{"cost_microdollars": 0, "total_cost_microdollars": 9, "output_tokens": 3}
		annotateUsageCost(usage, settlement)
		if !reflect.DeepEqual(usage, map[string]any{"output_tokens": 3}) {
			t.Fatalf("provider price reported as customer cost: %+v", usage)
		}
	}
}

type costUsageFailWriter struct {
	bytes.Buffer
	failAt string
	failed []byte
}

func (w *costUsageFailWriter) Write(p []byte) (int, error) {
	if bytes.Contains(p, []byte(w.failAt)) {
		w.failed = append([]byte(nil), p...)
		return 0, io.ErrClosedPipe
	}
	return w.Buffer.Write(p)
}

func TestMessagesWriteFailureHasOneBillingOutcome(t *testing.T) {
	t.Setenv("QUILL_USAGE_HEARTBEAT", "off")
	for _, scenario := range []string{"before-terminal", "settled", "durable", "error"} {
		t.Run(scenario, func(t *testing.T) {
			originalQueue := settlementRetries
			settlementRetries = &settlementRetryQueue{jobs: make(chan settlementRetryJob, 1)}
			t.Cleanup(func() { settlementRetries = originalQueue })
			auth := costReportingAuthorization()
			auth.CandidateCostReporting = false
			out := &costUsageFailWriter{failAt: "event: message_delta"}
			if scenario == "before-terminal" {
				out.failAt = "event: content_block_delta"
			}
			settles, refunds := 0, 0
			gateway := trustedrouter.New("http://127.0.0.1:18080", "test", &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				status, body := 200, ""
				switch r.URL.Path {
				case "/internal/gateway/authorize":
					encoded, _ := json.Marshal(map[string]any{"data": auth})
					body = string(encoded)
				case "/internal/gateway/settle":
					settles++
					body = `{"data":{"cost_microdollars":97,"disposition":"finalized"}}`
					if scenario == "durable" {
						body = `{"data":{"cost_microdollars":83,"disposition":"intent_durable","finalization_outcome":"pending"}}`
					} else if scenario == "error" {
						status, body = 503, `{"error":{"message":"fixture settlement error"}}`
					}
				case "/internal/gateway/refund":
					refunds++
					body = `{"data":{"settled":true,"cost_microdollars":0,"finalization_outcome":"refunded"}}`
				default:
					t.Fatalf("unexpected control-plane path: %s", r.URL.Path)
				}
				return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
			})})
			body := []byte(`{"model":"test-model","max_tokens":32,"stream":true,"messages":[{"role":"user","content":"hi"}]}`)
			serveMessages(t.Context(), out, &fakeStreamingLLM{}, body, gateway, nil, "test-key", "", "cost-write-failure", requestAttributionHeaders{})
			wantSettles, wantRefunds, wantRetries := 1, 0, 0
			if scenario == "before-terminal" {
				wantSettles, wantRefunds = 0, 1
			} else if scenario == "error" {
				wantRetries = 1
			}
			if len(out.failed) == 0 || settles != wantSettles || refunds != wantRefunds || len(settlementRetries.jobs) != wantRetries {
				t.Fatalf("write failed=%t settlements=%d refunds=%d retries=%d, want true/%d/%d/%d", len(out.failed) > 0, settles, refunds, len(settlementRetries.jobs), wantSettles, wantRefunds, wantRetries)
			}
			if scenario == "settled" || scenario == "durable" {
				cost := 97
				if scenario == "durable" {
					cost = 83
				}
				for _, key := range []string{"cost_microdollars", "total_cost_microdollars"} {
					if !bytes.Contains(out.failed, []byte(fmt.Sprintf(`"%s":%d`, key, cost))) {
						t.Fatalf("terminal %s does not contain %s=%d", out.failed, key, cost)
					}
				}
			} else if bytes.Contains(out.failed, []byte("cost_microdollars")) {
				t.Fatalf("unknown cost in failed write: %s", out.failed)
			}
		})
	}
}

func TestCostMismatchLogsBothPricesAndKeepsSettlement(t *testing.T) {
	for _, promise := range []bool{false, true} {
		for _, settled := range []int{15, 97} {
			t.Run(fmt.Sprintf("promise=%t/cost=%d", promise, settled), func(t *testing.T) {
				auth := costReportingAuthorization()
				auth.CandidateCostReporting = promise
				usage := trustedrouter.Usage{RouteType: "responses", SelectedEndpoint: "served", SelectedModel: "test-model", InputTokens: 2, OutputTokens: 2}
				settlement := &trustedrouter.SettleResult{CostMicrodollars: settled, CostMicrodollarsKnown: true}
				log := captureStderr(t, func() {
					got := reportedSettlement(settlement, auth, usage, nil)
					if got != settlement || got.CostMicrodollars != settled {
						t.Fatalf("settlement changed: %+v", got)
					}
				})
				want := ""
				if promise && settled == 97 {
					want = "enclave.usage_cost_mismatch level=error authorization_id=\"cost-auth\" endpoint_id=\"served\" local_cost_microdollars=15 settled_cost_microdollars=97\n"
				}
				if log != want {
					t.Fatalf("log = %q, want %q", log, want)
				}
			})
		}
	}
}

func TestSnapshotPromiseIgnoresReportedServiceTier(t *testing.T) {
	auth := costReportingAuthorization()
	usage := trustedrouter.Usage{RouteType: "responses", SelectedEndpoint: "served", SelectedModel: "test-model", InputTokens: 2, OutputTokens: 2, ServiceTier: "priority"}
	got := reportedSettlement(nil, auth, usage, nil)
	if !got.HasCost() || got.CostMicrodollars != 15 {
		t.Fatalf("snapshot price = %+v", got)
	}
}

func TestOldControlPlaneOmitsPricePromise(t *testing.T) {
	encoded, err := json.Marshal(costReportingAuthorization())
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatal(err)
	}
	delete(fields, "candidate_cost_reporting")
	encoded, _ = json.Marshal(fields)
	var auth trustedrouter.Authorization
	if err := json.Unmarshal(encoded, &auth); err != nil {
		t.Fatal(err)
	}
	usage := trustedrouter.Usage{RouteType: "responses", SelectedEndpoint: "served", SelectedModel: "test-model", InputTokens: 2, OutputTokens: 2}
	got := reportedSettlement(nil, &auth, usage, context.DeadlineExceeded)
	if got.HasCost() || auth.CandidateCostReporting {
		t.Fatalf("old control plane promised price: %+v", got)
	}
}

func TestPromisedCostDoesNotAddOptedOutChatUsage(t *testing.T) {
	t.Setenv("QUILL_USAGE_HEARTBEAT", "off")
	var out bytes.Buffer
	settles := 0
	gateway := stageDStreamingGateway(t, func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/internal/gateway/settle" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		settles++
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"data":{"cost_microdollars":15}}`)), Request: r}, nil
	})
	serveStreaming(t.Context(), &out, &fakeStreamingLLM{}, &types.OpenAIChatRequest{Model: "test-model", Stream: true, StreamOptions: &types.ChatStreamOptions{IncludeUsage: false}}, &types.AnthropicMessagesRequest{}, []llm.InvokeOptions{{Model: "test-model", Provider: "anthropic", EndpointID: "served"}}, gateway, costReportingAuthorization(), nil, time.Now(), nil, "chat.completions", "opt-out", "test-model")
	if settles != 1 {
		t.Fatalf("settles = %d", settles)
	}
	response, err := http.ReadResponse(bufio.NewReader(&out), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(body), "\n") {
		if !strings.HasPrefix(line, "data: {") {
			continue
		}
		var payload map[string]any
		if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &payload); err != nil {
			t.Fatal(err)
		}
		if payload["usage"] != nil {
			t.Fatalf("unrequested usage: %s", line)
		}
	}
	if strings.Count(string(body), "data: [DONE]") != 1 {
		t.Fatalf("bad terminal count: %s", body)
	}
}

func TestReportedCostMatchesRouterCatalogRefreshCharge(t *testing.T) {
	// Same authorization and final usage as test_snapshot_billing.py: live
	// catalog would charge 63, but the frozen authorization charges 49.
	auth := costReportingAuthorization()
	auth.CandidatePrices[0].RequestFeeMicro = 0
	auth.CandidatePrices[0].Rates.OutputMicroPerMillion = 5_000_000
	usage := trustedrouter.Usage{RouteType: "chat.completions", SelectedEndpoint: "served", SelectedModel: "test-model", InputTokens: 14, OutputTokens: 7}
	got := reportedSettlement(nil, auth, usage, context.DeadlineExceeded)
	if !got.HasCost() || got.CostMicrodollars != 49 {
		t.Fatalf("snapshot cost = %+v", got)
	}
}
