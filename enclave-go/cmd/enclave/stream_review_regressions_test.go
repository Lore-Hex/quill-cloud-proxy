package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/streamhttp"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/upstreamerror"
)

type streamingProviderFunc func(context.Context, io.Writer, llm.InvokeOptions) error

func (f streamingProviderFunc) InvokeStreaming(ctx context.Context, _ *types.OpenAIChatRequest, _ *types.AnthropicMessagesRequest, w io.Writer, opts ...llm.InvokeOptions) error {
	return f(ctx, w, opts[0])
}

func TestGatewayClosesAbandonedProviderReader(t *testing.T) {
	t.Setenv("QUILL_USAGE_HEARTBEAT", "off")
	for _, route := range []string{"chat.completions", "responses"} {
		for _, stream := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/%t", route, stream), func(t *testing.T) {
				provider := streamingProviderFunc(func(_ context.Context, w io.Writer, _ llm.InvokeOptions) error {
					if _, err := io.WriteString(w, providerStreamTestResponse); err != nil {
						return err
					}
					_, err := io.WriteString(w, ": trailer after terminal\n\n")
					return err
				})
				req := &types.OpenAIChatRequest{Model: "model-a", Stream: stream}
				opts := []llm.InvokeOptions{{Model: "model-a"}}
				invocation := startProviderInvocation(t.Context(), provider, req, &types.AnthropicMessagesRequest{}, opts, false, nil, "reader-close")
				defer invocation.abort(io.ErrClosedPipe)
				var out bytes.Buffer
				serveErrorTestRoute(withProviderInvocation(t.Context(), invocation), route, stream, &out, provider, nil, nil, opts)
				select {
				case <-invocation.done:
				case <-time.After(200 * time.Millisecond):
					t.Fatal("abandoned provider pipe reader left writer blocked")
				}
			})
		}
	}
}

func TestGatewayRedactsProviderCredentials(t *testing.T) {
	t.Setenv("QUILL_USAGE_HEARTBEAT", "off")
	const key = "provider-owned-secret"
	for _, header := range []string{"x-api-key", "x-goog-api-key", "api-key", "authorization"} {
		for _, status := range []int{200, 400} {
			t.Run(fmt.Sprintf("%s/%d", header, status), func(t *testing.T) {
				provider := streamingProviderFunc(func(ctx context.Context, w io.Writer, _ llm.InvokeOptions) error {
					req, _ := http.NewRequestWithContext(ctx, "POST", "https://provider.invalid/chat", nil)
					req.Header.Set(header, key)
					body := `{"error":{"message":"rejected ` + key + `","type":"` + key + `","code":"` + key + `","param":"` + key + `"},"headers":{"` + header + `":"header-owned-secret"}}`
					client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
						return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
					})}
					resp, err := streamhttp.Do(client, req)
					if err != nil {
						return err
					}
					defer resp.Body.Close()
					if status == 200 {
						upstreamerror.Open(w)
						if _, err := io.WriteString(w, "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"partial\"}}\n\n"); err != nil {
							return err
						}
					}
					payload, err := io.ReadAll(resp.Body)
					if err != nil {
						return err
					}
					return &upstreamerror.Error{Status: 400, Body: string(payload)}
				})
				var out bytes.Buffer
				serveErrorTestRoute(t.Context(), "chat.completions", true, &out, provider, nil, nil, []llm.InvokeOptions{{Model: "model-a"}})
				if strings.Contains(out.String(), key) || strings.Contains(out.String(), "header-owned-secret") {
					t.Fatalf("credential escaped on wire: %s", out.String())
				}
				if !strings.Contains(out.String(), "rejected") {
					t.Fatalf("lost provider error: %s", out.String())
				}
			})
		}
	}
}

type failAfterSettleWriter struct{ attempted *atomic.Bool }

func (w failAfterSettleWriter) Write(p []byte) (int, error) {
	if w.attempted.Load() {
		return 0, io.ErrClosedPipe
	}
	return len(p), nil
}

func TestStageDTerminalFailureNeverRefundsSettlementAttempt(t *testing.T) {
	t.Setenv("QUILL_USAGE_HEARTBEAT", "on")
	t.Setenv("QUILL_TERMINATE_AT_CAP", "off")
	t.Setenv("QUILL_SETTLE_BEFORE_TERMINAL_MS", "5")
	old := settlementRetries
	defer func() { settlementRetries = old }()
	for _, timeout := range []bool{false, true} {
		t.Run(fmt.Sprintf("timeout=%t", timeout), func(t *testing.T) {
			settlementRetries = &settlementRetryQueue{jobs: make(chan settlementRetryJob, 4), maxAttempts: 1}
			var attempted atomic.Bool
			var refunds, settles atomic.Int32
			gateway := stageDStreamingGateway(t, func(r *http.Request) (*http.Response, error) {
				body := `{"data":{"disposition":"finalized","cost_microdollars":15}}`
				switch {
				case r.URL.Path == trustedrouter.HeartbeatPath:
					body = string(enclaveStageDFixture(t, "heartbeat_response_accepted.json"))
				case r.URL.Path == "/internal/gateway/settle":
					count := settles.Add(1)
					attempted.Store(true)
					if timeout && count == 1 {
						<-r.Context().Done()
						return nil, r.Context().Err()
					}
				case r.URL.Path == "/internal/gateway/refund":
					refunds.Add(1)
				case strings.HasSuffix(r.URL.Path, "/disposition"):
					body = `{"data":{"disposition":"pending"}}`
				default:
					t.Errorf("unexpected path %s", r.URL.Path)
				}
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
			})
			provider := &scriptedProviderStreamClient{invoke: func(_ llm.InvokeOptions, w io.Writer) error {
				_, err := io.WriteString(w, providerStreamTestResponse)
				return err
			}}
			serveStreaming(t.Context(), failAfterSettleWriter{&attempted}, provider, &types.OpenAIChatRequest{Model: "model", Stream: true}, &types.AnthropicMessagesRequest{}, []llm.InvokeOptions{{Model: "model", EndpointID: "anthropic/test"}}, gateway, stageDStreamingAuthorization(), nil, time.Now(), nil, "chat.completions", "review-regression", "model")
			queued := len(settlementRetries.jobs)
			if timeout && queued != 1 {
				t.Fatalf("queued retries=%d", queued)
			}
			for len(settlementRetries.jobs) > 0 {
				settlementRetries.process(t.Context(), <-settlementRetries.jobs)
			}
			if !attempted.Load() || refunds.Load() != 0 {
				t.Fatalf("settles=%d queued=%d refunds=%d", settles.Load(), queued, refunds.Load())
			}
		})
	}
}

func TestIncompleteCandidatePriceIsNotFree(t *testing.T) {
	const rates = `{"input_micro_per_million":0,"output_micro_per_million":0,"cached_input_micro_per_million":0,"cache_creation_micro_per_million":0}`
	for _, tc := range []struct {
		name, fields string
		known        bool
	}{
		{"missing all", "", false},
		{"missing rates", `,"request_fee_micro":0`, false},
		{"null rates", `,"request_fee_micro":0,"rates":null`, false},
		{"partial rates", `,"request_fee_micro":0,"rates":{"input_micro_per_million":0}`, false},
		{"missing fee", `,"rates":` + rates, false},
		{"null fee", `,"request_fee_micro":null,"rates":` + rates, false},
		{"missing tier rates", `,"request_fee_micro":0,"rates":` + rates + `,"tiers":[{"max_prompt_tokens":null}]`, false},
		{"explicit free", `,"request_fee_micro":0,"rates":` + rates, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			auth := costReportingAuthorization()
			auth.CandidatePrices = nil
			if err := json.Unmarshal([]byte(`[{"endpoint_id":"served","price_history_version":1,"rounding":"half_up_per_million"`+tc.fields+`}]`), &auth.CandidatePrices); err != nil {
				t.Fatal(err)
			}
			got := reportedSettlement(nil, auth, trustedrouter.Usage{InputTokens: 2, OutputTokens: 2, SelectedEndpoint: "served", SelectedModel: "test-model", RouteType: "chat.completions"}, context.DeadlineExceeded)
			if got.HasCost() != tc.known {
				t.Fatalf("incomplete snapshot reported as known free cost: %+v", got)
			}
		})
	}
}

func TestDeferredSettlementLogsReportedCostMismatch(t *testing.T) {
	t.Setenv("QUILL_SETTLE_BEFORE_TERMINAL_MS", "5")
	old := settlementRetries
	settlementRetries = &settlementRetryQueue{jobs: make(chan settlementRetryJob, 1), maxAttempts: 1}
	defer func() { settlementRetries = old }()
	calls := 0
	gateway := trustedrouter.New("http://127.0.0.1:18080", "test", &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			<-r.Context().Done()
			return nil, r.Context().Err()
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"data":{"cost_microdollars":97,"disposition":"finalized"}}`)), Request: r}, nil
	})})
	auth := costReportingAuthorization()
	usage := trustedrouter.Usage{InputTokens: 2, OutputTokens: 2, SelectedEndpoint: "served", SelectedModel: "test-model", RouteType: "chat.completions"}
	reported, err := settleForUsageResponse(t.Context(), gateway, auth, nil, usage, &types.OpenAIChatRequest{}, nil, "answer", "review-regression")
	if err != nil || !reported.HasCost() || reported.CostMicrodollars != 15 {
		t.Fatalf("reported=%+v err=%v", reported, err)
	}
	if len(settlementRetries.jobs) != 1 {
		t.Fatal("missing retry")
	}
	job := <-settlementRetries.jobs
	// A second compaction and a changed live snapshot must not change the report.
	auth.CandidatePrices[0].RequestFeeMicro = 500
	logs := captureStderr(t, func() { settlementRetries.process(t.Context(), job) })
	for _, want := range []string{"enclave.usage_cost_mismatch", `authorization_id="cost-auth"`, `endpoint_id="served"`, "local_cost_microdollars=15", "settled_cost_microdollars=97"} {
		if !strings.Contains(logs, want) {
			t.Errorf("missing %q: %s", want, logs)
		}
	}
	if calls != 2 {
		t.Fatalf("settles=%d", calls)
	}
}
