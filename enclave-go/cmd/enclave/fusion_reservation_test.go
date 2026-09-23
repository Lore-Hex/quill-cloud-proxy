package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

type fusionHold struct{ input, output, price, cost int }
type fusionLedger struct {
	mu                                                        sync.Mutex
	balance, spent, peak, reserved, denied, settled, refunded int
	holds                                                     map[string]fusionHold
	authorized                                                []map[string]any
}

func newFusionLedgerGateway(t *testing.T, balance int) (*trustedrouter.Client, *fusionLedger) {
	t.Helper()
	ledger := &fusionLedger{balance: balance, holds: map[string]fusionHold{}}
	gateway := trustedrouter.New("https://trustedrouter.com", "token", &http.Client{Transport: fusionBudgetTransport(func(r *http.Request) (*http.Response, error) {
		if r.Method == "GET" {
			return fusionJSONResponse(200, map[string]any{"data": []any{map[string]any{"id": "model/capped", "top_provider": map[string]any{"max_completion_tokens": 8192}}}}), nil
		}
		var p map[string]any
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			return nil, err
		}
		ledger.mu.Lock()
		defer ledger.mu.Unlock()
		switch r.URL.Path {
		case "/internal/gateway/authorize":
			output := int(p["max_output_tokens"].(float64))
			input := int(p["estimated_input_tokens"].(float64))
			if p["max_tokens"] != float64(output) || output <= 0 {
				return nil, fmt.Errorf("reservation is not explicit: %#v", p)
			}
			price := 1
			if strings.HasSuffix(p["model"].(string), "b") {
				price = 2
			}
			cost := input + price*output
			if cost > ledger.balance-ledger.reserved {
				ledger.denied++
				return fusionJSONResponse(402, map[string]any{"error": map[string]any{"type": "insufficient_credits", "message": "insufficient balance"}}), nil
			}
			id := fmt.Sprintf("hold_%d", len(ledger.authorized))
			ledger.authorized = append(ledger.authorized, p)
			ledger.holds[id] = fusionHold{input, output, price, cost}
			ledger.reserved += cost
			ledger.peak = max(ledger.peak, ledger.reserved)
			model := p["model"].(string)
			return fusionJSONResponse(200, map[string]any{"data": map[string]any{"authorization_id": id, "model": model, "provider": "test", "endpoint_id": model + "@test/prepaid", "usage_type": "Credits"}}), nil
		case "/internal/gateway/settle":
			id := p["authorization_id"].(string)
			h, ok := ledger.holds[id]
			input := int(p["actual_input_tokens"].(float64))
			output := int(p["actual_output_tokens"].(float64))
			if !ok || output > h.output || input > h.input {
				t.Errorf("settlement outside hold: %#v hold=%+v", p, h)
				return nil, fmt.Errorf("settlement outside hold")
			}
			cost := input + h.price*output
			ledger.reserved -= h.cost
			ledger.balance -= cost
			ledger.spent += cost
			ledger.settled++
			delete(ledger.holds, id)
			return fusionJSONResponse(200, map[string]any{"data": map[string]any{"settled": true, "cost_microdollars": cost}}), nil
		case "/internal/gateway/refund":
			id := p["authorization_id"].(string)
			h, ok := ledger.holds[id]
			if !ok {
				return nil, fmt.Errorf("unknown hold %s", id)
			}
			ledger.reserved -= h.cost
			ledger.refunded++
			delete(ledger.holds, id)
			return fusionJSONResponse(200, map[string]any{"data": map[string]any{"refunded": true}}), nil
		}
		return nil, fmt.Errorf("unexpected path %s", r.URL.Path)
	})})
	return gateway, ledger
}
func fusionJSONResponse(status int, body any) *http.Response {
	raw, _ := json.Marshal(body)
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(raw))}
}

// Reports the worst case permitted by the provider's explicit output contract,
// including reasoning, so the success test exercises the entire reservation.
type fusionFullBudgetProvider struct {
	fusionEchoLLM
	short        bool
	beforeInvoke func() error
}

func (f *fusionFullBudgetProvider) InvokeStreaming(ctx context.Context, req *types.OpenAIChatRequest, body *types.AnthropicMessagesRequest, out io.Writer, options ...llm.InvokeOptions) error {
	if req.MaxTokens == nil || *req.MaxTokens <= 0 || body.MaxTokens != *req.MaxTokens || body.AnthropicDispatchMaxTokens() != *req.MaxTokens {
		return fmt.Errorf("missing/mismatched provider bound")
	}
	if f.beforeInvoke != nil {
		if err := f.beforeInvoke(); err != nil {
			return err
		}
	}
	var wire bytes.Buffer
	if err := f.fusionEchoLLM.InvokeStreaming(ctx, req, body, &wire, options...); err != nil {
		return err
	}
	if f.short {
		_, err := io.WriteString(out, wire.String())
		return err
	}
	_, err := io.WriteString(out, strings.ReplaceAll(wire.String(), `"output_tokens":4`, fmt.Sprintf(`"output_tokens":%d`, *req.MaxTokens)))
	return err
}

func TestFusionPanelFundedBeforeExecution(t *testing.T) {
	for _, tt := range []struct {
		balance int
		short   bool
	}{{100000, true}, {1000000, true}, {1000000, false}} {
		t.Run(fmt.Sprintf("balance=%d/short=%t", tt.balance, tt.short), func(t *testing.T) {
			balance := tt.balance
			gateway, ledger := newFusionLedgerGateway(t, balance)
			provider := &fusionFullBudgetProvider{short: tt.short}
			req := &types.OpenAIChatRequest{MaxTokens: intPtrMainTest(100), Reasoning: map[string]any{"max_tokens": 32768}, Messages: []types.OpenAIChatMessage{{Role: "user", Content: "hard problem"}}}
			config := fusionConfig{AnalysisModels: []string{"model/a", "model/b", "model/c", "model/d", "model/e", "model/f"}}
			_, err := runFusionPanel(context.Background(), provider, req, config, gateway, nil, "test", "id", "log")
			ledger.mu.Lock()
			defer ledger.mu.Unlock()
			provider.mu.Lock()
			defer provider.mu.Unlock()
			if balance == 100000 {
				if err == nil || ledger.denied == 0 || len(provider.calls) != 0 || ledger.spent != 0 || ledger.settled != 0 || ledger.refunded != len(ledger.authorized) {
					t.Fatalf("unfunded panel ran: err=%v calls=%d ledger=%+v", err, len(provider.calls), ledger)
				}
			} else {
				if err != nil || len(provider.calls) != 6 || ledger.settled != 6 || ledger.peak < 7*fusionPanelReasoningTokens || (!tt.short && ledger.spent < 7*fusionPanelReasoningTokens) || (tt.short && ledger.spent > 100) {
					t.Fatalf("funded panel: err=%v calls=%d ledger=%+v", err, len(provider.calls), ledger)
				}
			}
			if ledger.reserved != 0 || len(ledger.holds) != 0 || ledger.peak > balance || ledger.balance < 0 {
				t.Fatalf("bad ledger: %+v", ledger)
			}
			for _, p := range ledger.authorized {
				if p["max_output_tokens"] != float64(fusionPanelReasoningTokens) {
					t.Fatalf("wrong bound: %#v", p)
				}
			}
		})
	}
}

func TestFusionStageBudgetsAndCatalogCap(t *testing.T) {
	for _, configured := range []int{0, 1, 1024, 1025, 60000} {
		for _, model := range []string{"model/unknown", "model/capped"} {
			t.Run(fmt.Sprintf("%d/%s", configured, model), func(t *testing.T) {
				gateway, ledger := newFusionLedgerGateway(t, 10000000)
				if _, err := gateway.PublicModels(context.Background()); err != nil {
					t.Fatal(err)
				}
				req := &types.OpenAIChatRequest{MaxTokens: intPtrMainTest(100), Reasoning: map[string]any{"max_tokens": 32768}, Messages: []types.OpenAIChatMessage{{Role: "user", Content: "hard problem"}}}
				config := fusionConfig{MaxCompletionTokens: configured}
				requests := []*types.OpenAIChatRequest{
					fusionPanelRequest(req, model, 0, configured, ""), fusionJudgeRequest(req, model, nil, configured),
					selectorRequest(req, model, nil, config), mapReduceMapperRequest(req, model, config),
					mapReducePartRequest(req, model, mapReducePart{}, 0, config), mapReduceReducerRequest(req, model, mapReducePlan{}, nil, config),
				}
				routes := []string{"fusion.panel", "fusion.judge", "fusion.selector", "fusion.mapreduce.mapper", "fusion.mapreduce.part", "fusion.mapreduce.reducer"}
				want := fusionPanelReasoningTokens
				if configured > 0 {
					want = configured
				}
				if model == "model/capped" && want > 8192 {
					want = 8192
				}
				for i, inner := range requests {
					_, err := runFusionCall(context.Background(), &fusionFullBudgetProvider{}, inner, gateway, nil, "test", routes[i], fmt.Sprint(i), "log", nil, false)
					if err != nil {
						t.Fatal(err)
					}
					if inner.MaxTokens == nil || *inner.MaxTokens != want {
						t.Fatalf("%s max_tokens=%v want %d", routes[i], inner.MaxTokens, want)
					}
				}
				if req.Reasoning.(map[string]any)["max_tokens"] != 32768 {
					t.Fatal("mutated parent reasoning")
				}
				for _, p := range ledger.authorized {
					if p["max_output_tokens"] != float64(want) {
						t.Fatalf("authorization mismatch: %#v", p)
					}
				}
				if ledger.settled != 6 || ledger.reserved != 0 {
					t.Fatalf("bad settlement counts: %+v", ledger)
				}
			})
		}
	}
}

func TestFusionPanelConcurrentAdmission(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprintf("failure=%t", fail), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			entered := make(chan string, 6)
			release := make(chan struct{})
			late := make(chan struct{})
			failed := make(chan struct{})
			var releaseOnce, lateOnce sync.Once
			defer releaseOnce.Do(func() { close(release) })
			defer lateOnce.Do(func() { close(late) })
			var mu sync.Mutex
			holds, refunds := map[string]bool{}, map[string]bool{}
			provider := &fusionFullBudgetProvider{short: true}
			provider.beforeInvoke = func() error {
				mu.Lock()
				defer mu.Unlock()
				if len(holds) != 6 {
					return fmt.Errorf("provider started with only %d holds", len(holds))
				}
				return nil
			}
			gateway := trustedrouter.New("https://trustedrouter.com", "token", &http.Client{Transport: fusionBudgetTransport(func(r *http.Request) (*http.Response, error) {
				var p map[string]any
				if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
					return nil, err
				}
				switch r.URL.Path {
				case "/internal/gateway/authorize":
					model := p["model"].(string)
					entered <- model
					<-release // No authorization returns until all six are in flight.
					if fail && model == "model/a" {
						resp := fusionJSONResponse(402, map[string]any{"error": map[string]any{"type": "insufficient_credits", "message": "denied"}})
						resp.Body = &fusionAdmissionFailureBody{ReadCloser: resp.Body, closed: failed}
						return resp, nil
					}
					if model == "model/f" {
						<-late
					}
					mu.Lock()
					holds[model] = true
					mu.Unlock()
					return fusionJSONResponse(200, map[string]any{"data": map[string]any{"authorization_id": model, "model": model, "provider": "test", "endpoint_id": model + "@test/prepaid", "usage_type": "Credits"}}), nil
				case "/internal/gateway/refund":
					if r.Context().Err() != nil {
						t.Error("refund inherited cancellation")
					}
					mu.Lock()
					defer mu.Unlock()
					id := p["authorization_id"].(string)
					if !holds[id] || refunds[id] {
						t.Errorf("invalid/duplicate refund %s", id)
					}
					refunds[id] = true
					return fusionJSONResponse(200, map[string]any{"data": map[string]any{"refunded": true}}), nil
				case "/internal/gateway/settle":
					return fusionJSONResponse(200, map[string]any{"data": map[string]any{"settled": true}}), nil
				}
				return nil, fmt.Errorf("unexpected path %s", r.URL.Path)
			})})
			done := make(chan error, 1)
			go func() {
				req := &types.OpenAIChatRequest{Messages: []types.OpenAIChatMessage{{Role: "user", Content: "problem"}}}
				_, err := runFusionPanel(ctx, provider, req, fusionConfig{AnalysisModels: []string{"model/a", "model/b", "model/c", "model/d", "model/e", "model/f"}}, gateway, nil, "test", "id", "log")
				done <- err
			}()
			for i := 0; i < 6; i++ {
				select {
				case <-entered:
				case <-time.After(5 * time.Second):
					t.Fatal("authorizations serialized: not all six entered")
				}
			}
			releaseOnce.Do(func() { close(release) })
			if fail {
				select {
				case <-failed: // The failure response was consumed; the last success is still blocked.
				case <-time.After(5 * time.Second):
					t.Fatal("failure did not arrive")
				}
				cancel()
			}
			select {
			case err := <-done:
				t.Fatalf("admission returned before late authorization: %v", err)
			default:
			}
			provider.mu.Lock()
			if len(provider.calls) != 0 {
				t.Error("provider started before last hold")
			}
			provider.mu.Unlock()
			lateOnce.Do(func() { close(late) })
			select {
			case err := <-done:
				if (err != nil) != fail {
					t.Fatalf("err=%v failure=%t", err, fail)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("panel did not finish")
			}
			mu.Lock()
			defer mu.Unlock()
			provider.mu.Lock()
			defer provider.mu.Unlock()
			if fail {
				if len(holds) != 5 || len(refunds) != 5 || !refunds["model/f"] || len(provider.calls) != 0 {
					t.Fatalf("holds=%v refunds=%v provider calls=%d", holds, refunds, len(provider.calls))
				}
			} else if len(provider.calls) != 6 || len(refunds) != 0 {
				t.Fatalf("calls=%d refunds=%v", len(provider.calls), refunds)
			}
		})
	}
}

type fusionAdmissionFailureBody struct {
	io.ReadCloser
	closed chan struct{}
}

func (b *fusionAdmissionFailureBody) Close() error {
	close(b.closed)
	return b.ReadCloser.Close()
}
