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
	short bool
}

func (f *fusionFullBudgetProvider) InvokeStreaming(ctx context.Context, req *types.OpenAIChatRequest, body *types.AnthropicMessagesRequest, out io.Writer, options ...llm.InvokeOptions) error {
	if req.MaxTokens == nil || *req.MaxTokens <= 0 || body.MaxTokens != *req.MaxTokens {
		return fmt.Errorf("missing/mismatched provider bound")
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
			req := &types.OpenAIChatRequest{MaxTokens: intPtrMainTest(100), Messages: []types.OpenAIChatMessage{{Role: "user", Content: "hard problem"}}}
			config := fusionConfig{AnalysisModels: []string{"model/a", "model/b", "model/c", "model/d", "model/e", "model/f"}}
			_, err := runFusionPanel(context.Background(), provider, req, config, gateway, nil, "test", "id", "log")
			ledger.mu.Lock()
			defer ledger.mu.Unlock()
			provider.mu.Lock()
			defer provider.mu.Unlock()
			if balance == 100000 {
				if err == nil || ledger.denied != 1 || len(provider.calls) != 0 || ledger.spent != 0 || ledger.settled != 0 || ledger.refunded != len(ledger.authorized) {
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
	for _, configured := range []int{0, 1024, 60000} {
		for _, model := range []string{"model/unknown", "model/capped"} {
			t.Run(fmt.Sprintf("%d/%s", configured, model), func(t *testing.T) {
				gateway, ledger := newFusionLedgerGateway(t, 10000000)
				if _, err := gateway.PublicModels(context.Background()); err != nil {
					t.Fatal(err)
				}
				req := &types.OpenAIChatRequest{MaxTokens: intPtrMainTest(100), Messages: []types.OpenAIChatMessage{{Role: "user", Content: "hard problem"}}}
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
