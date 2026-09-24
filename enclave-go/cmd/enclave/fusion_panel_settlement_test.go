package main

import (
	"context"
	"encoding/json"
	"errors"
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

// TestFusionPanelSettlementOwnership drives settlement through the real panel
// path (concurrent up-front admission, then per-member dispatch), not a single
// inner call: a member whose generation succeeded but whose settlement failed
// must be queued for retry and never refunded, and a member whose generation
// failed must be refunded exactly once and never settled. After the queued
// settlement is processed every hold has exactly one terminal outcome.
func TestFusionPanelSettlementOwnership(t *testing.T) {
	q := &settlementRetryQueue{jobs: make(chan settlementRetryJob, 4), maxAttempts: 2}
	oldQueue := settlementRetries
	settlementRetries = q
	t.Cleanup(func() { settlementRetries = oldQueue })

	var mu sync.Mutex
	authorized := map[string]string{} // authorization id -> model
	settleAttempts := map[string]int{}
	charged := map[string]int{}
	refunded := map[string]int{}
	gateway := trustedrouter.New("https://trustedrouter.com", "internal", &http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			response := func(status int, payload string) (*http.Response, error) {
				return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(payload))}, nil
			}
			mu.Lock()
			defer mu.Unlock()
			switch r.URL.Path {
			case "/internal/gateway/authorize":
				model := fmt.Sprint(body["model"])
				id := "auth_" + strings.ReplaceAll(model, "/", "_")
				authorized[id] = model
				return response(200, fmt.Sprintf(`{"data":{"authorization_id":%q,"model":%q,"endpoint_id":"test-endpoint","provider":"test","usage_type":"Credits"}}`, id, model))
			case "/internal/gateway/settle":
				id := fmt.Sprint(body["authorization_id"])
				settleAttempts[id]++
				if id == "auth_model_ok" && settleAttempts[id] == 1 {
					return response(503, `{"error":{"message":"settlement unavailable"}}`)
				}
				charged[id]++
				return response(200, `{"data":{"settled":true}}`)
			case "/internal/gateway/refund":
				refunded[fmt.Sprint(body["authorization_id"])]++
				return response(200, `{"data":{"refunded":true}}`)
			default:
				t.Fatalf("unexpected control-plane path: %s", r.URL.Path)
				return nil, errors.New("unexpected path")
			}
		}),
	})

	ctx := trustedrouter.WithRequestLogID(t.Context(), "rlog_0123456789abcdef0123456789abcdef")
	req := &types.OpenAIChatRequest{Model: "trustedrouter/synth", Messages: []types.OpenAIChatMessage{{Role: "user", Content: "hello"}}}
	config := fusionConfig{AnalysisModels: []string{"model/ok", "model/bad"}}
	_, _ = runFusionPanel(ctx, &fusionPanelOwnershipLLM{}, req, config, gateway, nil, "bearer", "panel_ownership", "rlog_0123456789abcdef0123456789abcdef")

	mu.Lock()
	if len(authorized) != 2 {
		t.Fatalf("authorizations = %v, want both members held up front", authorized)
	}
	if refunded["auth_model_ok"] != 0 {
		t.Fatalf("a member whose generation succeeded was refunded: %v", refunded)
	}
	if refunded["auth_model_bad"] != 1 || settleAttempts["auth_model_bad"] != 0 {
		t.Fatalf("failed member: refunds=%d settle attempts=%d, want 1 and 0", refunded["auth_model_bad"], settleAttempts["auth_model_bad"])
	}
	if charged["auth_model_ok"] != 0 || settleAttempts["auth_model_ok"] != 1 {
		t.Fatalf("succeeded member before retry: charges=%d attempts=%d, want 0 and 1", charged["auth_model_ok"], settleAttempts["auth_model_ok"])
	}
	mu.Unlock()
	if len(q.jobs) != 1 {
		t.Fatalf("queued settlements = %d, want 1", len(q.jobs))
	}
	job := <-q.jobs
	if job.authorization.AuthorizationID != "auth_model_ok" {
		t.Fatalf("queued the wrong hold: %#v", job.authorization)
	}
	q.process(context.WithoutCancel(ctx), job)
	mu.Lock()
	defer mu.Unlock()
	if charged["auth_model_ok"] != 1 || refunded["auth_model_ok"] != 0 {
		t.Fatalf("succeeded member after retry: charges=%d refunds=%d, want 1 and 0", charged["auth_model_ok"], refunded["auth_model_ok"])
	}
	for id := range authorized {
		if charged[id]+refunded[id] != 1 {
			t.Fatalf("hold %s has %d charges and %d refunds, want exactly one outcome", id, charged[id], refunded[id])
		}
	}
}

type fusionPanelOwnershipLLM struct{}

func (fusionPanelOwnershipLLM) InvokeStreaming(_ context.Context, req *types.OpenAIChatRequest, _ *types.AnthropicMessagesRequest, out io.Writer, _ ...llm.InvokeOptions) error {
	if req != nil && req.Model == "model/bad" {
		return errors.New("provider unavailable")
	}
	_, err := io.WriteString(out, `event: message_start
data: {"type":"message_start","message":{"usage":{"input_tokens":11,"output_tokens":0}}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hello world"}}

event: message_delta
data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":7}}

event: message_stop
data: {"type":"message_stop"}

`)
	return err
}
