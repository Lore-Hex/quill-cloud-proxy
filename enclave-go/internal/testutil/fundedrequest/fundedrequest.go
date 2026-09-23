// Package fundedrequest supplies socket-free authorization fixtures for native
// wire tests. Orchestration tests separately exercise stage construction and
// catalog clamping through authorizeFusionCall.
package fundedrequest

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

type transport func(*http.Request) (*http.Response, error)

func (f transport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// New shapes inherited reasoning with the same helper used before fusion
// authorization and returns the output limit captured at the billing boundary.
func New(t *testing.T, total int, reasoning any, effort string) (*types.OpenAIChatRequest, *types.AnthropicMessagesRequest, int) {
	t.Helper()
	req := &types.OpenAIChatRequest{Model: "model/test", MaxTokens: &total, Reasoning: reasoning, ReasoningEffort: effort, Messages: []types.OpenAIChatMessage{{Role: "user", Content: "problem"}}}
	adapter.ConstrainReasoningBudget(req, total)
	authorized := 0
	gateway := trustedrouter.New("https://trustedrouter.com", "token", &http.Client{Transport: transport(func(r *http.Request) (*http.Response, error) {
		var p map[string]any
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			return nil, err
		}
		authorized = int(p["max_output_tokens"].(float64))
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"data":{"authorization_id":"hold","model":"model/test","provider":"test","usage_type":"Credits"}}`))}, nil
	})})
	if _, err := gateway.AuthorizeWithRoute(context.Background(), "test", req, "fusion.panel"); err != nil {
		t.Fatal(err)
	}
	body, err := adapter.ToAnthropic(req, req.Model)
	if err != nil {
		t.Fatal(err)
	}
	if authorized != total {
		t.Fatalf("authorized=%d want %d", authorized, total)
	}
	return req, body, authorized
}

// Check serializes the production provider projection and checks total output
// and any numeric thinking budget against the actual authorization payload.
func Check(t *testing.T, wire any, authorized int, gemini bool) {
	t.Helper()
	raw, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	var p map[string]any
	if err = json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	field := "max_tokens"
	if gemini {
		p = p["generationConfig"].(map[string]any)
		field = "maxOutputTokens"
	} else if _, ok := p["max_completion_tokens"]; ok {
		field = "max_completion_tokens"
	}
	if p[field] != float64(authorized) {
		t.Fatalf("wire limit != authorization %d: %s", authorized, raw)
	}
	thinking, _ := p["thinking"].(map[string]any)
	key := "budget_tokens"
	if gemini {
		thinking, _ = p["thinkingConfig"].(map[string]any)
		key = "thinkingBudget"
	}
	if n, ok := thinking[key].(float64); ok && (n < 0 || n >= float64(authorized)) {
		t.Fatalf("thinking exceeds total authorization %d: %s", authorized, raw)
	}
}
