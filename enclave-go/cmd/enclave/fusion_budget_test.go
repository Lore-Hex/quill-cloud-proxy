package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/auth"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestFusionInnerMaxTokens(t *testing.T) {
	for _, tt := range []struct {
		name       string
		caller     *int
		configured int
		want       *int
	}{
		{"override", intPtrMainTest(60000), 32000, intPtrMainTest(32000)},
		{"override without caller", nil, 32000, intPtrMainTest(32000)},
		{"above old clamp", intPtrMainTest(60000), 0, intPtrMainTest(32768)},
		{"small caller", intPtrMainTest(100), 0, intPtrMainTest(32768)},
		{"unset", nil, 0, intPtrMainTest(32768)},
		{"explicit zero", intPtrMainTest(0), 0, intPtrMainTest(32768)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			req := &types.OpenAIChatRequest{MaxTokens: tt.caller}
			// The former 1200 default / 2048 clamp starved reasoning before visible text.
			if got := fusionInnerMaxTokens(tt.configured); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
			for _, inner := range []*types.OpenAIChatRequest{fusionPanelRequest(req, "model/panel", 0, tt.configured, ""), fusionJudgeRequest(req, "model/judge", nil, tt.configured)} {
				if !reflect.DeepEqual(inner.MaxTokens, tt.want) {
					t.Fatalf("%s max_tokens = %v, want %v", inner.Model, inner.MaxTokens, tt.want)
				}
			}
		})
	}
}

// Like a reasoning provider, this fake returns no visible answer when thinking
// consumes the completion budget. Missing bounds are rejected.
type reasoningBudgetLLM struct{ fusionEchoLLM }

func (f *reasoningBudgetLLM) InvokeStreaming(ctx context.Context, req *types.OpenAIChatRequest, body *types.AnthropicMessagesRequest, out io.Writer, options ...llm.InvokeOptions) error {
	if req.MaxTokens == nil && req.Metadata["trustedrouter_fusion_stage"] != "final" {
		return fmt.Errorf("unfunded inner request")
	}
	if req.MaxTokens != nil && *req.MaxTokens <= 2048 {
		empty := fusionEchoLLM{thinking: true, textByModel: map[string]string{req.Model: ""}}
		return empty.InvokeStreaming(ctx, req, body, out, options...)
	}
	return f.fusionEchoLLM.InvokeStreaming(ctx, req, body, out, options...)
}

func TestFusionReasoningBudgetEndToEnd(t *testing.T) {
	for _, tt := range []struct {
		name, limits, override string
		inner, final           any
		estimate               int
		status                 int
	}{
		{"caller", `,"max_tokens":16000`, "", float64(32768), float64(16000), 32768, 200},
		{"override", `,"max_tokens":16000`, `,"max_completion_tokens":32000`, float64(32000), float64(16000), 32000, 200},
		{"unset", "", "", float64(32768), nil, 32768, 200},
		{"explicit insufficient override preserves empty handling", `,"max_tokens":16000`, `,"max_completion_tokens":2048`, float64(2048), float64(16000), 2048, 502},
	} {
		t.Run(tt.name, func(t *testing.T) {
			gateway, recorder := newFusionBudgetGateway(t)
			streamer := &reasoningBudgetLLM{fusionEchoLLM: fusionEchoLLM{thinking: true}}
			server, client := net.Pipe()
			defer client.Close()
			_ = client.SetDeadline(time.Now().Add(10 * time.Second))
			go serveOne(context.Background(), server, auth.New(nil), streamer, nil, nil, gateway, nil)
			payload := fmt.Sprintf(`{"model":"trustedrouter/synth","messages":[{"role":"user","content":"Solve a hard problem"}],"plugins":[{"id":"synth","analysis_models":["model/reasoner-a","model/reasoner-b"],"model":"model/reasoner-judge"%s}]%s}`, tt.override, tt.limits)
			if _, err := fmt.Fprintf(client, "POST /v1/chat/completions HTTP/1.1\r\nAuthorization: Bearer test\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", len(payload), payload); err != nil {
				t.Fatal(err)
			}
			resp, err := http.ReadResponse(bufio.NewReader(client), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			content, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != tt.status {
				t.Fatalf("status %d: %s", resp.StatusCode, content)
			}
			if tt.status == 502 {
				if !strings.Contains(string(content), "panel produced no successful responses") {
					t.Fatalf("changed empty handling: %s", content)
				}
				return
			}
			if !strings.Contains(string(content), "final answer from model/reasoner-judge") {
				t.Fatalf("no final answer: %s", content)
			}
			recorder.mu.Lock()
			defer recorder.mu.Unlock()
			if len(recorder.authorize) != 4 || len(recorder.settle) != 4 || len(recorder.refund) != 0 {
				t.Fatalf("authorize=%d settle=%d refund=%d", len(recorder.authorize), len(recorder.settle), len(recorder.refund))
			}
			for _, call := range recorder.authorize {
				want, estimate := tt.inner, tt.estimate
				if call["route_type"] == "fusion.final" {
					want = tt.final
					estimate = 512
					if want != nil {
						estimate = int(want.(float64))
					}
				}
				if call["max_tokens"] != want || call["max_output_tokens"] != float64(estimate) {
					t.Fatalf("wrong hold estimate: %#v", call)
				}
			}
		})
	}
}

// Keep the end-to-end HTTP handler test independent of listening sockets.
type fusionBudgetTransport func(*http.Request) (*http.Response, error)

func (f fusionBudgetTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func newFusionBudgetGateway(t *testing.T) (*trustedrouter.Client, *fusionGatewayRecorder) {
	t.Helper()
	recorder := &fusionGatewayRecorder{}
	client := &http.Client{Transport: fusionBudgetTransport(func(r *http.Request) (*http.Response, error) {
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			return nil, err
		}
		recorder.mu.Lock()
		defer recorder.mu.Unlock()
		var data map[string]any
		switch r.URL.Path {
		case "/internal/gateway/authorize":
			recorder.authorize = append(recorder.authorize, payload)
			model := payload["model"].(string)
			data = map[string]any{"authorization_id": fmt.Sprintf("auth_%d", len(recorder.authorize)), "workspace_id": "ws_1", "api_key_hash": "key_1", "model": model, "endpoint_id": model + "@test/prepaid", "provider": "test", "usage_type": "Credits", "limit_usage_type": "Credits", "route_candidates": []any{}}
		case "/internal/gateway/settle":
			recorder.settle = append(recorder.settle, payload)
			data = map[string]any{"settled": true, "generation_id": fmt.Sprintf("gen_%d", len(recorder.settle)), "cost_microdollars": 1, "model": payload["selected_model"], "provider": "test"}
		case "/internal/gateway/refund":
			recorder.refund = append(recorder.refund, payload)
			data = map[string]any{"refunded": true}
		default:
			return nil, fmt.Errorf("unexpected control-plane path %s", r.URL.Path)
		}
		raw, err := json.Marshal(map[string]any{"data": data})
		if err != nil {
			return nil, err
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(raw)))}, nil
	})}
	return trustedrouter.New("https://trustedrouter.com", "internal-token", client), recorder
}
