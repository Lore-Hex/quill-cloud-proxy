package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/auth"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
)

func TestChatOutputConfigEffort(t *testing.T) {
	for _, effort := range []string{"low", "medium", "high", "xhigh", "max"} {
		for _, thinking := range []string{"", `,"thinking":{"type":"adaptive"}`} {
			t.Run(effort+thinking, func(t *testing.T) {
				req, err := parseChatRequest([]byte(fmt.Sprintf(`{"model":"anthropic/claude-opus-5.5","messages":[{"role":"user","content":"hi"}],"output_config":{"effort":%q}%s}`, effort, thinking)))
				if err != nil {
					t.Fatal(err)
				}
				if req.Reasoning.(map[string]any)["effort"] != effort || !reflect.DeepEqual(req.RequestedParameters, []string{"reasoning"}) {
					t.Fatalf("reasoning=%v capabilities=%v", req.Reasoning, req.RequestedParameters)
				}
				wire, err := json.Marshal(req)
				if err != nil || strings.Contains(string(wire), `"output_config"`) || strings.Contains(string(wire), `"thinking"`) {
					t.Fatalf("native alias leaked from normalized request: %s, %v", wire, err)
				}
			})
		}
	}
	if req, err := parseChatRequest([]byte(`{"model":"m","output_config":null}`)); err != nil || req.Reasoning != nil || len(req.RequestedParameters) != 0 {
		t.Fatalf("null should be absent: %+v %v", req, err)
	}
}

func TestChatOutputConfigRejectsInvalidOrConflictingControls(t *testing.T) {
	for _, tc := range []struct{ fields, param string }{
		{`"output_config":"private-value"`, "output_config"},
		{`"output_config":[]`, "output_config"},
		{`"output_config":{}`, "output_config.effort"},
		{`"output_config":{"effort":null}`, "output_config.effort"},
		{`"output_config":{"effort":1}`, "output_config.effort"},
		{`"output_config":{"effort":"private-value"}`, "output_config.effort"},
		{`"output_config":{"effort":"adaptive"}`, "output_config.effort"},
		{`"output_config":{"effort":"HIGH"}`, "output_config.effort"},
		{`"output_config":{"effort":"high","unknown":"private-value"}`, "output_config.unknown"},
		{`"output_config":{"effort":"high","format":{"type":"json_schema"}}`, "output_config.format"},
		{`"output_config":{"effort":"high"},"reasoning_effort":"low"`, "output_config.effort"},
		{`"output_config":{"effort":"high"},"reasoning":{"effort":"low"}`, "output_config.effort"},
		{`"output_config":{"effort":"high"},"thinking":{"type":"disabled"}`, "output_config.effort"},
		{`"output_config":{"effort":"high"},"enable_thinking":false`, "output_config.effort"},
		{`"output_config":{"effort":"high"},"thinking":{"type":"adaptive","budget_tokens":1024}`, "thinking"},
	} {
		t.Run(tc.fields, func(t *testing.T) {
			_, err := parseChatRequest([]byte(`{"model":"anthropic/claude-opus-5.5",` + tc.fields + `}`))
			var rejected *adapter.AdapterError
			if !errors.As(err, &rejected) || rejected.Status != 400 || rejected.Context != tc.param || strings.Contains(err.Error(), "private-value") {
				t.Fatalf("want 400 at %s without request values, got %v", tc.param, err)
			}
		})
	}
}

func TestChatOutputConfigPreservesVisibilityAndExplicitBudget(t *testing.T) {
	for _, visibility := range []string{`"include_reasoning":false`, `"reasoning":{"exclude":true}`} {
		req, err := parseChatRequest([]byte(`{"model":"anthropic/claude-opus-5.5","output_config":{"effort":"high"},` + visibility + `}`))
		if err != nil {
			t.Fatal(err)
		}
		if !req.ExcludeReasoning || !reflect.DeepEqual(req.Reasoning, map[string]any{"effort": "high"}) {
			t.Fatalf("lost visibility or effort: %+v", req)
		}
	}
	req, err := parseChatRequest([]byte(`{"model":"anthropic/claude-opus-4.5","output_config":{"effort":"high"},"thinking":{"type":"enabled","budget_tokens":2048}}`))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(req.Reasoning, map[string]any{"effort": "high", "enabled": true, "max_tokens": float64(2048)}) {
		t.Fatalf("lost caller budget: %v", req.Reasoning)
	}
}

func TestServeChatOutputConfigBilling(t *testing.T) {
	for _, stream := range []bool{false, true} {
		for _, valid := range []bool{false, true} {
			t.Run(fmt.Sprintf("stream=%t/valid=%t", stream, valid), func(t *testing.T) {
				var authorize, settle, unexpected atomic.Int32
				control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					body, _ := io.ReadAll(r.Body)
					if strings.Contains(string(body), "private-content") {
						t.Error("prompt reached control plane")
					}
					switch r.URL.Path {
					case "/internal/gateway/authorize":
						authorize.Add(1)
						var request struct {
							RequestedParameters []string `json:"requested_parameters"`
						}
						if err := json.Unmarshal(body, &request); err != nil || !reflect.DeepEqual(request.RequestedParameters, []string{"reasoning"}) {
							t.Errorf("missing reasoning capability: %s (%v)", body, err)
						}
						_, _ = io.WriteString(w, `{"data":{"authorization_id":"auth_effort","workspace_id":"ws_1","api_key_hash":"key_1","model":"anthropic/claude-opus-5.5","endpoint_id":"anthropic/claude-opus-5.5@anthropic/prepaid","provider":"anthropic","usage_type":"Credits","limit_usage_type":"Credits","route_candidates":[]}}`)
					case "/internal/gateway/settle":
						settle.Add(1)
						_, _ = io.WriteString(w, `{"data":{"settled":true,"generation_id":"gen_effort","cost_microdollars":12,"model":"anthropic/claude-opus-5.5","provider":"anthropic","region":"us-central1"}}`)
					case "/internal/gateway/validate":
						_, _ = io.WriteString(w, `{"data":{"workspace_id":"ws_1","api_key_hash":"key_1"}}`)
					default:
						unexpected.Add(1)
						w.WriteHeader(500)
					}
				}))
				defer control.Close()
				effort, status := "high", 200
				if !valid {
					effort, status = "invalid", 400
				}
				body := fmt.Sprintf(`{"model":"anthropic/claude-opus-5.5","messages":[{"role":"user","content":"private-content"}],"stream":%t,"output_config":{"effort":%q}}`, stream, effort)
				conn := newScriptedConn(fmt.Sprintf("POST /v1/chat/completions HTTP/1.1\r\nAuthorization: Bearer test\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body), nil)
				provider := &fakeStreamingLLM{}
				serveOne(context.Background(), conn, auth.New(nil), provider, nil, nil, trustedrouter.New(control.URL, "internal-test", control.Client()), nil)
				resp, responseBody := readRawHTTPResponse(t, conn.writes.Bytes())
				if resp.StatusCode != status || unexpected.Load() != 0 {
					t.Fatalf("status=%d want=%d unexpected=%d body=%s", resp.StatusCode, status, unexpected.Load(), responseBody)
				}
				if !valid {
					if authorize.Load() != 0 || settle.Load() != 0 || provider.request != nil {
						t.Fatal("invalid effort invoked or billed")
					}
					return
				}
				if authorize.Load() != 1 || settle.Load() != 1 || provider.request == nil || provider.request.Reasoning.(map[string]any)["effort"] != effort {
					t.Fatalf("authorize=%d settle=%d request=%+v", authorize.Load(), settle.Load(), provider.request)
				}
				if stream && strings.Count(string(responseBody), "data: [DONE]") != 1 {
					t.Fatalf("incomplete stream: %s", responseBody)
				}
			})
		}
	}
}
