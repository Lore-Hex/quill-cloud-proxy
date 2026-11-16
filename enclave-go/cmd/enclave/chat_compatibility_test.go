package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/auth"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
)

func TestServeLegacyUsageAndCacheRetention(t *testing.T) {
	for _, route := range []string{"/v1/chat/completions", "/v1/responses"} {
		for _, stream := range []bool{false, true} {
			for _, tc := range []struct {
				field, value, parameter string
				status                  int
			}{
				{"usage", `{"include":true}`, "", 200},
				{"usage", `{"include":false}`, "", 200},
				{"usage", `null`, "", 200},
				{"usage", `{"include":"private-value"}`, "usage.include", 400},
				{"usage", `{"future_option":"private-value"}`, "usage.future_option", 400},
				{"future_option", `"private-value"`, "future_option", 400},
				{strings.Repeat("q", 100), `"private-value"`, strings.Repeat("q", 100), 400},
				{strings.Repeat("q", 101), `"private-value"`, "", 400},
				{"prompt_cache_retention", `null`, "", 200},
				{"prompt_cache_retention", `"in_memory"`, "prompt_cache_retention", 501},
				{"prompt_cache_retention", `"24h"`, "prompt_cache_retention", 501},
				{"include", `["reasoning.encrypted_content"]`, "", 200},
				{"include", `["reasoning.encrypted_content","private-value"]`, "include", 501},
				{"modalities", `["audio"]`, "modalities", 501},
			} {
				t.Run(fmt.Sprintf("%s/%t/%s/%s", route, stream, tc.field, tc.value), func(t *testing.T) {
					if tc.field == "include" && route == "/v1/chat/completions" {
						tc.status, tc.parameter = 400, "include"
					}
					wantPreview := `"[redacted:string]"`
					if tc.parameter == "prompt_cache_retention" {
						wantPreview = tc.value
					} else if tc.parameter == "" {
						wantPreview = ""
					} else if tc.field == "include" || tc.field == "modalities" {
						wantPreview = strings.ReplaceAll(tc.value, "private-value", "[redacted:string]")
					}
					var authorize, settle, validate, unexpected atomic.Int32
					control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						body, _ := io.ReadAll(r.Body)
						for _, private := range []string{"private-content", "private-value", "sk-private-test-bearer"} {
							if strings.Contains(string(body), private) {
								t.Error("private value reached control plane")
							}
						}
						if len(tc.field) > 100 && strings.Contains(string(body), tc.field[:100]) {
							t.Error("oversized field or its prefix reached control plane")
						}
						switch r.URL.Path {
						case "/internal/gateway/authorize":
							authorize.Add(1)
							_, _ = io.WriteString(w, `{"data":{"authorization_id":"auth_compat","workspace_id":"ws_1","api_key_hash":"key_1","model":"openai/gpt-4o-mini","endpoint_id":"openai/gpt-4o-mini@openai/prepaid","provider":"openai","usage_type":"Credits","limit_usage_type":"Credits","route_candidates":[]}}`)
						case "/internal/gateway/settle":
							settle.Add(1)
							_, _ = io.WriteString(w, `{"data":{"settled":true,"generation_id":"gen_compat","cost_microdollars":12,"model":"openai/gpt-4o-mini","provider":"openai","region":"us-central1"}}`)
						case "/internal/gateway/validate":
							validate.Add(1)
							var payload struct {
								Rejection struct {
									ParameterPath string `json:"parameter_path"`
									ValuePreview  string `json:"value_preview"`
								} `json:"contract_rejection"`
							}
							if err := json.Unmarshal(body, &payload); err != nil {
								t.Error(err)
							}
							if payload.Rejection.ParameterPath != tc.parameter {
								t.Errorf("lost rejected field: %s", body)
							}
							if payload.Rejection.ValuePreview != wantPreview {
								t.Errorf("wrong safe value preview: got %q want %q", payload.Rejection.ValuePreview, wantPreview)
							}
							_, _ = io.WriteString(w, `{"data":{"workspace_id":"ws_1","api_key_hash":"key_1"}}`)
						default:
							unexpected.Add(1)
							w.WriteHeader(500)
						}
					}))
					defer control.Close()
					input := `"messages":[{"role":"user","content":"private-content"}]`
					if route == "/v1/responses" {
						input = `"input":"private-content"`
					}
					body := fmt.Sprintf(`{"model":"openai/gpt-4o-mini",%s,"stream":%t,%q:%s}`, input, stream, tc.field, tc.value)
					request := fmt.Sprintf("POST %s HTTP/1.1\r\nAuthorization: Bearer sk-private-test-bearer\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", route, len(body), body)
					conn := newScriptedConn(request, nil)
					provider := &fakeStreamingLLM{}
					logs := captureProviderStreamStderr(t, func() *providerInvocation {
						serveOne(context.Background(), conn, auth.New(nil), provider, nil, nil, trustedrouter.New(control.URL, "internal-test", control.Client()), nil)
						return nil
					})
					response, responseBody := readRawHTTPResponse(t, conn.writes.Bytes())
					if response.StatusCode != tc.status {
						t.Fatalf("status=%d want %d body=%s", response.StatusCode, tc.status, responseBody)
					}
					if unexpected.Load() != 0 {
						t.Fatal("unexpected billing operation")
					}
					if strings.Contains(logs, "private-content") || strings.Contains(logs, "private-value") {
						t.Fatal("logged request value")
					}
					if len(tc.field) > 100 && strings.Contains(logs, tc.field[:100]) {
						t.Fatal("logged oversized field or its prefix")
					}
					if tc.status != 200 {
						if authorize.Load() != 0 || settle.Load() != 0 || provider.request != nil || validate.Load() != 1 {
							t.Fatal("rejection must only validate identity, never invoke or bill")
						}
						if !strings.Contains(logs, `parameter_path="`+tc.parameter+`"`) {
							t.Fatal("rejected field missing from durable log")
						}
						if !strings.Contains(logs, fmt.Sprintf("value_preview=%q", wantPreview)) {
							t.Fatal("missing safe preview in durable log")
						}
						return
					}
					if authorize.Load() != 1 || settle.Load() != 1 || provider.request == nil {
						t.Fatalf("authorize=%d settle=%d called=%t", authorize.Load(), settle.Load(), provider.request != nil)
					}
					wantUsage := !stream || route == "/v1/responses" || tc.value == `{"include":true}`
					if strings.Contains(string(responseBody), `"usage"`) != wantUsage {
						t.Fatalf("missing usage: %s", responseBody)
					}
					encoded, err := json.Marshal(provider.request)
					if err != nil {
						t.Fatal(err)
					}
					if strings.Contains(string(encoded), `"usage"`) || strings.Contains(string(encoded), `"prompt_cache_retention"`) {
						t.Fatal("local-only option sent to provider")
					}
					if stream && strings.Count(string(responseBody), "data: [DONE]") != 1 {
						t.Fatalf("incomplete stream: %s", responseBody)
					}
				})
			}
		}
	}
}

func TestLegacyUsageDoesNotDisableExplicitStreamUsage(t *testing.T) {
	for _, legacy := range []string{`{"include":false}`, `null`, `{}`} {
		req, err := parseChatRequest([]byte(`{"model":"m","messages":[],"stream":true,"stream_options":{"include_usage":true},"usage":` + legacy + `}`))
		if err != nil {
			t.Fatal(err)
		}
		if req.StreamOptions == nil || !req.StreamOptions.IncludeUsage {
			t.Fatal("legacy usage disabled explicit stream usage")
		}
	}
}

// compatibilityControlPlane is a control plane that authorizes and settles
// one request, records what the gateway told it, and fails the test if any
// request value reaches it.
type compatibilityControlPlane struct {
	authorize, settle, validate, unexpected atomic.Int32
	requestedParameters                     atomic.Value
	rejection                               atomic.Value
}

type compatibilityRejection struct {
	Status        int    `json:"status"`
	Parameter     string `json:"parameter"`
	ParameterPath string `json:"parameter_path"`
	ValuePreview  string `json:"value_preview"`
}

func (c *compatibilityControlPlane) serve(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		for _, private := range []string{"private-content", "private-value", "sk-private-test-bearer", "client_metadata\":{", "x-codex"} {
			if strings.Contains(string(body), private) {
				t.Errorf("request value reached control plane at %s: %s", r.URL.Path, private)
			}
		}
		switch r.URL.Path {
		case "/internal/gateway/authorize":
			c.authorize.Add(1)
			var request struct {
				RequestedParameters json.RawMessage `json:"requested_parameters"`
			}
			if err := json.Unmarshal(body, &request); err != nil {
				t.Error(err)
			}
			c.requestedParameters.Store(string(request.RequestedParameters))
			_, _ = io.WriteString(w, `{"data":{"authorization_id":"auth_compat","workspace_id":"ws_1","api_key_hash":"key_1","model":"openai/gpt-4o-mini","endpoint_id":"openai/gpt-4o-mini@openai/prepaid","provider":"openai","usage_type":"Credits","limit_usage_type":"Credits","route_candidates":[]}}`)
		case "/internal/gateway/settle":
			c.settle.Add(1)
			_, _ = io.WriteString(w, `{"data":{"settled":true,"generation_id":"gen_compat","cost_microdollars":12,"model":"openai/gpt-4o-mini","provider":"openai","region":"us-central1"}}`)
		case "/internal/gateway/validate":
			c.validate.Add(1)
			var payload struct {
				Rejection compatibilityRejection `json:"contract_rejection"`
			}
			if err := json.Unmarshal(body, &payload); err != nil {
				t.Error(err)
			}
			c.rejection.Store(payload.Rejection)
			_, _ = io.WriteString(w, `{"data":{"workspace_id":"ws_1","api_key_hash":"key_1"}}`)
		default:
			c.unexpected.Add(1)
			w.WriteHeader(500)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

// serveCompatibilityRequest serves one request and returns its status, the
// provider call it made, and everything it logged.
func serveCompatibilityRequest(t *testing.T, control *httptest.Server, route, body string) (int, *fakeStreamingLLM, string) {
	t.Helper()
	request := fmt.Sprintf("POST %s HTTP/1.1\r\nAuthorization: Bearer sk-private-test-bearer\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", route, len(body), body)
	conn := newScriptedConn(request, nil)
	provider := &fakeStreamingLLM{}
	logs := captureProviderStreamStderr(t, func() *providerInvocation {
		serveOne(context.Background(), conn, auth.New(nil), provider, nil, nil, trustedrouter.New(control.URL, "internal-test", control.Client()), nil)
		return nil
	})
	response, _ := readRawHTTPResponse(t, conn.writes.Bytes())
	for _, private := range []string{"private-content", "private-value", "x-codex"} {
		if strings.Contains(logs, private) {
			t.Fatalf("logged request value %s", private)
		}
	}
	return response.StatusCode, provider, logs
}

func TestServeChatThinkingSwitchCompatibility(t *testing.T) {
	for _, tc := range []struct {
		fields string
		// An accepted request: the reasoning control the provider call
		// carries and the parameters authorization is told were requested.
		reasoning, parameters string
		// A refused request: what the rejection report carries.
		rejection compatibilityRejection
	}{
		{fields: `"enable_thinking":false`, reasoning: `{"enabled":false}`, parameters: `["reasoning"]`},
		{fields: `"chat_template_kwargs":{"enable_thinking":false}`, reasoning: `{"enabled":false}`, parameters: `["reasoning"]`},
		{fields: `"chat_template_kwargs":{"thinking":true},"reasoning_effort":"low"`, reasoning: `{"effort":"low","enabled":true}`, parameters: `["reasoning"]`},
		{fields: `"thinking":{"type":"enabled"},"reasoning_effort":"high"`, reasoning: `{"effort":"high","enabled":true}`, parameters: `["reasoning"]`},
		{fields: `"thinking":{"type":"disabled"},"reasoning_effort":"high"`, reasoning: `{"enabled":false}`, parameters: `["reasoning"]`},
		{fields: `"chat_template_kwargs":{}`, reasoning: `null`, parameters: ``},
		{fields: `"thinking":{"type":"enabled"},"reasoning_effort":"none"`,
			rejection: compatibilityRejection{400, "thinking", "thinking", `{"type":"enabled"}`}},
		{fields: `"thinking":{"type":"enabled","budget_tokens":4096},"reasoning_effort":"high"`,
			rejection: compatibilityRejection{400, "thinking", "thinking", `{"budget_tokens":4096,"type":"enabled"}`}},
		{fields: `"thinking":{"type":"enabled","display":"private-value"}`,
			rejection: compatibilityRejection{400, "thinking", "thinking.display", `"[redacted:string]"`}},
		{fields: `"thinking":{"type":"auto","signature":"private-value"},"enable_thinking":true`,
			rejection: compatibilityRejection{400, "thinking", "thinking", `{"_redacted":true,"type":"auto"}`}},
		{fields: `"chat_template_kwargs":{"enable_thinking":true,"thinking":false}`,
			rejection: compatibilityRejection{400, "chat_template_kwargs", "chat_template_kwargs", `{"enable_thinking":true,"thinking":false}`}},
		{fields: `"chat_template_kwargs":{"enable_thinking":false,"documents":["private-value"]}`,
			rejection: compatibilityRejection{400, "chat_template_kwargs", "chat_template_kwargs.documents", `"[redacted:array]"`}},
		{fields: `"chat_template_kwargs":"private-value"`,
			rejection: compatibilityRejection{400, "chat_template_kwargs", "chat_template_kwargs", `"[redacted:string]"`}},
	} {
		for _, stream := range []bool{false, true} {
			t.Run(fmt.Sprintf("%t/%s", stream, tc.fields), func(t *testing.T) {
				control := &compatibilityControlPlane{}
				body := fmt.Sprintf(`{"model":"openai/gpt-4o-mini","messages":[{"role":"user","content":"private-content"}],"stream":%t,%s}`, stream, tc.fields)
				status, provider, logs := serveCompatibilityRequest(t, control.serve(t), "/v1/chat/completions", body)
				if control.unexpected.Load() != 0 {
					t.Fatal("unexpected billing operation")
				}
				if tc.rejection.Status != 0 {
					if status != tc.rejection.Status || control.authorize.Load() != 0 || control.settle.Load() != 0 || provider.request != nil || control.validate.Load() != 1 {
						t.Fatalf("status=%d: a rejection must only validate identity, never invoke or bill", status)
					}
					if got := control.rejection.Load(); got != tc.rejection {
						t.Fatalf("rejection = %+v, want %+v", got, tc.rejection)
					}
					if !strings.Contains(logs, fmt.Sprintf("parameter=%q parameter_path=%q value_preview=%q", tc.rejection.Parameter, tc.rejection.ParameterPath, tc.rejection.ValuePreview)) {
						t.Fatalf("rejection missing from durable log: %s", logs)
					}
					return
				}
				if status != 200 || control.authorize.Load() != 1 || control.settle.Load() != 1 || provider.request == nil {
					t.Fatalf("status=%d authorize=%d settle=%d called=%t", status, control.authorize.Load(), control.settle.Load(), provider.request != nil)
				}
				if got := control.requestedParameters.Load(); got != tc.parameters {
					t.Fatalf("requested_parameters = %s, want %s", got, tc.parameters)
				}
				reasoning, err := json.Marshal(provider.request.Reasoning)
				if err != nil || string(reasoning) != tc.reasoning || provider.request.ReasoningEffort != "" {
					t.Fatalf("reasoning = %s effort = %q, want %s (%v)", reasoning, provider.request.ReasoningEffort, tc.reasoning, err)
				}
				encoded, err := json.Marshal(provider.request)
				if err != nil || strings.Contains(string(encoded), "chat_template_kwargs") || strings.Contains(string(encoded), `"thinking"`) {
					t.Fatalf("alias sent to provider: %s (%v)", encoded, err)
				}
			})
		}
	}
}

func TestServeResponsesCodexCompatibility(t *testing.T) {
	// What Codex sends after its tool list changed: identifiers for its own
	// backend, and history that calls a namespaced function no longer declared.
	const history = `"tools":[{"type":"function","name":"shell","parameters":{"type":"object","properties":{}}}],` +
		`"input":[{"role":"user","content":"private-content"},` +
		`{"type":"function_call","namespace":"mcp__docs","name":"search","call_id":"call_1","arguments":"{}"},` +
		`{"type":"function_call_output","call_id":"call_1","output":"private-content"}]`
	for _, stream := range []bool{false, true} {
		for _, metadata := range []string{`{"x-codex-installation-id":"private-value","x-codex-turn-metadata":{"session":"private-value"}}`, `{}`, `null`} {
			t.Run(fmt.Sprintf("%t/%s", stream, metadata), func(t *testing.T) {
				control := &compatibilityControlPlane{}
				body := fmt.Sprintf(`{"model":"openai/gpt-4o-mini","stream":%t,"store":false,"client_metadata":%s,%s}`, stream, metadata, history)
				status, provider, _ := serveCompatibilityRequest(t, control.serve(t), "/v1/responses", body)
				if status != 200 || control.authorize.Load() != 1 || control.settle.Load() != 1 || control.unexpected.Load() != 0 || provider.request == nil {
					t.Fatalf("status=%d authorize=%d settle=%d called=%t", status, control.authorize.Load(), control.settle.Load(), provider.request != nil)
				}
				if got := control.requestedParameters.Load(); got != `["tools"]` {
					t.Fatalf("requested_parameters = %s", got)
				}
				if call := provider.request.Messages[1].ToolCalls[0]; call.Function.Name != "mcp__docs__search" || call.ID != "call_1" {
					t.Fatalf("replayed call = %+v", call)
				}
				if output := provider.request.Messages[2]; output.Role != "tool" || output.ToolCallID != "call_1" {
					t.Fatalf("tool output = %+v", output)
				}
				for _, sent := range []any{provider.request, provider.body} {
					encoded, err := json.Marshal(sent)
					if err != nil || strings.Contains(string(encoded), "client_metadata") || strings.Contains(string(encoded), "x-codex") || strings.Contains(string(encoded), "private-value") {
						t.Fatalf("client_metadata sent to provider: %s (%v)", encoded, err)
					}
				}
			})
		}
		for _, metadata := range []string{`"private-value"`, `["private-value"]`, `7`} {
			t.Run(fmt.Sprintf("%t/%s", stream, metadata), func(t *testing.T) {
				control := &compatibilityControlPlane{}
				body := fmt.Sprintf(`{"model":"openai/gpt-4o-mini","stream":%t,"client_metadata":%s,%s}`, stream, metadata, history)
				status, provider, _ := serveCompatibilityRequest(t, control.serve(t), "/v1/responses", body)
				if status != 400 || control.authorize.Load() != 0 || control.settle.Load() != 0 || control.unexpected.Load() != 0 || provider.request != nil || control.validate.Load() != 1 {
					t.Fatalf("status=%d: a rejection must only validate identity, never invoke or bill", status)
				}
				got := control.rejection.Load().(compatibilityRejection)
				if got.Status != 400 || got.Parameter != "client_metadata" || got.ParameterPath != "client_metadata" || !strings.HasPrefix(got.ValuePreview, `"[redacted:`) {
					t.Fatalf("rejection = %+v", got)
				}
			})
		}
	}
}
