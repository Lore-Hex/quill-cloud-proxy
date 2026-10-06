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
				{"include", `["reasoning.encrypted_content"]`, "include", 501},
				{"include", `["reasoning.encrypted_content","private-value"]`, "include", 501},
				{"modalities", `["audio"]`, "modalities", 501},
			} {
				t.Run(fmt.Sprintf("%s/%t/%s/%s", route, stream, tc.field, tc.value), func(t *testing.T) {
					if tc.field == "include" && route == "/v1/chat/completions" {
						tc.status = 400
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
