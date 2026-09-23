package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/auth"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
)

func TestServeOnePolyphemusResponses(t *testing.T) {
	for _, tc := range []struct{ stream, fallback, session bool }{
		{false, false, false}, {true, false, false}, {false, true, false}, {true, true, false},
		{false, false, true}, {true, false, true}, {false, true, true}, {true, true, true},
	} {
		t.Run(fmt.Sprint(tc), func(t *testing.T) {
			stream := tc.stream
			selectorCost := 50
			selectorTokens := 0
			sessionID := ""
			if tc.session {
				sessionID = "private-conversation-id"
			}
			if tc.fallback {
				selectorCost = 0
			}
			original := enclaveModelSelector
			t.Cleanup(func() { enclaveModelSelector = original })
			var mu sync.Mutex
			enclaveModelSelector = selectionStub(func(_ context.Context, messages string, perf float64, selectorSessionID string) (*llm.ModelSelection, error) {
				mu.Lock()
				selectorTokens = len(messages) / 4
				mu.Unlock()
				if !strings.Contains(messages, "PRIVATE INPUT") || perf != .9 {
					t.Error("incorrect selection request")
				}
				if selectorSessionID != polyphemusSelectorSessionID("test-user-bearer", sessionID) || strings.Contains(messages, "private-conversation-id") {
					t.Error("session was not scoped or leaked into selector context")
				}
				if tc.fallback {
					return nil, errors.New("selector unavailable")
				}
				return &llm.ModelSelection{Model: "gemini-3.8-flash"}, nil
			})
			admissions, settlements := []string{}, []string{}
			refunds := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				if strings.Contains(string(body), "PRIVATE INPUT") || strings.Contains(string(body), "test-user-bearer") {
					t.Error("content/key leaked to control plane")
				}
				var data map[string]any
				_ = json.Unmarshal(body, &data)
				switch r.URL.Path {
				case "/v1/models", "/models":
					_, _ = io.WriteString(w, selectionTestCatalog)
				case "/internal/gateway/authorize":
					if sessionID != "" && data["session_id"] != sessionID {
						t.Error("lost original session attribution")
					}
					route, _ := data["route_type"].(string)
					mu.Lock()
					admissions = append(admissions, route)
					mu.Unlock()
					if route == polyphemusSelectRoute {
						_, _ = fmt.Fprint(w, `{"data":{"authorization_id":"auth_selector","workspace_id":"ws_1","api_key_hash":"key_1","model":"trustedrouter/polyphemus-1.0","endpoint_id":"selector","provider":"telluvian","usage_type":"Credits","limit_usage_type":"Credits","estimated_cost_microdollars":1}}`)
					} else {
						wanted := "google/gemini-3.8-flash"
						if tc.fallback {
							wanted = "trustedrouter/auto"
						}
						if data["model"] != wanted {
							t.Error("wrong selected model")
						}
						_, _ = fmt.Fprint(w, `{"data":{"authorization_id":"auth_generation","workspace_id":"ws_1","api_key_hash":"key_1","model":"google/gemini-3.8-flash","endpoint_id":"google/gemini-3.8-flash@google-ai-studio/prepaid","provider":"google-ai-studio","usage_type":"Credits","limit_usage_type":"Credits","route_candidates":[]}}`)
					}
				case "/internal/gateway/settle":
					route, _ := data["route_type"].(string)
					mu.Lock()
					settlements = append(settlements, route)
					meteredTokens := selectorTokens
					mu.Unlock()
					if route == polyphemusSelectRoute {
						if data["actual_input_tokens"] != float64(meteredTokens) || data["actual_output_tokens"] != float64(0) || data["usage_estimated"] != true {
							t.Errorf("incorrect selector meter: %#v", data)
						}
						_, _ = fmt.Fprintf(w, `{"data":{"settled":true,"generation_id":"selection","cost_microdollars":%d,"model":"trustedrouter/polyphemus-1.0","provider":"telluvian"}}`, selectorCost)
					} else {
						_, _ = fmt.Fprint(w, `{"data":{"settled":true,"generation_id":"generation","cost_microdollars":12,"model":"google/gemini-3.8-flash","provider":"google-ai-studio"}}`)
					}
				case "/internal/gateway/refund":
					mu.Lock()
					refunds++
					mu.Unlock()
					_, _ = fmt.Fprint(w, `{"data":{"refunded":true}}`)
				default:
					t.Errorf("unexpected path: %s", r.URL.Path)
					http.Error(w, "unexpected", 500)
				}
			}))
			defer server.Close()
			gateway := trustedrouter.New(server.URL, "internal-token", server.Client())
			serverConn, client := net.Pipe()
			defer client.Close()
			_ = client.SetDeadline(time.Now().Add(10 * time.Second))
			go serveOne(context.Background(), serverConn, auth.New(nil), &fakeStreamingLLM{}, nil, nil, gateway, nil)
			body := fmt.Sprintf(`{"model":"trustedrouter/polyphemus-1.0","input":"PRIVATE INPUT","max_output_tokens":32,"stream":%t,"session_id":%q}`, stream, sessionID)
			_, err := fmt.Fprintf(client, "POST /v1/responses HTTP/1.1\r\nAuthorization: Bearer test-user-bearer\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
			if err != nil {
				t.Fatal(err)
			}
			response, err := http.ReadResponse(bufio.NewReader(client), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			output, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != 200 {
				t.Fatalf("%d %s", response.StatusCode, output)
			}
			var payload map[string]any
			if stream {
				if !strings.Contains(string(output), "response.output_text.delta") || !strings.Contains(string(output), "[DONE]") {
					t.Fatalf("incomplete SSE: %s", output)
				}
				for _, line := range strings.Split(string(output), "\n") {
					if !strings.HasPrefix(line, "data: ") {
						continue
					}
					var event map[string]any
					if json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &event) == nil && event["type"] == "response.completed" {
						payload, _ = event["response"].(map[string]any)
					}
				}
			} else if err := json.Unmarshal(output, &payload); err != nil {
				t.Fatal(err)
			}
			if payload == nil || payload["model"] != polyphemusModel {
				t.Fatalf("wrong response: %s", output)
			}
			usage, _ := payload["usage"].(map[string]any)
			if usage["input_tokens"] != float64(2) || usage["output_tokens"] != float64(2) {
				t.Fatalf("selector corrupted generation tokens: %#v", usage)
			}
			if usage["cost_microdollars"] != float64(12+selectorCost) {
				t.Fatalf("wrong total: %#v", usage)
			}
			providerUsage, _ := usage["provider_usage"].(map[string]any)
			if providerUsage["selector_session_supplied"] != tc.session {
				t.Fatalf("missing session request metadata: %#v", providerUsage)
			}
			if providerUsage["selector_cost_microdollars"] != float64(selectorCost) || providerUsage["generation_cost_microdollars"] != float64(12) {
				t.Fatalf("wrong breakdown: %#v", providerUsage)
			}
			mu.Lock()
			billedSelectorTokens := selectorTokens
			mu.Unlock()
			if tc.fallback {
				billedSelectorTokens = 0
			}
			if providerUsage["selector_input_tokens"] != float64(billedSelectorTokens) || providerUsage["selector_usage_estimated"] != true {
				t.Fatalf("incorrect selector metering disclosure: %#v", providerUsage)
			}
			mu.Lock()
			defer mu.Unlock()
			if tc.fallback {
				if len(admissions) != 2 || len(settlements) != 1 || settlements[0] != "responses" || refunds != 1 || providerUsage["selector_fallback_model"] != "trustedrouter/auto" {
					t.Fatalf("fallback admit=%v settle=%v refunds=%d usage=%v", admissions, settlements, refunds, providerUsage)
				}
			} else if len(admissions) != 2 || len(settlements) != 2 || settlements[0] != polyphemusSelectRoute || settlements[1] != "responses" || refunds != 0 {
				t.Fatalf("admit=%v settle=%v", admissions, settlements)
			}
		})
	}
}
