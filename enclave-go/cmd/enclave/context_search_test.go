package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/auth"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/websearch"
)

func TestContextWebSearchEndToEnd(t *testing.T) {
	for _, route := range []string{"responses", "chat/completions"} {
		for _, tc := range []struct {
			stream  bool
			credits int
		}{{false, 1}, {true, 1}, {false, 2}, {true, 2}} {
			stream := tc.stream
			charge := tc.credits * websearch.ContextCreditMicrodollars
			t.Run(fmt.Sprintf("%s/stream=%t/credits=%d", route, stream, tc.credits), func(t *testing.T) {
				previousExa, previousContext := enclaveWebSearchClient, enclaveContextSearchClient
				enclaveWebSearchClient = nil
				searcher := &fakeResponsesWebSearcher{results: []websearch.Result{{CostMicrodollars: charge, Sources: []websearch.Source{{Title: "Release", URL: "https://example.com/release", Snippet: "Evidence"}}}}}
				enclaveContextSearchClient = searcher
				t.Cleanup(func() { enclaveWebSearchClient, enclaveContextSearchClient = previousExa, previousContext })
				gateway, recorder, closeGateway := newFusionGatewayRecorder(t)
				defer closeGateway()
				server, client := net.Pipe()
				defer client.Close()
				go serveOne(context.Background(), server, auth.New(nil), webSearchScriptedLLM{}, nil, nil, gateway, nil)
				input := `"input":"What changed?","store":false`
				if route == "chat/completions" {
					input = `"messages":[{"role":"user","content":"What changed?"}],"stream_options":{"include_usage":true}`
				}
				request := fmt.Sprintf(`{"model":"test/model",%s,"tools":[{"type":"web_search","engine":"context.dev"}],"tool_choice":"required","max_tool_calls":1,"stream":%t}`, input, stream)
				if _, err := fmt.Fprintf(client, "POST /v1/%s HTTP/1.1\r\nAuthorization: Bearer test-key\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", route, len(request), request); err != nil {
					t.Fatal(err)
				}
				response, err := http.ReadResponse(bufio.NewReader(client), nil)
				if err != nil {
					t.Fatal(err)
				}
				defer response.Body.Close()
				body, _ := io.ReadAll(response.Body)
				if response.StatusCode != 200 {
					t.Fatalf("status=%d body=%s", response.StatusCode, body)
				}
				for _, expected := range []string{`"web_search_engine":"context.dev"`, `"web_search_credit_microdollars":6000`, fmt.Sprintf(`"web_search_credits":%d`, tc.credits), fmt.Sprintf(`"web_search_cost_microdollars":%d`, charge), `"conservative_credit_tariff"`, "https://example.com/release"} {
					if !bytes.Contains(body, []byte(expected)) {
						t.Fatalf("missing %s: %s", expected, body)
					}
				}
				if bytes.Contains(body, []byte(`"operator_web_search_cost_microdollars"`)) {
					t.Fatal("estimated tariff labeled actual operator cost")
				}
				if len(searcher.queries) != 1 {
					t.Fatal("incorrect search count")
				}
				recorder.mu.Lock()
				defer recorder.mu.Unlock()
				if len(recorder.authorize) != 2 || len(recorder.settle) != 2 || len(recorder.refund) != 0 {
					t.Fatal("unexpected billing operations")
				}
				if recorder.authorize[0]["additional_cost_reservation_microdollars"] != float64(12000) || recorder.settle[0]["additional_cost_microdollars"] != float64(charge) {
					t.Fatal("wrong context reserve/settle")
				}
			})
		}
	}
}

func TestContextWebSearchNoImplicitFallback(t *testing.T) {
	previousExa, previousContext := enclaveWebSearchClient, enclaveContextSearchClient
	t.Cleanup(func() { enclaveWebSearchClient, enclaveContextSearchClient = previousExa, previousContext })
	enclaveWebSearchClient = &fakeResponsesWebSearcher{}
	enclaveContextSearchClient = nil
	if selectedWebSearchClient(&types.ResponseWebSearchConfig{Engine: "context.dev"}) != nil {
		t.Fatal("context fell back to exa")
	}
	configureContextSearch("key")
	if selectedWebSearchClient(&types.ResponseWebSearchConfig{Engine: "context.dev"}) == nil {
		t.Fatal("context not configured")
	}
	if selectedWebSearchClient(&types.ResponseWebSearchConfig{Engine: "context"}) != nil {
		t.Fatal("removed alias selected a search engine")
	}
	configureContextSearch("")
	if enclaveContextSearchClient != nil {
		t.Fatal("removed credential still configured")
	}
	if selectedWebSearchClient(&types.ResponseWebSearchConfig{Engine: "unknown"}) != nil {
		t.Fatal("unknown engine fell back")
	}
}

func TestContextWebSearchFailureRefundsOnce(t *testing.T) {
	for _, route := range []string{"responses", "chat/completions"} {
		for _, stream := range []bool{false, true} {
			for _, tc := range []struct {
				name   string
				err    error
				cost   int
				status int
			}{
				{"rate_limited", &websearch.ProviderError{StatusCode: 429, Retryable: true}, 0, 429},
				{"invalid_usage", errors.New("invalid provider credit usage"), 0, 502},
				{"over_reserve", nil, 18000, 502},
			} {
				t.Run(fmt.Sprintf("%s/stream=%t/%s", route, stream, tc.name), func(t *testing.T) {
					previousExa, previousContext := enclaveWebSearchClient, enclaveContextSearchClient
					exa := &fakeResponsesWebSearcher{}
					searcher := &fakeResponsesWebSearcher{errors: []error{tc.err}, results: []websearch.Result{{CostMicrodollars: tc.cost}}}
					enclaveWebSearchClient, enclaveContextSearchClient = exa, searcher
					t.Cleanup(func() { enclaveWebSearchClient, enclaveContextSearchClient = previousExa, previousContext })
					gateway, recorder, closeGateway := newFusionGatewayRecorder(t)
					defer closeGateway()
					server, client := net.Pipe()
					defer client.Close()
					go serveOne(context.Background(), server, auth.New(nil), webSearchScriptedLLM{}, nil, nil, gateway, nil)
					input := `"input":"What changed?","store":false`
					if route == "chat/completions" {
						input = `"messages":[{"role":"user","content":"What changed?"}]`
					}
					request := fmt.Sprintf(`{"model":"test/model",%s,"tools":[{"type":"web_search","engine":"context.dev"}],"tool_choice":"required","max_tool_calls":1,"stream":%t}`, input, stream)
					if _, err := fmt.Fprintf(client, "POST /v1/%s HTTP/1.1\r\nAuthorization: Bearer test-key\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", route, len(request), request); err != nil {
						t.Fatal(err)
					}
					response, err := http.ReadResponse(bufio.NewReader(client), nil)
					if err != nil {
						t.Fatal(err)
					}
					defer response.Body.Close()
					body, err := io.ReadAll(response.Body)
					if err != nil {
						t.Fatal(err)
					}
					wantStatus := tc.status
					if stream {
						wantStatus = http.StatusOK
					}
					if response.StatusCode != wantStatus || !bytes.Contains(body, []byte(`"error"`)) {
						t.Fatalf("missing failure response: status=%d body=%s", response.StatusCode, body)
					}
					if len(searcher.queries) != 1 || len(exa.queries) != 0 {
						t.Fatal("failed search was retried or fell back to Exa")
					}
					recorder.mu.Lock()
					defer recorder.mu.Unlock()
					if len(recorder.authorize) != 1 || len(recorder.settle) != 0 || len(recorder.refund) != 1 {
						t.Fatalf("authorize=%d settle=%d refund=%d; want 1/0/1", len(recorder.authorize), len(recorder.settle), len(recorder.refund))
					}
					if recorder.authorize[0]["additional_cost_reservation_microdollars"] != float64(12000) {
						t.Fatal("incorrect hold before failed search")
					}
				})
			}
		}
	}
}

func TestContextWebSearchTariffReservation(t *testing.T) {
	for _, tc := range []struct{ results, calls, total, want int }{{5, 3, 0, 36000}, {25, 2, 0, 72000}, {10, 30, 2, 24000}} {
		config := &types.ResponseWebSearchConfig{Engine: "context.dev", MaxResults: tc.results, MaxCalls: tc.calls, MaxTotalResults: tc.total}
		if got := webSearchReservationMicrodollars(config); got != tc.want {
			t.Fatalf("reserve=%d want=%d", got, tc.want)
		}
	}
	for _, model := range []string{"trustedrouter/zdr", "trustedrouter/confidential", "trustedrouter/e2e", "trustedrouter/eu"} {
		req := webSearchTestRequest()
		req.Model = model
		req.Response.WebSearch.Engine = "context.dev"
		if validateResponsesWebSearchPrivacy(req) == nil {
			t.Fatalf("accepted restricted model %s", model)
		}
	}
}

func TestContextWebSearchRemovedAliasNeverInvokesProviders(t *testing.T) {
	previousExa, previousContext := enclaveWebSearchClient, enclaveContextSearchClient
	t.Cleanup(func() { enclaveWebSearchClient, enclaveContextSearchClient = previousExa, previousContext })
	for _, shape := range []struct{ route, input, search string }{
		{"chat/completions", `"messages":[{"role":"user","content":"Search"}]`, `"tools":[{"type":"web_search","engine":"context"}]`},
		{"chat/completions", `"messages":[{"role":"user","content":"Search"}]`, `"tools":[{"type":"openrouter:web_search","parameters":{"engine":"context"}}]`},
		{"chat/completions", `"messages":[{"role":"user","content":"Search"}]`, `"plugins":[{"id":"web","engine":"context"}]`},
		{"responses", `"input":"Search"`, `"tools":[{"type":"web_search","engine":"context"}]`},
	} {
		for _, stream := range []bool{false, true} {
			exa, searcher := &fakeResponsesWebSearcher{}, &fakeResponsesWebSearcher{}
			enclaveWebSearchClient, enclaveContextSearchClient = exa, searcher
			provider := &privacyEchoProvider{}
			body := fmt.Sprintf(`{"model":"test/model",%s,%s,"stream":%t}`, shape.input, shape.search, stream)
			status, response := privacyRoundTrip(t, "/v1/"+shape.route, body, provider)
			if status != http.StatusNotImplemented || provider.calls != 0 || len(exa.queries) != 0 || len(searcher.queries) != 0 {
				t.Fatalf("removed alias reached a provider: status=%d provider=%d exa=%d context=%d response=%s", status, provider.calls, len(exa.queries), len(searcher.queries), response)
			}
		}
	}
}
