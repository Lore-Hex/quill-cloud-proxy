package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/auth"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

const rerankPrivateBody = `{"model":"voyage/rerank-3","query":"PRIVATE-QUERY","documents":["PRIVATE-DOCUMENT-A",{"text":"PRIVATE-DOCUMENT-B"}],"session_id":"session","user":"user"}`
const rerankAuthorization = `{"data":{"authorization_id":"auth-rerank","model":"resolved-model","upstream_model":"rerank-3","provider":"voyage","endpoint_id":"primary","usage_type":"Credits","route_candidates":[{"model":"served-model","upstream_model":"rerank-3","provider":"voyage","endpoint_id":"served","usage_type":"Credits"},{"model":"unused-model","upstream_model":"unused","provider":"cohere","endpoint_id":"unused","usage_type":"Credits"}]}}`

type rerankBackend struct {
	fakeStreamingLLM
	response *types.RerankResponse
	err      error
	options  []llm.InvokeOptions
	calls    int
}

func (b *rerankBackend) InvokeRerank(_ context.Context, _ *types.RerankRequest, options ...llm.InvokeOptions) (*types.RerankResponse, error) {
	b.calls++
	b.options = options
	return b.response, b.err
}
func (b *rerankBackend) InvokeEmbedding(_ context.Context, req *types.EmbeddingRequest, _ ...llm.InvokeOptions) (*types.EmbeddingResponse, error) {
	return &types.EmbeddingResponse{Model: req.Model, Usage: types.EmbeddingUsage{PromptTokens: 7, TotalTokens: 7}}, nil
}

func rerankControlPlane(t *testing.T, mode string, calls *map[string][]map[string]any) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		if strings.Contains(string(raw), "PRIVATE-") {
			t.Error("request text reached control plane")
		}
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		(*calls)[r.URL.Path] = append((*calls)[r.URL.Path], body)
		if r.Header.Get("X-TR-Settlement-Mode") != "" {
			t.Error("async header on rerank")
		}
		switch r.URL.Path {
		case "/internal/gateway/authorize":
			if mode == "authorize" {
				w.WriteHeader(400)
				_, _ = io.WriteString(w, `{"error":{"type":"invalid_request","message":"authorization refused"}}`)
				return
			}
			answer := rerankAuthorization
			if mode == "pinned_voyage" {
				answer = strings.Replace(answer, `"provider":"cohere"`, `"provider":"voyage"`, 1)
			}
			if mode == "differential" {
				answer = strings.Replace(answer, `"endpoint_id":"primary"`, `"endpoint_id":"served"`, 1)
			}
			if mode == "byok_answer" {
				answer = strings.Replace(answer, `"usage_type":"Credits"`, `"usage_type":"BYOK"`, 1)
			}
			if mode == "byok_candidate" {
				answer = strings.Replace(answer, `"endpoint_id":"served","usage_type":"Credits"`, `"endpoint_id":"served","usage_type":"BYOK"`, 1)
			}
			if mode == "unsupported_candidate" {
				answer = strings.ReplaceAll(answer, `"provider":"voyage"`, `"provider":"privatemode"`)
			}
			_, _ = io.WriteString(w, answer)
		case "/internal/gateway/settle":
			if mode == "settle" {
				w.WriteHeader(400)
				_, _ = io.WriteString(w, `{"error":{"type":"invalid_request","message":"settlement refused"}}`)
				return
			}
			_, _ = io.WriteString(w, `{"data":{"settled":true,"cost_microdollars":17,"cost":0.000017}}`)
		case "/internal/gateway/refund":
			if mode == "refund" {
				w.WriteHeader(400)
				_, _ = io.WriteString(w, `{"error":{"type":"invalid_request","message":"refund refused"}}`)
				return
			}
			_, _ = io.WriteString(w, `{"data":{"refunded":true}}`)
		case "/internal/gateway/validate":
			_, _ = io.WriteString(w, `{"data":{}}`)
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			w.WriteHeader(400)
		}
	})
}

func rerankMemoryGateway(t *testing.T, mode string, calls *map[string][]map[string]any) *trustedrouter.Client {
	handler := rerankControlPlane(t, mode, calls)
	return trustedrouter.New("https://trustedrouter.com", "internal", &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, r)
		return recorder.Result(), nil
	})})
}

func TestRerankHandlerPrivacyAndBilling(t *testing.T) {
	for _, tc := range []struct {
		name                                      string
		status, authorize, invoke, settle, refund int
	}{
		{"success", 200, 1, 1, 1, 0}, {"estimated", 200, 1, 1, 1, 0}, {"zero_usage", 200, 1, 1, 1, 0},
		{"bad_json", 400, 0, 0, 0, 0}, {"validation", 400, 0, 0, 0, 0}, {"metadata", 400, 0, 0, 0, 0}, {"tags", 400, 0, 0, 0, 0},
		{"byok_request", 400, 0, 0, 0, 0}, {"build", 501, 0, 0, 0, 0}, {"no_plane", 503, 0, 0, 0, 0},
		{"authorize", 400, 1, 0, 0, 0}, {"byok_answer", 400, 1, 0, 0, 1}, {"byok_candidate", 400, 1, 0, 0, 1}, {"unsupported_candidate", 501, 1, 0, 0, 1},
		{"excluded_fallback", 503, 1, 0, 0, 1},
		{"provider", 502, 1, 1, 0, 1}, {"refund", 502, 1, 1, 0, 1}, {"input_limit", 400, 1, 1, 0, 1}, {"unsupported", 501, 1, 1, 0, 1},
		{"nil_response", 502, 1, 1, 0, 1}, {"invalid_result", 502, 1, 1, 0, 1}, {"invalid_usage", 502, 1, 1, 0, 1}, {"settle", 502, 1, 1, 1, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("TR_REQUEST_METADATA_ENFORCEMENT", "enforce")
			calls := make(map[string][]map[string]any)
			gateway := rerankMemoryGateway(t, tc.name, &calls)
			tokens := 7
			backend := &rerankBackend{response: &types.RerankResponse{InputTokens: &tokens, Results: []types.RerankResult{{Index: 1, RelevanceScore: 0.5}, {Index: 0, RelevanceScore: 0.5}}}}
			var client llm.Client = backend
			body := rerankPrivateBody
			switch tc.name {
			case "bad_json":
				body = body + " trailing"
			case "validation":
				body = strings.Replace(body, `"PRIVATE-QUERY"`, `null`, 1)
			case "metadata":
				body = strings.Replace(body, `"session"`, `"`+strings.Repeat("s", 257)+`"`, 1)
			case "tags":
				body = strings.TrimSuffix(body, "}") + `,"tags":{"aws:reserved":"value"}}`
			case "byok_request":
				body = strings.TrimSuffix(body, "}") + `,"provider":{"billing":"byok"}}`
			case "excluded_fallback":
				body = strings.TrimSuffix(body, "}") + `,"provider":{"only":["voyage"]}}`
			case "build":
				client = &fakeStreamingLLM{}
			case "provider", "refund":
				backend.err = errors.New("PRIVATE-QUERY PRIVATE-DOCUMENT-A")
			case "input_limit":
				backend.err = llm.ErrRerankInputLimit
			case "unsupported":
				backend.err = llm.ErrRerankUnsupported
			case "nil_response":
				backend.response = nil
			case "invalid_result":
				backend.response.Results[0].RelevanceScore = math.NaN()
			case "invalid_usage":
				tokens = -1
			case "zero_usage":
				tokens = 0
			case "estimated":
				backend.response.InputTokens = nil
			}
			var out bytes.Buffer
			logs := captureStderr(t, func() {
				serveRerank(t.Context(), &out, client, []byte(body), gateway, tc.name != "no_plane", "test-key", "rerank-idem", requestAttributionHeaders{}, "log-rerank")
			})
			if !strings.HasPrefix(out.String(), fmt.Sprintf("HTTP/1.1 %d ", tc.status)) {
				t.Fatalf("status: %s", out.String())
			}
			for _, private := range []string{"PRIVATE-QUERY", "PRIVATE-DOCUMENT-A", "PRIVATE-DOCUMENT-B"} {
				if strings.Contains(logs, private) {
					t.Fatal("request text in logs")
				}
				if tc.status != 200 && strings.Contains(out.String(), private) {
					t.Fatal("request text in error response")
				}
			}
			if len(calls["/internal/gateway/authorize"]) != tc.authorize || backend.calls != tc.invoke || len(calls["/internal/gateway/settle"]) != tc.settle || len(calls["/internal/gateway/refund"]) != tc.refund {
				t.Fatalf("calls: authorize=%d invoke=%d settle=%d refund=%d", len(calls["/internal/gateway/authorize"]), backend.calls, len(calls["/internal/gateway/settle"]), len(calls["/internal/gateway/refund"]))
			}
			if tc.invoke > 0 && (len(backend.options) != 1 || backend.options[0].EndpointID != "served" || backend.options[0].UpstreamModel != "rerank-3" || backend.options[0].ProviderAPIKey != "") {
				t.Fatal("candidate dispatch changed")
			}
			if tc.status == 200 {
				var payload struct {
					Model   string               `json:"model"`
					Results []types.RerankResult `json:"results"`
					Usage   map[string]any       `json:"usage"`
				}
				_ = json.Unmarshal(bytes.SplitN(out.Bytes(), []byte("\r\n\r\n"), 2)[1], &payload)
				if payload.Model != "voyage/rerank-3" || payload.Results[0].Index != 0 || payload.Results[0].Document.Text != "PRIVATE-DOCUMENT-A" || payload.Usage["cost_microdollars"] != float64(17) || payload.Usage["total_cost_microdollars"] != float64(17) {
					t.Fatal("public response contract changed")
				}
				settle := calls["/internal/gateway/settle"][0]
				want := float64(tokens)
				if tc.name == "estimated" {
					want = float64(types.EstimateRerankInputTokens("PRIVATE-QUERY", []string{"PRIVATE-DOCUMENT-A", "PRIVATE-DOCUMENT-B"}))
				}
				if settle["actual_input_tokens"] != want || settle["actual_output_tokens"] != float64(0) || settle["usage_estimated"] != (tc.name == "estimated") || settle["route_type"] != "rerank" || settle["streamed"] != false || settle["selected_endpoint"] != "served" || settle["selected_model"] != "served-model" {
					t.Fatalf("settle contract: %v", settle)
				}
				authorize := calls["/internal/gateway/authorize"][0]
				if authorize["estimated_input_tokens"] != float64(14) || authorize["max_output_tokens"] != float64(1) || authorize["stream"] != false || authorize["route_type"] != "rerank" {
					t.Fatalf("authorize contract: %v", authorize)
				}
			}
		})
	}
}

func TestRerankSwitchAndRouteLists(t *testing.T) {
	old := rerankEnabled
	t.Cleanup(func() { rerankEnabled = old })
	for _, setting := range []string{"", "false", "1", "TRUE", "true"} {
		t.Setenv("TR_RERANK_ENABLED", setting)
		configureRerank()
		want := setting == "true"
		if rerankEnabled != want || isBearerCORSRoute("/v1/rerank") != want || billingBackoffRoute("POST", "/v1/rerank") != want || billingBackoffRoute("GET", "/v1/rerank") {
			t.Fatal("feature switch classification changed")
		}
	}
	if err := validateConfidentialHostRequest("POST", "/v1/rerank", []byte(rerankPrivateBody), nil); err == nil || err.Type != "confidential_route_unsupported" {
		t.Fatal("confidential rerank was allowed")
	}
	raw := fmt.Sprintf("POST /v1/rerank HTTP/1.1\r\nHost: api.trustedrouter.com\r\nAuthorization: Bearer valid\r\nConnection: close\r\nContent-Length: %d\r\n\r\n%s", len(rerankPrivateBody), rerankPrivateBody)
	conn := newScriptedConn(raw, nil)
	logs := captureStderr(t, func() {
		serveOne(t.Context(), conn, auth.New([]types.DeviceConfig{{KeyHash: trustedrouter.LookupHash("valid")}}), &fakeStreamingLLM{}, nil, nil, nil, nil)
	})
	if !strings.Contains(conn.writes.String(), "501 Not Implemented") || !strings.Contains(conn.writes.String(), "Access-Control-Allow-Origin: *") || strings.Contains(logs, "PRIVATE-") {
		t.Fatal("enabled route did not reach build check with private logging")
	}
}

func TestRerankEmbeddingSettleDifferential(t *testing.T) {
	captured := make([]map[string]any, 0, 2)
	for _, route := range []string{"embeddings", "rerank"} {
		calls := make(map[string][]map[string]any)
		gateway := rerankMemoryGateway(t, "differential", &calls)
		backend := &rerankBackend{response: &types.RerankResponse{Results: []types.RerankResult{}}}
		var out bytes.Buffer
		if route == "embeddings" {
			serveEmbeddings(t.Context(), &out, backend, []byte(`{"model":"embedding-model","input":"1234567890123456789012345678"}`), gateway, true, "test-key", nil, "idem", requestAttributionHeaders{}, "log")
		} else {
			serveRerank(t.Context(), &out, backend, []byte(`{"model":"rerank-model","query":"1234","documents":["123456789012345678901234"]}`), gateway, true, "test-key", "idem", requestAttributionHeaders{}, "log")
		}
		if !strings.HasPrefix(out.String(), "HTTP/1.1 200 ") {
			t.Fatalf("response %s", out.String())
		}
		body := calls["/internal/gateway/settle"][0]
		delete(body, "request_id")
		delete(body, "elapsed_seconds")
		delete(body, "route_type")
		delete(body, "selected_model")
		captured = append(captured, body)
	}
	if !reflect.DeepEqual(captured[0], captured[1]) {
		t.Fatalf("settlement mismatch: %v versus %v", captured[0], captured[1])
	}
}

func TestRerankHandlerListeners(t *testing.T) {
	calls := make(map[string][]map[string]any)
	plane := httptest.NewServer(rerankControlPlane(t, "success", &calls))
	defer plane.Close()
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req["query"] != "PRIVATE-QUERY" || req["model"] != "rerank-3" {
			t.Error("provider dispatch changed")
		}
		_, _ = io.WriteString(w, `{"results":[{"index":0,"relevance_score":0.8}],"total_tokens":14}`)
	}))
	defer provider.Close()
	backend := &rerankHTTPBackend{url: provider.URL, httpc: provider.Client()}
	var out bytes.Buffer
	logs := captureStderr(t, func() {
		serveRerank(t.Context(), &out, backend, []byte(rerankPrivateBody), trustedrouter.New(plane.URL, "internal", plane.Client()), true, "key", "idem", requestAttributionHeaders{}, "log")
	})
	if !strings.HasPrefix(out.String(), "HTTP/1.1 200 ") || len(calls["/internal/gateway/settle"]) != 1 || strings.Contains(logs, "PRIVATE-") {
		t.Fatal("listener integration failed")
	}
}

type rerankHTTPBackend struct {
	fakeStreamingLLM
	url   string
	httpc *http.Client
}

func (b *rerankHTTPBackend) InvokeRerank(ctx context.Context, req *types.RerankRequest, options ...llm.InvokeOptions) (*types.RerankResponse, error) {
	raw, _ := json.Marshal(map[string]any{"model": options[0].UpstreamModel, "query": req.Query, "documents": req.Documents})
	request, _ := http.NewRequestWithContext(ctx, "POST", b.url, bytes.NewReader(raw))
	resp, err := b.httpc.Do(request)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var wire struct {
		Results []types.RerankResult `json:"results"`
		Tokens  int                  `json:"total_tokens"`
	}
	if err = json.NewDecoder(resp.Body).Decode(&wire); err != nil {
		return nil, err
	}
	return &types.RerankResponse{Results: wire.Results, InputTokens: &wire.Tokens}, nil
}

func TestRerankBodyLimitAndPreflight(t *testing.T) {
	old := rerankEnabled
	rerankEnabled = true
	t.Cleanup(func() { rerankEnabled = old })
	for _, tc := range []struct {
		raw    string
		status int
	}{
		{fmt.Sprintf("POST /v1/rerank HTTP/1.1\r\nHost: api.trustedrouter.com\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", maxRequestBodyBytes+1), 413},
		{"OPTIONS /v1/rerank HTTP/1.1\r\nHost: api.trustedrouter.com\r\nOrigin: https://example.com\r\nConnection: close\r\n\r\n", 204},
		{"GET /v1/rerank HTTP/1.1\r\nHost: api.trustedrouter.com\r\nAuthorization: Bearer valid\r\nConnection: close\r\n\r\n", 404},
	} {
		conn := newScriptedConn(tc.raw, nil)
		logs := captureStderr(t, func() {
			serveOne(t.Context(), conn, auth.New([]types.DeviceConfig{{KeyHash: trustedrouter.LookupHash("valid")}}), &fakeStreamingLLM{}, nil, nil, nil, nil)
		})
		if !strings.HasPrefix(conn.writes.String(), fmt.Sprintf("HTTP/1.1 %d ", tc.status)) || strings.Contains(logs, "PRIVATE-") {
			t.Fatalf("status changed: %s", conn.writes.String())
		}
	}
}

func TestRerankAttributionAndResponseOptions(t *testing.T) {
	for _, bodySession := range []bool{false, true} {
		calls := make(map[string][]map[string]any)
		gateway := rerankMemoryGateway(t, "pinned_voyage", &calls)
		tokens := 14
		backend := &rerankBackend{response: &types.RerankResponse{InputTokens: &tokens, Results: []types.RerankResult{{Index: 1, RelevanceScore: 0.5}, {Index: 0, RelevanceScore: 0.5}}}}
		body := strings.TrimSuffix(rerankPrivateBody, "}") + `,"top_n":1,"return_documents":false,"metadata":{"task":"retrieval"},"trace":{"source":"test"},"provider":{"only":["voyage"],"allow_fallbacks":false}}`
		wantSession := "session"
		if !bodySession {
			body = strings.Replace(body, `"session_id":"session",`, "", 1)
			wantSession = "header-session"
		}
		var out bytes.Buffer
		logs := captureStderr(t, func() {
			serveRerank(t.Context(), &out, backend, []byte(body), gateway, true, "test-key", "idem", requestAttributionHeaders{SessionID: "header-session", App: "app", HTTPReferer: "https://example.com", AppCategories: []string{"search"}}, "log")
		})
		if !strings.HasPrefix(out.String(), "HTTP/1.1 200 ") || strings.Contains(logs, "PRIVATE-") || strings.Contains(out.String(), "PRIVATE-") {
			t.Fatal("response omission or privacy changed")
		}
		for _, path := range []string{"/internal/gateway/authorize", "/internal/gateway/settle"} {
			got := calls[path][0]
			if got["session_id"] != wantSession || got["user"] != "user" || got["app"] != "app" || got["http_referer"] != "https://example.com" || got["metadata"] == nil || got["trace"] == nil {
				t.Fatal("attribution lost")
			}
		}
		provider := calls["/internal/gateway/authorize"][0]["provider"].(map[string]any)
		if provider["allow_fallbacks"] != false || provider["only"].([]any)[0] != "voyage" {
			t.Fatal("provider preferences lost")
		}
		var payload struct {
			Results []types.RerankResult `json:"results"`
		}
		_ = json.Unmarshal(bytes.SplitN(out.Bytes(), []byte("\r\n\r\n"), 2)[1], &payload)
		if len(payload.Results) != 1 || payload.Results[0].Index != 0 || payload.Results[0].Document != nil {
			t.Fatal("top_n or tie order changed")
		}
	}
}
