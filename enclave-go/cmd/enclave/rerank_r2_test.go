package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

type rerankStatusError int

func (e rerankStatusError) Error() string { return "PRIVATE-PROVIDER-ERROR" }
func (e rerankStatusError) UpstreamResponse() (int, string) {
	return int(e), "PRIVATE-PROVIDER-ERROR"
}

func TestRerankRefundDetails(t *testing.T) { testRerankRefundDetails(t, false) }

func TestRerankRefundDetailsListeners(t *testing.T) { testRerankRefundDetails(t, true) }

func testRerankRefundDetails(t *testing.T, listener bool) {
	for _, tc := range []struct {
		name, mode, class string
		err               error
		status, public    int
		invoke, settle    int
	}{
		{"http_429", "", "provider_error", fmt.Errorf("wrapped: %w", rerankStatusError(429)), 429, 502, 1, 0},
		{"http_503", "", "provider_error", rerankStatusError(503), 503, 502, 1, 0},
		{"input_limit", "", "provider_error", fmt.Errorf("wrapped: %w", llm.ErrRerankInputLimit), 413, 400, 1, 0},
		{"invalid_response", "", "provider_error", errors.New("PRIVATE-PROVIDER-ERROR"), 502, 502, 1, 0},
		{"nil_response", "", "provider_error", nil, 502, 502, 1, 0},
		{"invalid_result", "", "provider_error", nil, 502, 502, 1, 0},
		{"negative_tokens", "", "provider_error", nil, 502, 502, 1, 0},
		{"negative_search", "", "provider_error", nil, 502, 502, 1, 0},
		{"unsupported_provider", "", "provider_error", llm.ErrRerankUnsupported, 501, 501, 1, 0},
		{"unsupported_route", "unsupported_candidate", "rerank_route_unsupported", nil, 501, 501, 0, 0},
		{"byok_authorization", "byok_answer", "rerank_route_unsupported", nil, 400, 400, 0, 0},
		{"byok_candidate", "byok_candidate", "rerank_route_unsupported", nil, 400, 400, 0, 0},
		{"settlement", "settle", "settlement_failed", nil, 502, 502, 1, 1},
		{"refund_rejected", "refund", "provider_error", rerankStatusError(429), 429, 502, 1, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := make(map[string][]map[string]any)
			var gateway *trustedrouter.Client
			if listener {
				server := httptest.NewServer(rerankControlPlane(t, tc.mode, &calls))
				defer server.Close()
				gateway = trustedrouter.New(server.URL, "internal", server.Client())
			} else {
				gateway = rerankMemoryGateway(t, tc.mode, &calls)
			}
			negative := -1
			backend := &rerankBackend{err: tc.err, response: &types.RerankResponse{Results: []types.RerankResult{{Index: 0, RelevanceScore: 0.5}}}}
			switch tc.name {
			case "nil_response":
				backend.response = nil
			case "invalid_result":
				backend.response.Results[0].Index = 2
			case "negative_tokens":
				backend.response.InputTokens = &negative
			case "negative_search":
				backend.response.SearchUnits = &negative
			}
			var out bytes.Buffer
			logs := captureStderr(t, func() {
				serveRerank(t.Context(), &out, backend, []byte(rerankPrivateBody), gateway, true, "key", "idem", requestAttributionHeaders{}, "log-rerank-r2")
			})
			if !strings.HasPrefix(out.String(), fmt.Sprintf("HTTP/1.1 %d ", tc.public)) {
				t.Fatalf("response: %s", &out)
			}
			refunds := calls["/internal/gateway/refund"]
			if len(refunds) != 1 || len(calls["/internal/gateway/authorize"]) != 1 || backend.calls != tc.invoke || len(calls["/internal/gateway/settle"]) != tc.settle {
				t.Fatalf("terminal counts: calls=%v invoke=%d", calls, backend.calls)
			}
			refund := refunds[0]
			if refund["authorization_id"] != "auth-rerank" || refund["error_status"] != float64(tc.status) || refund["error_type"] != tc.class {
				t.Fatalf("refund: %v; want auth-rerank, %d, %s", refund, tc.status, tc.class)
			}
			// serveRerank has returned, so its deferred guard has also run.
			// Even a rejected explicit refund records an attempt and wins over it.
			if strings.Contains(logs, "enclave.hold_closed_at_exit") {
				t.Fatalf("deferred guard sent a second terminal: %s", logs)
			}
			if tc.class == "provider_error" && !strings.Contains(logs, fmt.Sprintf("enclave.rerank_failed request_log_id=\"log-rerank-r2\" upstream_status=%d documents=2 error_class=provider_error", tc.status)) {
				t.Fatalf("provider failure log: %s", logs)
			}
			if tc.class == "settlement_failed" && !strings.Contains(logs, `enclave.rerank_settle_failed request_log_id="log-rerank-r2" error_class=settlement`) {
				t.Fatalf("settlement failure log: %s", logs)
			}
			if tc.mode == "refund" && !strings.Contains(logs, "enclave.refund_failed") {
				t.Fatalf("missing refund failure log: %s", logs)
			}
			if strings.Contains(logs+out.String(), "PRIVATE-") {
				t.Fatal("private text escaped")
			}
		})
	}
}

func TestRerankAuthorizedOptionGuards(t *testing.T) {
	for _, scope := range []string{"authorization", "candidate"} {
		for _, field := range []string{"usage_type", "byok_secret_ref", "byok_encrypted_secret", "byok_cache_key", "byok_provider"} {
			t.Run(scope+"/"+field, func(t *testing.T) {
				route := map[string]any{"model": "m", "upstream_model": "u", "provider": "voyage", "endpoint_id": "e", "usage_type": "Credits"}
				var a trustedrouter.Authorization
				raw, _ := json.Marshal(route)
				if err := json.Unmarshal(raw, &a); err != nil {
					t.Fatal(err)
				}
				value := any("customer")
				if field == "usage_type" {
					value = "bYoK"
				}
				if field == "byok_encrypted_secret" {
					value = map[string]any{}
				}
				route[field] = value
				raw, _ = json.Marshal(route)
				if scope == "authorization" {
					if err := json.Unmarshal(raw, &a); err != nil {
						t.Fatal(err)
					}
				} else {
					a.RouteCandidates = make([]trustedrouter.RouteCandidate, 1)
					if err := json.Unmarshal(raw, &a.RouteCandidates[0]); err != nil {
						t.Fatal(err)
					}
				}
				if option, err := rerankAuthorizedOption(&a); err == nil || err.Error() != "rerank requires a prepaid Voyage or Cohere route" || option != (llm.InvokeOptions{}) {
					t.Fatalf("option=%+v error=%v", option, err)
				}
			})
		}
	}
	if _, err := rerankAuthorizedOption(nil); err == nil {
		t.Fatal("nil authorization accepted")
	}
	for _, field := range []string{"Model", "UpstreamModel", "EndpointID", "Provider"} {
		t.Run("missing/"+field, func(t *testing.T) {
			a := trustedrouter.Authorization{Model: "m", UpstreamModel: "u", EndpointID: "e", Provider: "voyage", UsageType: "Credits"}
			reflect.ValueOf(&a).Elem().FieldByName(field).SetString("")
			if _, err := rerankAuthorizedOption(&a); err == nil {
				t.Fatal("incomplete route accepted")
			}
		})
	}
}

func TestRerankAuthorizedOptionInheritance(t *testing.T) {
	want := llm.InvokeOptions{Model: "candidate-m", UpstreamModel: "candidate-u", EndpointID: "candidate-e", Provider: "cohere", UsageType: "Credits"}
	for _, field := range []string{"none", "Model", "UpstreamModel", "EndpointID", "Provider", "UsageType", "no_candidates"} {
		t.Run(field, func(t *testing.T) {
			a := trustedrouter.Authorization{Model: "parent-m", UpstreamModel: "parent-u", EndpointID: "parent-e", Provider: "voyage", UsageType: "Credits", RouteCandidates: []trustedrouter.RouteCandidate{{Model: want.Model, UpstreamModel: want.UpstreamModel, EndpointID: want.EndpointID, Provider: want.Provider, UsageType: want.UsageType}, {Provider: "unused"}}}
			expected := want
			if field == "no_candidates" {
				a.RouteCandidates = nil
				expected = llm.InvokeOptions{Model: a.Model, UpstreamModel: a.UpstreamModel, EndpointID: a.EndpointID, Provider: a.Provider, UsageType: a.UsageType}
			} else if field != "none" {
				reflect.ValueOf(&a.RouteCandidates[0]).Elem().FieldByName(field).SetString("")
				reflect.ValueOf(&expected).Elem().FieldByName(field).SetString(reflect.ValueOf(a).FieldByName(field).String())
			}
			got, err := rerankAuthorizedOption(&a)
			if err != nil || !reflect.DeepEqual(got, expected) {
				t.Fatalf("got %+v, %v; want %+v", got, err, expected)
			}
		})
	}
}

func TestRerankSearchUnitsAndRequestModes(t *testing.T) {
	for _, field := range []string{"usage", "usage_type", "billing"} {
		for _, mode := range []string{"", "Credits", "pRePaId", "BYOK", "other"} {
			t.Run(field+"/"+mode, func(t *testing.T) {
				calls := make(map[string][]map[string]any)
				gateway := rerankMemoryGateway(t, "", &calls)
				units := 3
				backend := &rerankBackend{response: &types.RerankResponse{Results: []types.RerankResult{}, SearchUnits: &units}}
				body := strings.TrimSuffix(rerankPrivateBody, "}") + fmt.Sprintf(`,"provider":{%q:%q}}`, field, mode)
				var out bytes.Buffer
				serveRerank(t.Context(), &out, backend, []byte(body), gateway, true, "key", "idem", requestAttributionHeaders{}, "log")
				if mode == "BYOK" || mode == "other" {
					if len(calls) != 0 || backend.calls != 0 || !strings.HasPrefix(out.String(), "HTTP/1.1 400 ") {
						t.Fatalf("non-prepaid dispatch: %s", &out)
					}
					return
				}
				if !strings.HasPrefix(out.String(), "HTTP/1.1 200 ") || !strings.Contains(out.String(), `"search_units":3`) || len(calls["/internal/gateway/settle"]) != 1 || len(calls["/internal/gateway/refund"]) != 0 {
					t.Fatalf("prepaid response: %s", &out)
				}
			})
		}
	}
}

func TestRerankValidationErrorDetails(t *testing.T) {
	for _, tc := range []struct{ name, body, code, param string }{
		{"json", `{`, "bad_request", ""},
		{"query", strings.Replace(rerankPrivateBody, `"PRIVATE-QUERY"`, `null`, 1), "bad_request", "query"},
		{"tags", strings.TrimSuffix(rerankPrivateBody, "}") + `,"tags":{"aws:reserved":"value"}}`, "invalid_tags", "tags"},
		{"metadata", strings.Replace(rerankPrivateBody, `"session"`, `"`+strings.Repeat("s", 257)+`"`, 1), "invalid_request_metadata", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("TR_REQUEST_METADATA_ENFORCEMENT", "enforce")
			calls := make(map[string][]map[string]any)
			backend := &rerankBackend{}
			var out bytes.Buffer
			serveRerank(t.Context(), &out, backend, []byte(tc.body), rerankMemoryGateway(t, "", &calls), true, "key", "idem", requestAttributionHeaders{}, "log")
			var payload struct {
				Error struct {
					Code  string `json:"code"`
					Param string `json:"param"`
				} `json:"error"`
			}
			parts := bytes.SplitN(out.Bytes(), []byte("\r\n\r\n"), 2)
			if len(parts) != 2 {
				t.Fatalf("response=%s", &out)
			}
			if err := json.Unmarshal(parts[1], &payload); err != nil {
				t.Fatal(err)
			}
			if payload.Error.Code != tc.code || payload.Error.Param != tc.param || len(calls) != 0 || backend.calls != 0 {
				t.Fatalf("response=%s calls=%v", &out, calls)
			}
		})
	}
}

func TestRerankMetadataObserveLog(t *testing.T) {
	t.Setenv("TR_REQUEST_METADATA_ENFORCEMENT", "observe")
	calls := make(map[string][]map[string]any)
	backend := &rerankBackend{response: &types.RerankResponse{Results: []types.RerankResult{}}}
	body := strings.Replace(rerankPrivateBody, `"session"`, `"`+strings.Repeat("s", 257)+`"`, 1)
	var out bytes.Buffer
	logs := captureStderr(t, func() {
		serveRerank(t.Context(), &out, backend, []byte(body), rerankMemoryGateway(t, "", &calls), true, "key", "idem", requestAttributionHeaders{}, "log-observe")
	})
	if !strings.HasPrefix(out.String(), "HTTP/1.1 200 ") || !strings.Contains(logs, `enclave.request_metadata_dropped request_log_id="log-observe" kind="attribution" enforcement="observe"`) {
		t.Fatalf("response=%s logs=%s", &out, logs)
	}
	for _, path := range []string{"/internal/gateway/authorize", "/internal/gateway/settle"} {
		if len(calls[path]) != 1 {
			t.Fatalf("calls=%v", calls)
		}
		if session, _ := calls[path][0]["session_id"].(string); session != "" {
			t.Fatal("invalid metadata retained")
		}
	}
}

func TestRerankAuthorizationFailureDetails(t *testing.T) {
	for _, status := range []int{401, 402, 429} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			calls := 0
			gateway := trustedrouter.New("https://trustedrouter.com", "internal", &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.URL.Path != "/internal/gateway/authorize" {
					t.Fatalf("unexpected terminal: %s", r.URL.Path)
				}
				return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"error":{"type":"invalid_request","message":"authorization refused"}}`))}, nil
			})})
			backend := &rerankBackend{}
			var out bytes.Buffer
			serveRerank(t.Context(), &out, backend, []byte(rerankPrivateBody), gateway, true, "key", "idem", requestAttributionHeaders{}, "log")
			if !strings.HasPrefix(out.String(), fmt.Sprintf("HTTP/1.1 %d ", status)) || !strings.Contains(out.String(), "authorization refused") || calls != 1 || backend.calls != 0 {
				t.Fatalf("response=%s calls=%d invoke=%d", &out, calls, backend.calls)
			}
		})
	}
}
