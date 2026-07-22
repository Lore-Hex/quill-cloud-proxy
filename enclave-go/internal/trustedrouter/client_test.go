package trustedrouter

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestAuthorizeSendsLookupHashAndNoPromptContent(t *testing.T) {
	rawKey := "sk-tr-v1-secret"
	var payload map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/internal/gateway/authorize" {
			t.Fatalf("path = %s", r.URL.Path)
		}
		if r.Header.Get(internalTokenHeader) != "internal" {
			t.Fatalf("missing internal token")
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		if strings.Contains(string(body), rawKey) || strings.Contains(string(body), "secret prompt") {
			t.Fatalf("authorize leaked sensitive material: %s", body)
		}
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		_, _ = io.WriteString(w, `{"data":{"authorization_id":"auth_1","workspace_id":"ws_1","api_key_hash":"key_1","model":"openai/gpt-4o-mini","endpoint_id":"openai/gpt-4o-mini@openai/prepaid","provider":"openai","usage_type":"Credits","limit_usage_type":"Credits","additional_cost_reservation_microdollars":300000,"route_candidates":[]}}`)
	}))
	defer server.Close()

	client := New(server.URL, "internal", server.Client())
	maxTokens := 7
	auth, err := client.Authorize(t.Context(), rawKey, &qtypes.OpenAIChatRequest{
		Model:                                 "openai/gpt-4o-mini",
		MaxTokens:                             &maxTokens,
		Messages:                              []qtypes.OpenAIChatMessage{{Role: "user", Content: "secret prompt"}},
		IdempotencyKey:                        "idem-123",
		AdditionalCostReservationMicrodollars: 300_000,
	})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if auth.AuthorizationID != "auth_1" {
		t.Fatalf("authorization id = %q", auth.AuthorizationID)
	}
	if payload["api_key_lookup_hash"] != lookupHash(rawKey) {
		t.Fatalf("lookup hash = %v", payload["api_key_lookup_hash"])
	}
	if _, ok := payload["api_key_hash"]; ok {
		t.Fatalf("api_key_hash should not be sent by gateway: %#v", payload)
	}
	if payload["max_output_tokens"] != float64(maxTokens) {
		t.Fatalf("max_output_tokens = %v", payload["max_output_tokens"])
	}
	if payload["idempotency_key"] != "idem-123" {
		t.Fatalf("idempotency_key = %v", payload["idempotency_key"])
	}
	if payload["additional_cost_reservation_microdollars"] != float64(300_000) {
		t.Fatalf("additional cost reservation = %v", payload["additional_cost_reservation_microdollars"])
	}
}

func TestAuthorizePreservesFailClosedMinPrivacy(t *testing.T) {
	var payload map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		_, _ = io.WriteString(w, `{"data":{"authorization_id":"auth_private","workspace_id":"ws_1","api_key_hash":"key_1","model":"z-ai/glm-5.2","endpoint_id":"z-ai/glm-5.2@tinfoil/prepaid","provider":"tinfoil","usage_type":"Credits","limit_usage_type":"Credits","route_candidates":[]}}`)
	}))
	defer server.Close()

	var req qtypes.OpenAIChatRequest
	if err := json.Unmarshal([]byte(`{
		"model":"trustedrouter/monitor",
		"messages":[{"role":"user","content":"private prompt"}],
		"provider":{"min_privacy":"confidential"}
	}`), &req); err != nil {
		t.Fatalf("decode inbound request: %v", err)
	}
	client := New(server.URL, "internal", server.Client())
	if _, err := client.Authorize(t.Context(), "sk-test", &req); err != nil {
		t.Fatalf("Authorize: %v", err)
	}

	provider, ok := payload["provider"].(map[string]any)
	if !ok {
		t.Fatalf("provider routing = %#v", payload["provider"])
	}
	if got := provider["min_privacy"]; got != "confidential" {
		t.Fatalf("provider.min_privacy = %#v, want confidential", got)
	}
}

func TestAuthorizeRejectsControlPlaneWithoutHostedToolBilling(t *testing.T) {
	refunds := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/internal/gateway/authorize":
			_, _ = io.WriteString(w, `{"data":{"authorization_id":"auth_old","workspace_id":"ws_1","api_key_hash":"key_1","model":"test/model","endpoint_id":"test/model@test/prepaid","provider":"test","usage_type":"Credits","limit_usage_type":"Credits","route_candidates":[]}}`)
		case "/internal/gateway/refund":
			refunds++
			_, _ = io.WriteString(w, `{"data":{"refunded":true}}`)
		default:
			t.Fatalf("path = %s", r.URL.Path)
		}
	}))
	defer server.Close()

	client := New(server.URL, "internal", server.Client())
	_, err := client.AuthorizeWithRoute(t.Context(), "sk-test", &qtypes.OpenAIChatRequest{
		Model:                                 "test/model",
		Messages:                              []qtypes.OpenAIChatMessage{{Role: "user", Content: "search"}},
		AdditionalCostReservationMicrodollars: 100_000,
	}, "responses.web_search.planner")
	var controlErr *ControlPlaneError
	if !errors.As(err, &controlErr) || controlErr.Type != "hosted_tool_billing_unavailable" {
		t.Fatalf("error = %#v", err)
	}
	if refunds != 1 {
		t.Fatalf("refunds = %d, want 1", refunds)
	}
}

func TestAuthorizeAndSettleCarryAttributionWithoutMutableSettleTags(t *testing.T) {
	var authorizePayload map[string]any
	var settlePayload map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		switch r.URL.Path {
		case "/internal/gateway/authorize":
			if err := json.Unmarshal(body, &authorizePayload); err != nil {
				t.Fatalf("decode authorize: %v", err)
			}
			_, _ = io.WriteString(w, `{"data":{"authorization_id":"auth_1","workspace_id":"ws_1","api_key_hash":"key_1","model":"openai/gpt-4o-mini","endpoint_id":"openai/gpt-4o-mini@openai/prepaid","provider":"openai","usage_type":"Credits","limit_usage_type":"Credits","request_metadata_version":1,"tags":{"environment":"production","team":"legal"},"route_candidates":[]}}`)
		case "/internal/gateway/settle":
			if err := json.Unmarshal(body, &settlePayload); err != nil {
				t.Fatalf("decode settle: %v", err)
			}
			_, _ = io.WriteString(w, `{"data":{"generation_id":"gen_1","cost_microdollars":1}}`)
		default:
			t.Fatalf("unexpected path = %s", r.URL.Path)
		}
	}))
	defer server.Close()

	client := New(server.URL, "internal", server.Client())
	req := &qtypes.OpenAIChatRequest{
		Model:         "openai/gpt-4o-mini",
		Messages:      []qtypes.OpenAIChatMessage{{Role: "user", Content: "private prompt"}},
		User:          "user-123",
		SessionID:     "matter-456",
		Trace:         map[string]any{"source": "eval"},
		Tags:          qtypes.NewRequestTags(qtypes.TagMap{"team": "legal"}),
		App:           "Contract Review",
		HTTPReferer:   "https://legal.example/app",
		AppCategories: []string{"legal", "productivity"},
	}
	auth, err := client.Authorize(t.Context(), "sk-test", req)
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if req.Tags.Values()["environment"] != "production" {
		t.Fatalf("effective request tags = %#v", req.Tags)
	}
	if authorizePayload["user"] != "user-123" || authorizePayload["session_id"] != "matter-456" {
		t.Fatalf("authorize attribution = %#v", authorizePayload)
	}
	if authorizePayload["http_referer"] != "https://legal.example/app" || authorizePayload["app"] != "Contract Review" {
		t.Fatalf("authorize app attribution = %#v", authorizePayload)
	}
	if strings.Contains(string(mustJSON(t, authorizePayload)), "private prompt") {
		t.Fatalf("authorize payload leaked prompt: %#v", authorizePayload)
	}

	_, err = client.Settle(t.Context(), auth, Usage{
		RequestID:                  "req-1",
		InputTokens:                10,
		OutputTokens:               2,
		ElapsedSeconds:             0.1,
		User:                       req.User,
		SessionID:                  req.SessionID,
		Trace:                      req.Trace,
		Metadata:                   req.Metadata,
		App:                        req.App,
		HTTPReferer:                req.HTTPReferer,
		AppCategories:              req.AppCategories,
		AdditionalCostMicrodollars: 7_000,
	})
	if err != nil {
		t.Fatalf("Settle: %v", err)
	}
	if _, ok := settlePayload["tags"]; ok {
		t.Fatalf("settlement must use authorization-frozen tags server-side: %#v", settlePayload)
	}
	if settlePayload["app"] != "Contract Review" || settlePayload["http_referer"] != "https://legal.example/app" {
		t.Fatalf("settle attribution = %#v", settlePayload)
	}
	if settlePayload["additional_cost_microdollars"] != float64(7_000) {
		t.Fatalf("settle additional cost = %#v", settlePayload)
	}
}

func TestSettleMapsTrustedSyntheticAppSentinelToDefault(t *testing.T) {
	tests := []struct {
		name string
		app  string
		want string
	}{
		{name: "sentinel exact", app: "TrustedRouter Synthetic", want: "attested-gateway"},
		{name: "sentinel mixed case", app: "trustedrouter synthetic", want: "attested-gateway"},
		{name: "client app", app: "Customer Portal", want: "Customer Portal"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var payload map[string]any
			client := New("https://control.example", "internal", &http.Client{
				Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
					if r.URL.Path != "/internal/gateway/settle" {
						t.Fatalf("path = %s", r.URL.Path)
					}
					body, err := io.ReadAll(r.Body)
					if err != nil {
						t.Fatalf("read body: %v", err)
					}
					if err := json.Unmarshal(body, &payload); err != nil {
						t.Fatalf("decode body: %v", err)
					}
					return &http.Response{
						StatusCode: http.StatusOK,
						Header:     make(http.Header),
						Body:       io.NopCloser(strings.NewReader(`{"data":{"generation_id":"gen_1","cost_microdollars":1}}`)),
					}, nil
				}),
			})
			_, err := client.Settle(t.Context(), &Authorization{
				AuthorizationID: "auth_1",
				Model:           "openai/gpt-4o-mini",
				EndpointID:      "endpoint_1",
			}, Usage{
				RequestID:      "req_1",
				InputTokens:    1,
				OutputTokens:   1,
				ElapsedSeconds: 0.001,
				App:            test.app,
			})
			if err != nil {
				t.Fatalf("Settle: %v", err)
			}
			if got := payload["app"]; got != test.want {
				t.Fatalf("app = %v, want %q; payload=%#v", got, test.want, payload)
			}
		})
	}
}

func TestAuthorizeRefundsAndFailsWhenControlPlaneLacksTagCapability(t *testing.T) {
	refunds := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/internal/gateway/authorize":
			_, _ = io.WriteString(w, `{"data":{"authorization_id":"auth_old","workspace_id":"ws_1","api_key_hash":"key_1","model":"openai/gpt-4o-mini","endpoint_id":"endpoint_1","provider":"openai","usage_type":"Credits","limit_usage_type":"Credits","route_candidates":[]}}`)
		case "/internal/gateway/refund":
			refunds++
			_, _ = io.WriteString(w, `{"data":{"refunded":true}}`)
		default:
			t.Fatalf("unexpected path = %s", r.URL.Path)
		}
	}))
	defer server.Close()

	client := New(server.URL, "internal", server.Client())
	req := &qtypes.OpenAIChatRequest{
		Model: "openai/gpt-4o-mini",
		Tags:  qtypes.NewRequestTags(qtypes.TagMap{"team": "legal"}),
	}
	_, err := client.Authorize(t.Context(), "sk-test", req)
	var controlErr *ControlPlaneError
	if !errors.As(err, &controlErr) || controlErr.StatusCode != 503 || controlErr.Type != "request_metadata_unavailable" {
		t.Fatalf("err = %#v, want request_metadata_unavailable 503", err)
	}
	if refunds != 1 {
		t.Fatalf("refunds = %d, want 1", refunds)
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return body
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestValidateKeySendsLookupHashAndRouteOnly(t *testing.T) {
	rawKey := "test-user-bearer"
	var payload map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/internal/gateway/validate" {
			t.Fatalf("path = %s", r.URL.Path)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		if strings.Contains(string(body), rawKey) || strings.Contains(string(body), "private input") {
			t.Fatalf("validate leaked sensitive material: %s", body)
		}
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		_, _ = io.WriteString(w, `{"data":{"workspace_id":"ws_1","api_key_hash":"key_1","route_type":"responses.input_tokens"}}`)
	}))
	defer server.Close()

	client := New(server.URL, "internal", server.Client())
	if err := client.ValidateKey(t.Context(), rawKey, "responses.input_tokens"); err != nil {
		t.Fatalf("ValidateKey: %v", err)
	}
	if payload["api_key_lookup_hash"] != lookupHash(rawKey) {
		t.Fatalf("lookup hash = %v", payload["api_key_lookup_hash"])
	}
	if payload["route_type"] != "responses.input_tokens" {
		t.Fatalf("route_type = %v", payload["route_type"])
	}
}

func TestAuthorizeReturnsParsedControlPlaneError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"error":{"message":"Routing filters cannot contain router name 'openrouter'","type":"bad_request"}}`)
	}))
	defer server.Close()

	client := New(server.URL, "internal", server.Client())
	_, err := client.Authorize(t.Context(), "sk-test", &qtypes.OpenAIChatRequest{
		Model:    "trustedrouter/zdr",
		Messages: []qtypes.OpenAIChatMessage{{Role: "user", Content: "private input"}},
	})
	if err == nil {
		t.Fatal("expected control-plane error")
	}
	var controlErr *ControlPlaneError
	if !errors.As(err, &controlErr) {
		t.Fatalf("error type = %T, want ControlPlaneError", err)
	}
	if controlErr.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d", controlErr.StatusCode)
	}
	if controlErr.Message != "Routing filters cannot contain router name 'openrouter'" {
		t.Fatalf("message = %q", controlErr.Message)
	}
}

func TestAuthorizeCapturesRetryAfterHeader(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "3600")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = io.WriteString(w, `{"error":{"message":"API key daily spend limit exceeded","type":"key_window_limit_exceeded"}}`)
	}))
	defer server.Close()

	client := New(server.URL, "internal", server.Client())
	_, err := client.Authorize(t.Context(), "sk-test", &qtypes.OpenAIChatRequest{
		Model:    "trustedrouter/cheap",
		Messages: []qtypes.OpenAIChatMessage{{Role: "user", Content: "hi"}},
	})
	var controlErr *ControlPlaneError
	if !errors.As(err, &controlErr) {
		t.Fatalf("error type = %T, want ControlPlaneError", err)
	}
	if controlErr.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status = %d", controlErr.StatusCode)
	}
	if controlErr.RetryAfter != "3600" {
		t.Fatalf("RetryAfter = %q, want 3600", controlErr.RetryAfter)
	}
}

func TestKeyInfoUsesLookupHashNotRawBearer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The RAW BEARER MUST NOT LEAVE THE ENCLAVE: KeyInfo POSTs the lookup
		// hash + internal token to /internal/gateway/key, never GET /v1/key
		// with the bearer.
		if r.Method != http.MethodPost || r.URL.Path != "/internal/gateway/key" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "" {
			t.Fatalf("raw bearer leaked in Authorization header: %q", r.Header.Get("Authorization"))
		}
		if r.Header.Get(internalTokenHeader) != "internal" {
			t.Fatalf("missing internal token, got %q", r.Header.Get(internalTokenHeader))
		}
		var body struct {
			LookupHash string `json:"api_key_lookup_hash"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.LookupHash != lookupHash("sk-holder") {
			t.Fatalf("lookup hash = %q, want %q", body.LookupHash, lookupHash("sk-holder"))
		}
		if bytes.Contains([]byte(body.LookupHash), []byte("sk-holder")) {
			t.Fatal("raw key present in payload")
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"data":{"limit_daily":0.5}}`)
	}))
	defer server.Close()

	client := New(server.URL, "internal", server.Client())
	status, body, err := client.KeyInfo(t.Context(), "sk-holder")
	if err != nil {
		t.Fatal(err)
	}
	if status != http.StatusOK {
		t.Fatalf("status = %d", status)
	}
	if string(body) != `{"data":{"limit_daily":0.5}}` {
		t.Fatalf("body = %s", body)
	}
}

func TestSanitizeRetryAfter(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"3600", "3600"},
		{"  120 ", "120"},
		{"", ""},
		{"60\r\nX-Evil: 1", ""},               // CRLF injection dropped
		{"Wed, 21 Oct 2026 07:28:00 GMT", ""}, // HTTP-date we never emit
		{"abc", ""},
	} {
		if got := sanitizeRetryAfter(tc.in); got != tc.want {
			t.Fatalf("sanitizeRetryAfter(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
