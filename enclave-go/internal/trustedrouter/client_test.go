package trustedrouter

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestPublicModelsCachesCatalogWithoutCredentials(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != http.MethodGet || r.URL.Path != "/v1/models" {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "" {
			t.Fatalf("authorization leaked to public catalog: %q", got)
		}
		if got := r.Header.Get(internalTokenHeader); got != "" {
			t.Fatalf("internal token leaked to public catalog: %q", got)
		}
		_, _ = io.WriteString(w, `{"data":[{"id":"trustedrouter/auto"}]}`)
	}))
	defer server.Close()

	client := New(server.URL, "internal-secret", server.Client())
	first, err := client.PublicModels(t.Context())
	if err != nil {
		t.Fatalf("PublicModels first: %v", err)
	}
	first[0] = 'x'
	second, err := client.PublicModels(t.Context())
	if err != nil {
		t.Fatalf("PublicModels second: %v", err)
	}
	if calls != 1 {
		t.Fatalf("catalog calls = %d, want 1", calls)
	}
	if !strings.Contains(string(second), "trustedrouter/auto") {
		t.Fatalf("cached catalog was mutated: %s", second)
	}
}

func TestPublicModelsUsesBoundedStaleCatalogOnRefreshFailure(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		if calls == 1 {
			_, _ = io.WriteString(w, `{"data":[{"id":"trustedrouter/zdr"}]}`)
			return
		}
		http.Error(w, "temporary failure", http.StatusBadGateway)
	}))
	defer server.Close()

	client := New(server.URL, "internal", server.Client())
	want, err := client.PublicModels(t.Context())
	if err != nil {
		t.Fatalf("PublicModels prime: %v", err)
	}
	client.modelsFetched = time.Now().Add(-publicModelsFreshTTL - time.Second)
	got, err := client.PublicModels(t.Context())
	if err != nil {
		t.Fatalf("PublicModels stale fallback: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("stale body = %s, want %s", got, want)
	}
	if calls != 2 {
		t.Fatalf("catalog calls = %d, want 2", calls)
	}
}

func TestPublicModelsRejectsMalformedCatalog(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"data":[]}`)
	}))
	defer server.Close()

	client := New(server.URL, "internal", server.Client())
	if _, err := client.PublicModels(t.Context()); err == nil || !strings.Contains(err.Error(), "invalid /models response") {
		t.Fatalf("PublicModels error = %v", err)
	}
}

func TestPublicModelsFallsThroughReadOnlyControlPlanes(t *testing.T) {
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer primary.Close()
	secondary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"data":[{"id":"trustedrouter/e2e"}]}`)
	}))
	defer secondary.Close()

	client := New(primary.URL+","+secondary.URL, "internal", secondary.Client())
	body, err := client.PublicModels(t.Context())
	if err != nil {
		t.Fatalf("PublicModels: %v", err)
	}
	if !strings.Contains(string(body), "trustedrouter/e2e") {
		t.Fatalf("catalog = %s", body)
	}
}

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

func TestGatewayRequestIDForwarding(t *testing.T) {
	tests := []struct {
		name string
		id   string
		want bool
	}{
		{name: "valid", id: "rlog_0123456789abcdef0123456789abcdef", want: true},
		{name: "missing"},
		{name: "malformed", id: "rlog_0123456789abcdef0123456789abcdeg"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			payloads := make(map[string]map[string]any)
			client := New("https://trustedrouter.com", "internal", &http.Client{
				Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
					var payload map[string]any
					if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
						t.Fatalf("decode %s body: %v", r.URL.Path, err)
					}
					payloads[r.URL.Path] = payload
					var responseBody string
					switch r.URL.Path {
					case "/internal/gateway/authorize":
						responseBody = `{"data":{"authorization_id":"auth_1","workspace_id":"ws_1","api_key_hash":"key_1","model":"openai/gpt-4o-mini","endpoint_id":"openai/gpt-4o-mini@openai/prepaid","provider":"openai","usage_type":"Credits","limit_usage_type":"Credits","route_candidates":[]}}`
					case "/internal/gateway/settle":
						responseBody = `{"data":{"generation_id":"gen_1","cost_microdollars":1}}`
					case "/internal/gateway/refund":
						responseBody = `{"data":{"refunded":true}}`
					default:
						t.Fatalf("unexpected path %s", r.URL.Path)
					}
					return &http.Response{
						StatusCode: http.StatusOK,
						Header:     make(http.Header),
						Body:       io.NopCloser(strings.NewReader(responseBody)),
					}, nil
				}),
			})
			ctx := context.Context(t.Context())
			if test.id != "" {
				ctx = WithRequestLogID(ctx, test.id)
			}
			auth, err := client.Authorize(ctx, "sk-test", &qtypes.OpenAIChatRequest{
				Model:    "openai/gpt-4o-mini",
				Messages: []qtypes.OpenAIChatMessage{{Role: "user", Content: "hello"}},
			})
			if err != nil {
				t.Fatalf("Authorize: %v", err)
			}
			if _, err := client.Settle(ctx, auth, Usage{
				RequestID:      "chatcmpl_1",
				InputTokens:    1,
				OutputTokens:   1,
				ElapsedSeconds: 0.01,
			}); err != nil {
				t.Fatalf("Settle: %v", err)
			}
			if _, err := client.RefundDetailedAttributed(
				ctx, auth, http.StatusBadGateway, "provider_error", 0.01, nil,
				RefundAttribution{User: "user-1"},
			); err != nil {
				t.Fatalf("RefundDetailedAttributed: %v", err)
			}

			if _, ok := payloads["/internal/gateway/authorize"]["gateway_request_id"]; ok {
				t.Fatalf("authorize body contains gateway_request_id: %#v", payloads["/internal/gateway/authorize"])
			}
			for _, path := range []string{"/internal/gateway/settle", "/internal/gateway/refund"} {
				got, ok := payloads[path]["gateway_request_id"]
				if test.want {
					if !ok || got != test.id {
						t.Fatalf("%s gateway_request_id = %#v, present=%v, want %q", path, got, ok, test.id)
					}
				} else if ok {
					t.Fatalf("%s gateway_request_id = %#v, want absent", path, got)
				}
			}
		})
	}
}

func TestClientContextForwardedOnlyOnSettleAndRefund(t *testing.T) {
	attempt := 0
	stream := false
	clientContext := &qtypes.ClientContext{
		V:          1,
		Source:     "tr",
		SDK:        "tr-py",
		SDKVersion: "0.6.0",
		Lang:       "python",
		Runtime:    "cpython/3.12.1",
		OS:         "macos",
		Arch:       "arm64",
		TimeoutMS:  120000,
		Attempt:    &attempt,
		Stream:     &stream,
	}

	type captured struct {
		authorize []byte
		settle    map[string]any
		refund    map[string]any
	}
	run := func(context *qtypes.ClientContext) captured {
		t.Helper()
		var got captured
		client := New("https://trustedrouter.com", "internal", &http.Client{
			Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Fatalf("read %s body: %v", r.URL.Path, err)
				}
				responseBody := ""
				switch r.URL.Path {
				case "/internal/gateway/authorize":
					got.authorize = append([]byte(nil), body...)
					responseBody = `{"data":{"authorization_id":"auth_1","workspace_id":"ws_1","api_key_hash":"key_1","model":"openai/gpt-4o-mini","endpoint_id":"openai/gpt-4o-mini@openai/prepaid","provider":"openai","usage_type":"Credits","limit_usage_type":"Credits","route_candidates":[]}}`
				case "/internal/gateway/settle":
					if err := json.Unmarshal(body, &got.settle); err != nil {
						t.Fatalf("decode settle: %v", err)
					}
					responseBody = `{"data":{"generation_id":"gen_1","cost_microdollars":1}}`
				case "/internal/gateway/refund":
					if err := json.Unmarshal(body, &got.refund); err != nil {
						t.Fatalf("decode refund: %v", err)
					}
					responseBody = `{"data":{"refunded":true}}`
				default:
					t.Fatalf("unexpected path %s", r.URL.Path)
				}
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader(responseBody)),
				}, nil
			}),
		})
		ctx := WithClientContext(t.Context(), context)
		req := &qtypes.OpenAIChatRequest{
			Model:          "openai/gpt-4o-mini",
			Messages:       []qtypes.OpenAIChatMessage{{Role: "user", Content: "hello"}},
			IdempotencyKey: "idem-client-context",
		}
		auth, err := client.Authorize(ctx, "sk-test", req)
		if err != nil {
			t.Fatalf("Authorize: %v", err)
		}
		usage := Usage{RequestID: "chatcmpl_1", InputTokens: 1, OutputTokens: 1, ElapsedSeconds: 0.01}
		if _, err := client.Settle(ctx, auth, usage); err != nil {
			t.Fatalf("Settle: %v", err)
		}
		if _, err := client.RefundDetailed(ctx, auth, http.StatusBadGateway, "provider_error", 0.01, nil); err != nil {
			t.Fatalf("RefundDetailed: %v", err)
		}
		return got
	}

	without := run(nil)
	with := run(clientContext)
	if !bytes.Equal(with.authorize, without.authorize) {
		t.Fatalf("authorize body changed with client context:\nwithout=%s\nwith=%s", without.authorize, with.authorize)
	}
	var authorize map[string]any
	if err := json.Unmarshal(with.authorize, &authorize); err != nil {
		t.Fatalf("decode authorize: %v", err)
	}
	if _, ok := authorize["client"]; ok {
		t.Fatalf("authorize body contains client: %#v", authorize)
	}

	wantClient := make(map[string]any)
	wantBytes, err := json.Marshal(clientContext.AsBody())
	if err != nil {
		t.Fatalf("marshal expected client context: %v", err)
	}
	if err := json.Unmarshal(wantBytes, &wantClient); err != nil {
		t.Fatalf("decode expected client context: %v", err)
	}
	for _, payload := range []struct {
		name string
		with map[string]any
		none map[string]any
	}{
		{name: "settle", with: with.settle, none: without.settle},
		{name: "refund", with: with.refund, none: without.refund},
	} {
		if !reflect.DeepEqual(payload.with["client"], wantClient) {
			t.Fatalf("%s client = %#v, want %#v", payload.name, payload.with["client"], wantClient)
		}
		delete(payload.with, "client")
		if !reflect.DeepEqual(payload.with, payload.none) {
			t.Fatalf("%s changed beyond client:\nwithout=%#v\nwith=%#v", payload.name, payload.none, payload.with)
		}
	}

	invalid := run(&qtypes.ClientContext{V: 1, Source: "tr", SDK: "not-an-sdk"})
	if _, ok := invalid.settle["client"]; ok {
		t.Fatalf("settle contains invalid client context: %#v", invalid.settle)
	}
	if _, ok := invalid.refund["client"]; ok {
		t.Fatalf("refund contains invalid client context: %#v", invalid.refund)
	}
}

func TestClientContextContextHelpersAreNilSafe(t *testing.T) {
	ctx := WithClientContext(nil, nil) //nolint:staticcheck // Explicitly verify the documented nil-safe helper.
	if ctx == nil {
		t.Fatal("WithClientContext(nil, nil) returned nil")
	}
	if got := ClientContextFromContext(ctx); got != nil {
		t.Fatalf("client context = %#v, want nil", got)
	}
	if got := ClientContextFromContext(nil); got != nil { //nolint:staticcheck // Explicitly verify the documented nil-safe helper.
		t.Fatalf("nil-context client context = %#v, want nil", got)
	}
}

func TestClientContextIsReadOnlyBySettleAndRefundBodyBuilders(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "client.go", nil, 0)
	if err != nil {
		t.Fatalf("parse client.go: %v", err)
	}
	var readers []string
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Body == nil {
			continue
		}
		ast.Inspect(function.Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			identifier, ok := call.Fun.(*ast.Ident)
			if ok && identifier.Name == "ClientContextFromContext" {
				readers = append(readers, function.Name.Name)
			}
			return true
		})
	}
	sort.Strings(readers)
	want := []string{"Settle", "refundDetailed"}
	if !reflect.DeepEqual(readers, want) {
		t.Fatalf("client context readers = %#v, want %#v", readers, want)
	}
}

func TestResolveCustomModelDecodesUserProvidedDispatchContract(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/internal/gateway/resolve-custom-model" {
			t.Fatalf("path = %s", r.URL.Path)
		}
		_, _ = io.WriteString(w, `{"data":{"workspace_id":"caller-ws","custom_model":{"id":"trustedrouter/user-demo","name":"Demo","kind":"user_provided","user_model_kind":"human","owner_workspace_id":"owner-ws","owner_user_id":"owner-user","endpoint_url":"https://owner.example/v1","upstream_model_id":"private-model","revision":7,"supports_streaming":true,"secret_namespace":"user_model","endpoint_encrypted_secret":null,"endpoint_secret_purpose":"user_model_endpoint_key","signing_encrypted_secret":{"algorithm":"TR-BYOK-ENVELOPE-AES-256-GCM-V2","key_ref":"kms-key","encrypted_dek":"dek","dek_nonce":"dek-nonce","ciphertext":"ciphertext","nonce":"nonce"},"signing_secret_purpose":"user_model_signing","connect_timeout_seconds":10,"first_byte_timeout_seconds":300,"idle_timeout_seconds":120,"total_timeout_seconds":900}}}`)
	}))
	defer server.Close()

	client := New(server.URL, "internal", server.Client())
	auth, err := client.ResolveCustomModel(t.Context(), "sk-test", "trustedrouter/user-demo", "responses")
	if err != nil {
		t.Fatalf("ResolveCustomModel: %v", err)
	}
	model := auth.CustomModel
	if model == nil {
		t.Fatal("missing custom model")
	}
	if model.Kind != "user_provided" || model.UserModelKind != "human" || model.OwnerWorkspaceID != "owner-ws" {
		t.Fatalf("identity fields = %#v", model)
	}
	if model.EndpointEncryptedSecret != nil || model.SigningEncryptedSecret == nil {
		t.Fatalf("secret envelope nullability = %#v", model)
	}
	if !model.SupportsStreaming || model.FirstByteTimeoutSeconds != 300 || model.TotalTimeoutSeconds != 900 {
		t.Fatalf("dispatch fields = %#v", model)
	}
}

func TestAuthorizeAndSettleCarryServiceTier(t *testing.T) {
	var authorizePayload map[string]any
	var settlePayload map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/internal/gateway/authorize":
			if err := json.NewDecoder(r.Body).Decode(&authorizePayload); err != nil {
				t.Fatalf("decode authorize: %v", err)
			}
			_, _ = io.WriteString(w, `{"data":{"authorization_id":"auth_priority","workspace_id":"ws_1","api_key_hash":"key_1","model":"openai/gpt-5.6-sol","endpoint_id":"openai/gpt-5.6-sol@openai/prepaid","provider":"openai","usage_type":"Credits","limit_usage_type":"Credits","route_candidates":[]}}`)
		case "/internal/gateway/settle":
			if err := json.NewDecoder(r.Body).Decode(&settlePayload); err != nil {
				t.Fatalf("decode settle: %v", err)
			}
			_, _ = io.WriteString(w, `{"data":{"generation_id":"gen_priority","cost_microdollars":1}}`)
		default:
			t.Fatalf("path = %s", r.URL.Path)
		}
	}))
	defer server.Close()

	client := New(server.URL, "internal", server.Client())
	req := &qtypes.OpenAIChatRequest{
		Model:       "openai/gpt-5.6-sol",
		ServiceTier: "priority",
		Messages:    []qtypes.OpenAIChatMessage{{Role: "user", Content: "PONG"}},
	}
	auth, err := client.Authorize(t.Context(), "sk-test", req)
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if authorizePayload["service_tier"] != "priority" {
		t.Fatalf("authorize service_tier = %#v", authorizePayload["service_tier"])
	}
	_, err = client.Settle(t.Context(), auth, Usage{
		RequestID:      "req-priority",
		InputTokens:    7,
		OutputTokens:   2,
		ElapsedSeconds: 0.1,
		ServiceTier:    "default",
	})
	if err != nil {
		t.Fatalf("Settle: %v", err)
	}
	if settlePayload["service_tier"] != "default" {
		t.Fatalf("settle service_tier = %#v", settlePayload["service_tier"])
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
	var refundPayload map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/internal/gateway/authorize":
			_, _ = io.WriteString(w, `{"data":{"authorization_id":"auth_old","workspace_id":"ws_1","api_key_hash":"key_1","model":"test/model","endpoint_id":"test/model@test/prepaid","provider":"test","usage_type":"Credits","limit_usage_type":"Credits","route_candidates":[]}}`)
		case "/internal/gateway/refund":
			refunds++
			if err := json.NewDecoder(r.Body).Decode(&refundPayload); err != nil {
				t.Fatalf("decode refund: %v", err)
			}
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
	if refundPayload["route_type"] != "responses.web_search.planner" {
		t.Fatalf("refund route_type = %#v", refundPayload["route_type"])
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

func TestAuthorizeCarriesEnclaveDerivedRequestedParameters(t *testing.T) {
	var payload map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode authorize: %v", err)
		}
		_, _ = io.WriteString(w, `{"data":{"authorization_id":"auth_1","workspace_id":"ws_1","api_key_hash":"key_1","model":"test/model","endpoint_id":"test/model@test/prepaid","provider":"test","usage_type":"Credits","limit_usage_type":"Credits","route_candidates":[]}}`)
	}))
	defer server.Close()

	client := New(server.URL, "internal", server.Client())
	_, err := client.Authorize(t.Context(), "sk-test", &qtypes.OpenAIChatRequest{
		Model:               "test/model",
		RequestedParameters: []string{"temperature", "tools"},
	})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	got, ok := payload["requested_parameters"].([]any)
	if !ok || len(got) != 2 || got[0] != "temperature" || got[1] != "tools" {
		t.Fatalf("requested_parameters = %#v", payload["requested_parameters"])
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
			client := New("https://trustedrouter.com", "internal", &http.Client{
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

func TestSettleForwardsProviderPriceTierInputTokens(t *testing.T) {
	var payload map[string]any
	client := New("https://trustedrouter.com", "internal", &http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.URL.Path != "/internal/gateway/settle" {
				t.Fatalf("path = %s", r.URL.Path)
			}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatalf("decode settle body: %v", err)
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(`{"data":{"generation_id":"gen_1","cost_microdollars":1}}`)),
			}, nil
		}),
	})

	_, err := client.Settle(t.Context(), &Authorization{
		AuthorizationID: "auth_fugu",
		Model:           "sakana-ai/fugu-ultra-v1.1",
		EndpointID:      "sakana-ai/fugu-ultra-v1.1@sakana/prepaid",
	}, Usage{
		RequestID:            "req_fugu",
		InputTokens:          1265,
		OutputTokens:         62,
		PriceTierInputTokens: 5,
	})
	if err != nil {
		t.Fatalf("Settle: %v", err)
	}
	if got := payload["price_tier_input_tokens"]; got != float64(5) {
		t.Fatalf("price_tier_input_tokens = %#v, want 5; payload=%#v", got, payload)
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

func TestValidateKeyInfoReturnsIdentityAndSendsLookupHashAndRouteOnly(t *testing.T) {
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
	identity, err := client.ValidateKeyInfo(t.Context(), rawKey, "responses.input_tokens")
	if err != nil {
		t.Fatalf("ValidateKeyInfo: %v", err)
	}
	if identity.WorkspaceID != "ws_1" || identity.APIKeyHash != "key_1" {
		t.Fatalf("identity = %#v", identity)
	}
	if payload["api_key_lookup_hash"] != lookupHash(rawKey) {
		t.Fatalf("lookup hash = %v", payload["api_key_lookup_hash"])
	}
	if payload["route_type"] != "responses.input_tokens" {
		t.Fatalf("route_type = %v", payload["route_type"])
	}
}

func TestBatchContextUsesPrecomputedLookupHashWithoutAcceptingItAsBearer(t *testing.T) {
	lookup := strings.Repeat("ab", 32)
	var received string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		received, _ = payload["api_key_lookup_hash"].(string)
		_, _ = io.WriteString(w, `{"data":{"workspace_id":"ws_1","api_key_hash":"key_1","route_type":"batch"}}`)
	}))
	defer server.Close()

	ctx, err := WithAPIKeyLookupHash(t.Context(), strings.ToUpper(lookup))
	if err != nil {
		t.Fatalf("WithAPIKeyLookupHash: %v", err)
	}
	client := New(server.URL, "internal", server.Client())
	if err := client.ValidateKey(ctx, "not-a-real-bearer", "batch"); err != nil {
		t.Fatalf("ValidateKey: %v", err)
	}
	if received != lookup {
		t.Fatalf("lookup hash = %q, want %q", received, lookup)
	}

	if _, err := WithAPIKeyLookupHash(t.Context(), "not-a-sha256-digest"); err == nil {
		t.Fatal("accepted invalid lookup hash")
	}
	if err := client.ValidateKey(t.Context(), lookup, "batch"); err != nil {
		t.Fatalf("direct ValidateKey: %v", err)
	}
	if received == lookup {
		t.Fatal("public-style bearer was accepted as a precomputed lookup hash")
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
