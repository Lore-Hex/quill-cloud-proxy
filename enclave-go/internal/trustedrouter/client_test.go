package trustedrouter

import (
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
		_, _ = io.WriteString(w, `{"data":{"authorization_id":"auth_1","workspace_id":"ws_1","api_key_hash":"key_1","model":"openai/gpt-4o-mini","endpoint_id":"openai/gpt-4o-mini@openai/prepaid","provider":"openai","usage_type":"Credits","limit_usage_type":"Credits","route_candidates":[]}}`)
	}))
	defer server.Close()

	client := New(server.URL, "internal", server.Client())
	maxTokens := 7
	auth, err := client.Authorize(t.Context(), rawKey, &qtypes.OpenAIChatRequest{
		Model:          "openai/gpt-4o-mini",
		MaxTokens:      &maxTokens,
		Messages:       []qtypes.OpenAIChatMessage{{Role: "user", Content: "secret prompt"}},
		IdempotencyKey: "idem-123",
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
