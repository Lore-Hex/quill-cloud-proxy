package trustedrouter

import (
	"encoding/json"
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
		Model:     "openai/gpt-4o-mini",
		MaxTokens: &maxTokens,
		Messages:  []qtypes.OpenAIChatMessage{{Role: "user", Content: "secret prompt"}},
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
}
