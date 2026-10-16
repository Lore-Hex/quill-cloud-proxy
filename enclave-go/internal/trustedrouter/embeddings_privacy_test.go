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

func TestEmbeddingAuthorizationPreservesProviderRestrictions(t *testing.T) {
	var req qtypes.EmbeddingRequest
	if err := json.Unmarshal([]byte(`{"model":"qwen/qwen3-embedding-4b","input":"private-content","provider":{"only":["privatemode"],"allow_fallbacks":false,"min_privacy":"confidential"}}`), &req); err != nil {
		t.Fatal(err)
	}
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		raw, _ := io.ReadAll(r.Body)
		if strings.Contains(string(raw), "private-content") {
			t.Error("input leaked to control plane")
		}
		var body struct {
			Provider qtypes.ProviderRouting `json:"provider"`
		}
		if json.Unmarshal(raw, &body) != nil || body.Provider.MinPrivacy != "confidential" || len(body.Provider.Only) != 1 || body.Provider.Only[0] != "privatemode" || body.Provider.AllowFallbacks == nil || *body.Provider.AllowFallbacks {
			t.Error("provider restrictions lost")
		}
		_, _ = io.WriteString(w, `{"data":{"authorization_id":"a1","model":"qwen/qwen3-embedding-4b","provider":"privatemode","usage_type":"Credits"}}`)
	}))
	defer server.Close()
	client := New(server.URL, "internal", server.Client())
	if _, err := client.AuthorizeEmbeddings(WithConfidentialOnly(t.Context()), "test-key", &req, 4); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("authorization calls = %d", calls)
	}
}

func TestEmbeddingConfidentialFloorFailsBeforeAuthorization(t *testing.T) {
	client := New("https://must-not-authorize.invalid", "internal", nil)
	for _, provider := range []*qtypes.ProviderRouting{nil, {}, {MinPrivacy: "any"}, {MinPrivacy: "zdr"}} {
		_, err := client.AuthorizeEmbeddings(WithConfidentialOnly(t.Context()), "test-key", &qtypes.EmbeddingRequest{Model: "test", Provider: provider}, 1)
		if err == nil || !strings.Contains(err.Error(), "confidential") {
			t.Fatalf("lost privacy accepted: %v", err)
		}
	}
}
