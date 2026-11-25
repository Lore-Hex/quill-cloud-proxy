//go:build llm_multi

package llm

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

func TestRerankMultiDispatch(t *testing.T) {
	for _, provider := range []string{"voyage", "cohere"} {
		calls := 0
		httpc := &http.Client{Transport: rerankTransport(func(r *http.Request) (*http.Response, error) {
			calls++
			if r.URL.Path != "/v1/rerank" && r.URL.Path != "/v2/rerank" {
				t.Error("wrong rerank endpoint")
			}
			raw := `{"data":[{"index":0,"relevance_score":0.5}],"usage":{"total_tokens":2}}`
			if provider == "cohere" {
				raw = `{"results":[{"index":0,"relevance_score":0.5}],"meta":{"billed_units":{"input_tokens":2}}}`
			}
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(raw))}, nil
		})}
		m := &multiClient{voyage: &openAICompatibleClient{provider: "voyage", baseURL: "https://api.voyageai.com/v1", apiKey: "k", httpc: httpc}, cohere: &cohereClient{baseURL: cohereBaseURL, apiKey: "k", httpc: httpc}}
		resp, err := m.InvokeRerank(t.Context(), &qtypes.RerankRequest{Query: "q", Documents: []string{"d"}}, InvokeOptions{Provider: provider, UpstreamModel: "native-model", UsageType: "Credits"})
		if err != nil || calls != 1 || len(resp.Results) != 1 {
			t.Fatalf("dispatch %s: %v", provider, err)
		}
	}
	for _, provider := range []string{"voyage", "cohere", "jina", "privatemode", "tinfoil", "maple", "openai", "unknown"} {
		_, err := (&multiClient{}).InvokeRerank(t.Context(), &qtypes.RerankRequest{}, InvokeOptions{Provider: provider})
		if !errors.Is(err, ErrRerankUnsupported) {
			t.Fatal("unavailable provider must be unsupported")
		}
	}
}

func TestRerankAdaptersListeners(t *testing.T) {
	for _, provider := range []string{"voyage", "cohere"} {
		t.Run(provider, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var body map[string]any
				_ = json.NewDecoder(r.Body).Decode(&body)
				if r.URL.Path != "/rerank" || body["model"] != "native-model" || body["query"] != "q" {
					t.Error("request changed")
				}
				if provider == "voyage" {
					_, _ = io.WriteString(w, `{"data":[{"index":0,"relevance_score":0.5}],"usage":{"total_tokens":2}}`)
				} else {
					_, _ = io.WriteString(w, `{"results":[{"index":0,"relevance_score":0.5}],"meta":{"billed_units":{"input_tokens":2}}}`)
				}
			}))
			defer server.Close()
			m := &multiClient{voyage: &openAICompatibleClient{provider: "voyage", baseURL: server.URL, apiKey: "k", httpc: server.Client()}, cohere: &cohereClient{baseURL: server.URL, apiKey: "k", httpc: server.Client()}}
			_, err := m.InvokeRerank(t.Context(), &qtypes.RerankRequest{Query: "q", Documents: []string{"d"}}, InvokeOptions{Provider: provider, UpstreamModel: "native-model", UsageType: "Credits"})
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}
