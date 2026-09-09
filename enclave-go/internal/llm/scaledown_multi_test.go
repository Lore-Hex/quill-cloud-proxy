//go:build llm_multi

package llm

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMultiClientScaleDownUsesNativeAndRejectsBYOK(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/summarization/abstractive" {
			t.Error("native dispatch bypassed")
		}
		fmt.Fprint(w, `{"input_tokens":83,"summary":"Acme launched Monday."}`)
	}))
	defer server.Close()
	client := &multiClient{direct: map[string]*openAICompatibleClient{"scaledown": {provider: "scaledown", baseURL: server.URL, apiKey: "operator", httpc: server.Client()}}}
	req := scaleDownRequest("summarize", "Acme launched Monday.")
	if err := client.InvokeStreaming(t.Context(), req, nil, &bytes.Buffer{}, InvokeOptions{Provider: "scaledown", UpstreamModel: "summarize", UsageType: "credits"}); err != nil {
		t.Fatal(err)
	}
	if err := client.InvokeStreaming(t.Context(), req, nil, &bytes.Buffer{}, InvokeOptions{Provider: "scaledown", ProviderAPIKey: "caller", UsageType: "byok"}); err == nil {
		t.Fatal("BYOK escaped native guard")
	}
	if calls != 1 {
		t.Fatalf("made %d upstream calls", calls)
	}
}
