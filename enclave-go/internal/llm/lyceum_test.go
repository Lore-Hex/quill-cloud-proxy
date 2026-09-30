//go:build llm_multi

package llm

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestLyceumPrepaidStreamingPreservesUsageAndNativeModel(t *testing.T) {
	clients := newBootstrapDirectClients(map[string]string{"lyceum": "operator-test-key"})
	if clients["lyceum"] == nil {
		t.Fatal("Lyceum prepaid client missing")
	}
	calls := 0
	clients["lyceum"].httpc = &http.Client{Transport: byokRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.String() != "https://api.lyceum.technology/openai/v1/chat/completions" || r.Header.Get("Authorization") != "Bearer operator-test-key" {
			t.Fatal("incorrect Lyceum endpoint or credential")
		}
		var wire openAICompatibleRequest
		if err := json.NewDecoder(r.Body).Decode(&wire); err != nil {
			t.Fatal(err)
		}
		if wire.Model != "z-ai/glm-5.3-flash" || !wire.Stream || wire.StreamOptions == nil || !wire.StreamOptions.IncludeUsage {
			t.Fatalf("incorrect upstream request: %+v", wire)
		}
		stream := "data: {\"choices\":[{\"delta\":{\"content\":\"PONG\"},\"finish_reason\":\"stop\"}]}\n\n" +
			"data: {\"choices\":[],\"usage\":{\"prompt_tokens\":3023,\"completion_tokens\":281,\"total_tokens\":3304,\"prompt_tokens_details\":{\"cached_tokens\":1920}}}\n\n" +
			"data: [DONE]\n\n"
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/event-stream"}}, Body: io.NopCloser(strings.NewReader(stream))}, nil
	})}
	var out bytes.Buffer
	multi := &multiClient{direct: clients}
	err := multi.InvokeStreaming(t.Context(), &qtypes.OpenAIChatRequest{Model: "z-ai/glm-5.3-flash"},
		&qtypes.AnthropicMessagesRequest{MaxTokens: 512, Messages: []qtypes.AnthropicMessage{{Role: "user", Content: "PONG"}}},
		&out, InvokeOptions{Provider: "lyceum", UpstreamModel: "z-ai/glm-5.3-flash"})
	if err != nil || calls != 1 {
		t.Fatalf("calls=%d error=%v", calls, err)
	}
	for _, want := range []string{"PONG", `"input_tokens":3023`, `"output_tokens":281`, `"cache_read_input_tokens":1920`, "message_stop"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("missing %s in stream", want)
		}
	}
}
