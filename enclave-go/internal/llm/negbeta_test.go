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

func TestPrepaidCatalogStreamingPreservesNativeModelsAndCachedUsage(t *testing.T) {
	for _, tc := range []struct{ provider, model, native, origin string }{
		{"negbeta", "qwen/qwen3.8-27b", "qwen/qwen3.8-27b", "https://inference.negbeta.com/v1"},
		{"negbeta", "deepseek/deepseek-v4.1-flash-1017", "deepseek/deepseek-v4.1-flash-1017", "https://inference.negbeta.com/v1"},
		{"nito", "openai/gpt-oss-120b", "openai/gpt-oss-120b:confidential", "https://app.trynito.ai/api/v1"},
	} {
		model := tc.model
		t.Run(model, func(t *testing.T) {
			clients := newBootstrapDirectClients(map[string]string{tc.provider: "operator-test-key"})
			if clients[tc.provider] == nil {
				t.Fatal("prepaid client missing")
			}
			calls := 0
			clients[tc.provider].httpc = &http.Client{Transport: byokRoundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.URL.String() != tc.origin+"/chat/completions" || r.Header.Get("Authorization") != "Bearer operator-test-key" {
					t.Fatal("incorrect endpoint or credential")
				}
				var wire openAICompatibleRequest
				if err := json.NewDecoder(r.Body).Decode(&wire); err != nil {
					t.Fatal(err)
				}
				if wire.Model != tc.native || !wire.Stream || wire.StreamOptions == nil || !wire.StreamOptions.IncludeUsage {
					t.Fatal("incorrect upstream model or streaming options")
				}
				stream := ": keep-alive\n\n" +
					"data: {\"choices\":[{\"delta\":{\"content\":\"PONG\"},\"finish_reason\":\"stop\"}]}\n\n" +
					"data: {\"choices\":[],\"usage\":{\"prompt_tokens\":3023,\"completion_tokens\":281,\"total_tokens\":3304,\"prompt_tokens_details\":{\"cached_tokens\":1920}}}\n\n" +
					"data: [DONE]\n\n"
				return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/event-stream"}}, Body: io.NopCloser(strings.NewReader(stream))}, nil
			})}
			var out bytes.Buffer
			multi := &multiClient{direct: clients}
			err := multi.InvokeStreaming(t.Context(), &qtypes.OpenAIChatRequest{Model: model},
				&qtypes.AnthropicMessagesRequest{MaxTokens: 64, Messages: []qtypes.AnthropicMessage{{Role: "user", Content: "PONG"}}},
				&out, InvokeOptions{Provider: tc.provider, UpstreamModel: tc.native})
			if err != nil || calls != 1 {
				t.Fatalf("calls=%d error=%v", calls, err)
			}
			for _, want := range []string{"PONG", `"input_tokens":3023`, `"output_tokens":281`, `"cache_read_input_tokens":1920`, "message_stop"} {
				if !strings.Contains(out.String(), want) {
					t.Fatalf("missing %s in stream", want)
				}
			}
		})
	}
}
