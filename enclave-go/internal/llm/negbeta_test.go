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

func TestNegbetaPrepaidStreamingPreservesNativeModelsAndCachedUsage(t *testing.T) {
	for _, model := range []string{"qwen/qwen3.8-27b", "deepseek/deepseek-v4.1-flash-1017"} {
		t.Run(model, func(t *testing.T) {
			clients := newBootstrapDirectClients(map[string]string{"negbeta": "operator-test-key"})
			if clients["negbeta"] == nil {
				t.Fatal("Negbeta prepaid client missing")
			}
			calls := 0
			clients["negbeta"].httpc = &http.Client{Transport: byokRoundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.URL.String() != "https://inference.negbeta.com/v1/chat/completions" || r.Header.Get("Authorization") != "Bearer operator-test-key" {
					t.Fatal("incorrect Negbeta endpoint or credential")
				}
				var wire openAICompatibleRequest
				if err := json.NewDecoder(r.Body).Decode(&wire); err != nil {
					t.Fatal(err)
				}
				if wire.Model != model || !wire.Stream || wire.StreamOptions == nil || !wire.StreamOptions.IncludeUsage {
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
				&out, InvokeOptions{Provider: "negbeta", UpstreamModel: model})
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
