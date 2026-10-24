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

func TestAbliterationPreservesNativeModelAndCacheUsage(t *testing.T) {
	for _, model := range []string{"abliterated-model", "abliterated-model-large", "abliterated-model-large-v2", "abliterated-model-large-flash"} {
		t.Run(model, func(t *testing.T) {
			clients := newBootstrapDirectClients(map[string]string{"abliteration": "test-key"})
			if clients["abliteration"] == nil {
				t.Fatal("Abliteration client missing")
			}
			calls := 0
			clients["abliteration"].httpc = &http.Client{Transport: byokRoundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.URL.String() != "https://api.abliteration.ai/v1/chat/completions" || r.Header.Get("Authorization") != "Bearer test-key" {
					t.Fatal("incorrect provider endpoint or credential")
				}
				var wire openAICompatibleRequest
				if err := json.NewDecoder(r.Body).Decode(&wire); err != nil {
					t.Fatal(err)
				}
				if wire.Model != model || !wire.Stream || wire.StreamOptions == nil || !wire.StreamOptions.IncludeUsage {
					t.Fatalf("incorrect upstream request: %+v", wire)
				}
				stream := "data: {\"choices\":[{\"delta\":{\"content\":\"PONG\"},\"finish_reason\":\"stop\"}]}\n\n" +
					"data: {\"choices\":[],\"usage\":{\"prompt_tokens\":2048,\"completion_tokens\":2,\"total_tokens\":2050,\"prompt_tokens_details\":{\"cached_tokens\":1024}}}\n\n" +
					"data: [DONE]\n\n"
				return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/event-stream"}}, Body: io.NopCloser(strings.NewReader(stream))}, nil
			})}
			var out bytes.Buffer
			multi := &multiClient{direct: clients}
			err := multi.InvokeStreaming(t.Context(), &qtypes.OpenAIChatRequest{Model: "abliteration/" + model},
				&qtypes.AnthropicMessagesRequest{MaxTokens: 512, Messages: []qtypes.AnthropicMessage{{Role: "user", Content: "PONG"}}},
				&out, InvokeOptions{Provider: "abliteration", UpstreamModel: model})
			if err != nil || calls != 1 {
				t.Fatalf("calls=%d error=%v", calls, err)
			}
			for _, want := range []string{"PONG", `"input_tokens":2048`, `"output_tokens":2`, `"cache_read_input_tokens":1024`, "message_stop"} {
				if !strings.Contains(out.String(), want) {
					t.Fatalf("missing %s in stream", want)
				}
			}
		})
	}
}

func TestAbliterationRejectsNativePaidWebTools(t *testing.T) {
	for _, tool := range []any{map[string]any{"type": "web_search"}, map[string]any{"type": "web_fetch"}, true} {
		_, err := PrepareChatRequest("abliteration", "abliterated-model", &qtypes.OpenAIChatRequest{Tools: []any{tool}},
			&qtypes.AnthropicMessagesRequest{MaxTokens: 16}, nil, ChatPreparationOptions{})
		if err == nil {
			t.Fatalf("unmetered/non-ZDR tool admitted: %+v", tool)
		}
	}
	_, err := PrepareChatRequest("abliteration", "abliterated-model", &qtypes.OpenAIChatRequest{
		Tools: []any{map[string]any{"type": "function", "function": map[string]any{"name": "web_search"}}},
	}, &qtypes.AnthropicMessagesRequest{MaxTokens: 16}, nil, ChatPreparationOptions{})
	if err != nil {
		t.Fatalf("caller-executed function tool rejected: %v", err)
	}
}
