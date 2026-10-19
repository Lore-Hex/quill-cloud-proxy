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

func TestBedrockMantlePrepaidStreamingUsageWithoutDone(t *testing.T) {
	clients := newBootstrapDirectClients(map[string]string{"amazon-bedrock": "operator-test-key"})
	if clients["amazon-bedrock"] == nil {
		t.Fatal("Bedrock prepaid client missing")
	}
	calls := 0
	clients["amazon-bedrock"].httpc = &http.Client{Transport: byokRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.String() != "https://bedrock-mantle.us-east-1.api.aws/v1/chat/completions" || r.Header.Get("Authorization") != "Bearer operator-test-key" {
			t.Fatal("incorrect regional Bedrock endpoint or credential")
		}
		var wire openAICompatibleRequest
		if err := json.NewDecoder(r.Body).Decode(&wire); err != nil {
			t.Fatal(err)
		}
		if wire.Model != "qwen.qwen3-32b" || !wire.Stream || wire.StreamOptions == nil || !wire.StreamOptions.IncludeUsage || wire.ServiceTier != "" {
			t.Fatalf("incorrect upstream request: %+v", wire)
		}
		// Live Mantle streams terminate at EOF after the usage chunk, without
		// [DONE]. The finish reason and final counts must survive translation.
		stream := "data: {\"choices\":[{\"delta\":{\"content\":\"PONG\"},\"finish_reason\":\"stop\"}],\"service_tier\":\"default\"}\n\n" +
			"data: {\"choices\":[],\"usage\":{\"prompt_tokens\":16,\"completion_tokens\":3,\"total_tokens\":19,\"prompt_tokens_details\":{\"cached_tokens\":8}},\"service_tier\":\"default\"}\n\n"
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/event-stream"}}, Body: io.NopCloser(strings.NewReader(stream))}, nil
	})}
	var out bytes.Buffer
	err := (&multiClient{direct: clients}).InvokeStreaming(t.Context(),
		&qtypes.OpenAIChatRequest{Model: "qwen/qwen3-32b"},
		&qtypes.AnthropicMessagesRequest{MaxTokens: 128, Messages: []qtypes.AnthropicMessage{{Role: "user", Content: "PONG"}}},
		&out, InvokeOptions{Provider: "amazon-bedrock", UpstreamModel: "qwen.qwen3-32b"})
	if err != nil || calls != 1 {
		t.Fatalf("calls=%d error=%v", calls, err)
	}
	for _, want := range []string{"PONG", `"input_tokens":16`, `"output_tokens":3`, `"cache_read_input_tokens":8`, "message_stop"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("missing %s in stream", want)
		}
	}
}
