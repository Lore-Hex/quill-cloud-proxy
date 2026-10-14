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

func TestCoralBricksPrepaidWireAndUsage(t *testing.T) {
	for _, native := range []string{"glm-5.3-fast", "deepseek-v4.1-flash-fast"} {
		for _, stream := range []bool{false, true} {
			clients := newBootstrapDirectClients(map[string]string{"coralbricks": "fixture-key"})
			if clients["coralbricks"] == nil {
				t.Fatal("CoralBricks client missing")
			}
			clients["coralbricks"].httpc = &http.Client{Transport: byokRoundTripFunc(func(r *http.Request) (*http.Response, error) {
				if r.URL.String() != "https://inference.coralbricks.ai/v1/chat/completions" || r.Header.Get("Authorization") != "Bearer fixture-key" {
					t.Fatal("wrong endpoint or key")
				}
				var wire openAICompatibleRequest
				if err := json.NewDecoder(r.Body).Decode(&wire); err != nil {
					t.Fatal(err)
				}
				if wire.Model != native || wire.PromptCacheRetention != "off" || wire.PromptCacheKey != "session" || !wire.Stream || wire.StreamOptions == nil || !wire.StreamOptions.IncludeUsage {
					t.Fatalf("bad wire: %+v", wire)
				}
				body := "data: {\"choices\":[{\"delta\":{\"content\":\"PONG\"},\"finish_reason\":\"stop\"}]}\n\n" +
					"data: {\"choices\":[],\"usage\":{\"prompt_tokens\":100,\"completion_tokens\":20,\"total_tokens\":120,\"prompt_tokens_details\":{\"cached_tokens\":80,\"cache_write_tokens\":20,\"billable_cache_write_tokens\":0},\"completion_tokens_details\":{\"reasoning_tokens\":16}}}\n\ndata: [DONE]\n\n"
				return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/event-stream"}}, Body: io.NopCloser(strings.NewReader(body))}, nil
			})}
			var out bytes.Buffer
			err := (&multiClient{direct: clients}).InvokeStreaming(t.Context(), &qtypes.OpenAIChatRequest{Model: "public/model", Stream: stream, PromptCacheKey: "session"}, &qtypes.AnthropicMessagesRequest{Messages: []qtypes.AnthropicMessage{{Role: "user", Content: "PONG"}}}, &out, InvokeOptions{Provider: "coralbricks", UpstreamModel: native})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"PONG", `"input_tokens":100`, `"output_tokens":20`, `"cache_read_input_tokens":80`, `"reasoning_tokens":16`, "message_stop"} {
				if !strings.Contains(out.String(), want) {
					t.Fatalf("missing %s: %s", want, out.String())
				}
			}
			// Physical cache writes are not billable retained-cache creation.
			for _, line := range strings.Split(out.String(), "\n") {
				if !strings.HasPrefix(line, "data: ") {
					continue
				}
				var event struct {
					Usage struct {
						CacheCreation int `json:"cache_creation_input_tokens"`
					} `json:"usage"`
				}
				if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &event); err != nil {
					t.Fatal(err)
				}
				if event.Usage.CacheCreation != 0 {
					t.Fatalf("billed physical cache writes: %s", line)
				}
			}
		}
	}
}

func TestCoralBricksRejectsPaidRetentionAndDoesNotChangeOtherProviders(t *testing.T) {
	req := &qtypes.OpenAIChatRequest{Model: "glm-5.3-fast", PromptCacheOptions: map[string]any{"ttl": "30m"}}
	_, err := PrepareChatRequest("coralbricks", req.Model, req, nil, nil, ChatPreparationOptions{})
	if status, ok := HTTPStatusFromError(err); !ok || status != http.StatusBadRequest {
		t.Fatalf("expected 400, got %v", err)
	}
	if req.PromptCacheOptions["ttl"] != "30m" {
		t.Fatal("mutated caller options")
	}
	wire := buildOpenAICompatibleRequest("openai", "gpt-4o", nil, nil, nil)
	if wire.PromptCacheRetention != "" {
		t.Fatal("changed another provider")
	}
	if isOpenAICompatibleBYOKProvider("coralbricks") {
		t.Fatal("unreviewed BYOK support")
	}
}
