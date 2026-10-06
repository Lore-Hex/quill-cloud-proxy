package llm

import (
	"io"
	"net/http"
	"strings"
	"testing"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestCloudflareGatewayBillingAndPrivacyHeaders(t *testing.T) {
	for _, provider := range []string{"cloudflare-workers-ai", "Workers AI", "zai"} {
		t.Run(provider, func(t *testing.T) {
			called := false
			httpc := &http.Client{Transport: byokRoundTripFunc(func(req *http.Request) (*http.Response, error) {
				called = true
				if req.Header.Get("Authorization") != "Bearer test-key" || req.URL.Path != "/v1/chat/completions" {
					t.Fatal("changed provider auth or API path")
				}
				for header, want := range map[string]string{
					"cf-aig-gateway-id":          "default",
					"cf-aig-collect-log":         "false",
					"cf-aig-collect-log-payload": "false",
					"cf-aig-skip-cache":          "true",
				} {
					if provider == "zai" {
						want = ""
					}
					if got := req.Header.Get(header); got != want {
						t.Errorf("%s=%q, want %q", header, got, want)
					}
				}
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
					Body:       io.NopCloser(strings.NewReader("data: {\"choices\":[{\"delta\":{\"content\":\"PONG\"},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n")),
				}, nil
			})}
			err := invokeOpenAICompatibleStreamingWithClientOptions(
				t.Context(), httpc, provider, "https://provider.example/v1", "test-key",
				&qtypes.OpenAIChatRequest{Model: "z-ai/glm-5.2"},
				&qtypes.AnthropicMessagesRequest{
					Messages:  []qtypes.AnthropicMessage{{Role: "user", Content: "Reply PONG"}},
					MaxTokens: 32,
				}, io.Discard, "@cf/zai-org/glm-5.2", openAICompatibleInvocationOptions{},
			)
			if err != nil || !called {
				t.Fatalf("called=%t err=%v", called, err)
			}
		})
	}
}
