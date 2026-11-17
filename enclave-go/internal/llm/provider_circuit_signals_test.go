//go:build llm_multi

package llm

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/upstreamerror"
)

// The gateway's provider circuit breaker must not read the gateway's own
// failures as the provider being down.
func TestGatewayOwnFailuresAreMarkedLocal(t *testing.T) {
	assertLocal := func(t *testing.T, err error) {
		t.Helper()
		if err == nil || !upstreamerror.IsLocal(err) {
			t.Fatalf("err = %v, want a Local gateway failure", err)
		}
		_, redact := upstreamerror.WithCredentialRedaction(t.Context(), "secret")
		redacted := redact(err)
		if !upstreamerror.IsLocal(redacted) {
			t.Fatalf("credential redaction dropped the Local mark: %v", redacted)
		}
	}
	t.Run("gcp metadata token 503", func(t *testing.T) {
		client := &gcpClient{projectID: "test", region: "global", httpc: &http.Client{Transport: gcpRoundTripFunc(func(req *http.Request) (*http.Response, error) {
			if req.URL.String() != metadataTokenURL {
				t.Fatalf("inference ran without a token: %s", req.URL)
			}
			return runtimeReply(503, "metadata server unavailable"), nil
		})}}
		var out bytes.Buffer
		err := client.InvokeStreaming(t.Context(), &qtypes.OpenAIChatRequest{Model: "anthropic/claude-haiku-4.5"}, &qtypes.AnthropicMessagesRequest{MaxTokens: 16}, &out)
		assertLocal(t, err)
		if status, ok := upstreamerror.Status(err); !ok || status != 503 {
			t.Fatalf("status = %d %t, want the 503 kept for the client", status, ok)
		}
	})
	t.Run("gcp metadata server unreachable", func(t *testing.T) {
		client := &gcpClient{projectID: "test", region: "global", httpc: &http.Client{Transport: gcpRoundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, fmt.Errorf("dial tcp: connect: connection refused")
		})}}
		var out bytes.Buffer
		assertLocal(t, client.InvokeStreaming(t.Context(), &qtypes.OpenAIChatRequest{Model: "anthropic/claude-haiku-4.5"}, &qtypes.AnthropicMessagesRequest{MaxTokens: 16}, &out))
	})
	t.Run("bedrock runtime retention check", func(t *testing.T) {
		client := newBedrockRuntimeWithHTTP("test-key", &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return runtimeReply(503, `{"message":"unavailable"}`), nil
		})})
		var out bytes.Buffer
		err := client.InvokeStreaming(t.Context(), &qtypes.OpenAIChatRequest{Model: "anthropic/claude-haiku-5.5"}, &qtypes.AnthropicMessagesRequest{MaxTokens: 16}, &out, InvokeOptions{UpstreamModel: "us.anthropic.claude-haiku-5-5"})
		assertLocal(t, err)
	})
}

type answeredRecorder struct {
	bytes.Buffer
	answered bool
}

func (r *answeredRecorder) UpstreamAnswered() { r.answered = true }

// ScaleDown and Clairic buffer the whole body. They must say when the provider
// answered, so an unusable 200 body is not counted as the provider being down.
func TestBufferedTaskClientsSignalAcceptance(t *testing.T) {
	for _, tc := range []struct {
		name   string
		invoke func(t *testing.T, url string, out *answeredRecorder) error
	}{
		{"scaledown", func(t *testing.T, url string, out *answeredRecorder) error {
			client := &openAICompatibleClient{provider: "scaledown", baseURL: url, apiKey: "operator-key", httpc: http.DefaultClient}
			return client.InvokeStreaming(t.Context(), scaleDownRequest("summarize", scaleDownTestInputs["summarize"]), nil, out, InvokeOptions{Provider: "scaledown", UpstreamModel: "summarize", UsageType: "credits"})
		}},
		{"clairic", func(t *testing.T, url string, out *answeredRecorder) error {
			client := &openAICompatibleClient{provider: "cloudflare-workers-ai", baseURL: url + "/ai/v1", apiKey: "key", httpc: http.DefaultClient}
			return client.InvokeStreaming(t.Context(), clairicRequest(clairicInput), nil, out)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, status := range []int{200, 503} {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(status)
					fmt.Fprint(w, `not the expected body`)
				}))
				var out answeredRecorder
				err := tc.invoke(t, server.URL, &out)
				server.Close()
				if err == nil {
					t.Fatalf("status %d: unusable body accepted", status)
				}
				if out.answered != (status == 200) {
					t.Fatalf("status %d: answered=%t", status, out.answered)
				}
			}
		})
	}
}
