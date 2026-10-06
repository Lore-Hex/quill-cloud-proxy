//go:build llm_multi && live_tencent

package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

// Paid, opt-in, exactly two requests; no cloud bootstrap or credential lookup.
func TestLiveTencentStreaming(t *testing.T) {
	if os.Getenv("TR_LIVE_TENCENT") != "1" {
		t.Skip("set TR_LIVE_TENCENT=1 to authorize two paid TokenHub stream requests")
	}
	key := strings.TrimSpace(os.Getenv("TENCENT_API_KEY"))
	if key == "" {
		t.Fatal("TENCENT_API_KEY is required in the test process environment")
	}
	maxTokens := 128
	switch os.Getenv("TR_LIVE_TENCENT_MAX_TOKENS") {
	case "", "128":
	case "256":
		maxTokens = 256
	default:
		t.Fatal("TR_LIVE_TENCENT_MAX_TOKENS must be 128 or 256")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	defer transport.CloseIdleConnections()
	httpc := &http.Client{
		Transport: transport,
		Timeout:   90 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	for _, model := range []string{"glm-5.3-flash", "mimo-v2.6-flash"} {
		t.Run(model, func(t *testing.T) {
			result, err := tencentSmoke(t.Context(), httpc, key, model, maxTokens)
			if err != nil {
				status, _ := HTTPStatusFromError(err)
				// Never log raw errors, provider bodies, keys, or reasoning text.
				t.Fatalf("model=%s status=%d error_type=%T", model, status, err)
			}
			pong := strings.TrimSpace(result.Text) == "PONG"
			if !pong || result.FinishReason != "stop" {
				t.Fatalf("model=%s pong=%t terminal_stop=%t max_tokens=%d", model, pong, result.FinishReason == "stop", maxTokens)
			}
			u := result.Usage
			if u == nil || u.InputTokens <= 0 || u.OutputTokens <= 0 || u.ReasoningTokens > u.OutputTokens {
				t.Fatal("stream lacks coherent positive provider-reported usage")
			}
			t.Logf("model=%s PONG max_tokens=%d input_tokens=%d output_tokens=%d reasoning_tokens=%d cached_tokens=%d",
				model, maxTokens, u.InputTokens, u.OutputTokens, u.ReasoningTokens, u.CacheReadInputTokens)
		})
	}
}

func tencentSmoke(ctx context.Context, httpc *http.Client, key, model string, maxTokens int) (adapter.StreamResult, error) {
	req := &qtypes.OpenAIChatRequest{
		Model: model, MaxTokens: &maxTokens,
		Messages: []qtypes.OpenAIChatMessage{{Role: "user", Content: "Reply exactly PONG"}},
	}
	body, err := adapter.ToAnthropic(req, model)
	if err != nil {
		return adapter.StreamResult{}, err
	}
	var out bytes.Buffer
	err = invokeOpenAICompatibleBYOKStreamingWithClient(ctx, httpc, "tencent", req, body, &out,
		InvokeOptions{ProviderAPIKey: key, UpstreamModel: model})
	if err != nil {
		return adapter.StreamResult{}, err
	}
	return adapter.CollectAnthropicTextStrict(&out)
}

func TestTencentSmokeOffline(t *testing.T) {
	for _, maxTokens := range []int{128, 256} {
		calls := 0
		httpc := &http.Client{Transport: byokRoundTripFunc(func(r *http.Request) (*http.Response, error) {
			calls++
			var wire openAICompatibleRequest
			if err := json.NewDecoder(r.Body).Decode(&wire); err != nil {
				t.Fatal(err)
			}
			if r.URL.String() != "https://tokenhub-intl.tencentcloudmaas.com/v1/chat/completions" || wire.MaxTokens != maxTokens || !wire.Stream || wire.Thinking != nil || wire.ReasoningEffort != "" || wire.StreamOptions == nil || !wire.StreamOptions.IncludeUsage {
				t.Fatal("live smoke changed its fixed endpoint, explicit cap, native thinking defaults, or usage request")
			}
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(tencentTestStream))}, nil
		})}
		for _, model := range []string{"glm-5.3-flash", "mimo-v2.6-flash"} {
			result, err := tencentSmoke(t.Context(), httpc, "test-key", model, maxTokens)
			if err != nil || result.Text != "PONG" || result.FinishReason != "stop" || result.Usage == nil || result.Usage.InputTokens != 12 || result.Usage.OutputTokens != 8 || result.Usage.ReasoningTokens != 6 {
				t.Fatal("smoke adapter lost PONG, terminal state, or exact usage")
			}
		}
		if calls != 2 {
			t.Fatalf("calls=%d, want two", calls)
		}
	}
}
