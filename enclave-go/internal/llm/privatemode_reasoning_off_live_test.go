//go:build linux && live_provider_wave && llm_multi

package llm

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/privatemode"
	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestPrivatemodeReasoningOffLive(t *testing.T) {
	key := os.Getenv("PRIVATEMODE_API_KEY")
	if os.Getenv("TR_PRIVATEMODE_REASONING_LIVE") != "1" || key == "" {
		t.Skip("two paid, encrypted synthetic PONG requests require explicit opt-in")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	verified, err := privatemode.Start(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ConfigurePrivatemode(verified)
	defer ConfigurePrivatemode(nil)
	assertPrivatemodeUnprivileged(t)
	for _, model := range []string{"glm-5.3", "glm-5.3-flash"} {
		t.Run(model, func(t *testing.T) {
			zero := 0.0
			req := &qtypes.OpenAIChatRequest{Model: model, Reasoning: map[string]any{"enabled": false}}
			body := &qtypes.AnthropicMessagesRequest{MaxTokens: 32, MaxTokensExplicit: true, Temperature: &zero,
				Messages: []qtypes.AnthropicMessage{{Role: "user", Content: "Reply with exactly PONG and nothing else."}}}
			out := &privatemodeProbeBuffer{}
			err := newOpenAICompatible("privatemode", key).InvokeStreaming(ctx, req, body, out,
				InvokeOptions{Provider: "privatemode", UpstreamModel: model, ProviderCacheScope: "synthetic-reasoning-off-test"})
			if err != nil {
				status, _ := HTTPStatusFromError(err)
				reason := "transport_or_adapter"
				var typed *privatemodeHTTPError
				if errors.As(err, &typed) {
					reason = typed.reason
				}
				t.Fatalf("encrypted reasoning-off request failed: status=%d category=%s", status, reason)
			}
			parsed, err := adapter.CollectAnthropicTextStrict(bytes.NewReader(out.buffer.Bytes()))
			if err != nil || parsed.Usage == nil || parsed.Usage.InputTokens <= 0 || parsed.Usage.OutputTokens <= 0 {
				t.Fatal("missing complete response or billable usage")
			}
			if strings.TrimSpace(parsed.Text) != "PONG" || len(parsed.Thinking) != 0 || parsed.Usage.ReasoningTokens != 0 {
				t.Fatal("synthetic answer mismatch or reasoning emitted with off")
			}
			t.Logf("encrypted PONG with reasoning off: input_tokens=%d output_tokens=%d reasoning_tokens=%d",
				parsed.Usage.InputTokens, parsed.Usage.OutputTokens, parsed.Usage.ReasoningTokens)
		})
	}
}
