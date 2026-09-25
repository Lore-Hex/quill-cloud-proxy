package llm

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/privatemode"
	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

// PrivatemodeProbeResult contains only fixed model IDs and measured metadata.
// Never add error bodies, output, thinking, or credentials to this event.
type PrivatemodeProbeResult struct {
	Event        string `json:"event"`
	Model        string `json:"model"`
	Success      bool   `json:"success"`
	HTTPStatus   int    `json:"http_status,omitempty"`
	InputTokens  int    `json:"input_tokens,omitempty"`
	OutputTokens int    `json:"output_tokens,omitempty"`
}

// ProbePrivatemode sends exactly three bounded synthetic requests, no retries.
// It is an operator expense, not a customer request or settlement. Run once per
// boot, off the startup critical path, to verify a dark regional deployment.
func ProbePrivatemode(ctx context.Context, client *http.Client, key string, emit func(PrivatemodeProbeResult)) {
	for _, model := range []string{"gpt-oss-120b", "glm-5.3", "glm-5.3-flash"} {
		if ctx.Err() != nil {
			return
		}
		emit(probePrivatemodeModel(ctx, client, key, model))
	}
}

func probePrivatemodeModel(ctx context.Context, client *http.Client, key, model string) PrivatemodeProbeResult {
	result := PrivatemodeProbeResult{Event: "privatemode.encrypted_probe", Model: model}
	if client == nil || key == "" || !privatemode.AllowedModel(model) {
		return result
	}
	ctx, cancel := context.WithTimeout(ctx, 180*time.Second)
	defer cancel()
	maxTokens := 1024
	req := &qtypes.OpenAIChatRequest{Model: model, MaxTokens: &maxTokens, ReasoningEffort: "low"}
	body := &qtypes.AnthropicMessagesRequest{MaxTokens: maxTokens, MaxTokensExplicit: true,
		Messages: []qtypes.AnthropicMessage{{Role: "user", Content: "Reply with exactly PONG and nothing else."}}}
	out := &privatemodeProbeBuffer{}
	err := invokeOpenAICompatibleStreamingWithClientOptions(ctx, client, "privatemode", privatemode.BaseURL,
		key, req, body, out, model, openAICompatibleInvocationOptions{})
	if err != nil {
		result.HTTPStatus, _ = HTTPStatusFromError(err)
		return result
	}
	parsed, err := adapter.CollectAnthropicTextStrict(bytes.NewReader(out.buffer.Bytes()))
	if err != nil || parsed.Usage == nil {
		return result
	}
	result.InputTokens, result.OutputTokens = parsed.Usage.InputTokens, parsed.Usage.OutputTokens
	result.Success = strings.TrimSpace(parsed.Text) == "PONG" && result.InputTokens > 0 && result.OutputTokens > 0
	return result
}

type privatemodeProbeBuffer struct{ buffer bytes.Buffer }

func (b *privatemodeProbeBuffer) Write(p []byte) (int, error) {
	if b.buffer.Len()+len(p) > 1<<20 {
		return 0, errors.New("privatemode: synthetic response exceeds limit")
	}
	return b.buffer.Write(p)
}

var _ io.Writer = (*privatemodeProbeBuffer)(nil)
