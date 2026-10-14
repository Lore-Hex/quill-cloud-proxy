//go:build live_provider_wave

package llm

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

// One paid request through the production adapter, using synthetic input only.
func TestLiveDatabricksQwenReasoningBlocks(t *testing.T) {
	if os.Getenv("TR_LIVE_DATABRICKS") != "1" {
		t.Skip("set TR_LIVE_DATABRICKS=1 for the bounded paid adapter smoke")
	}
	host, key := os.Getenv("DATABRICKS_HOST"), os.Getenv("DATABRICKS_TOKEN")
	if _, err := databricksServingBaseURL(host); err != nil || key == "" {
		t.Fatal("approved Databricks host and token required")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	limit := 512
	req := &qtypes.OpenAIChatRequest{
		Model: "qwen/qwen3.5-122b-a10b", MaxTokens: &limit,
		Messages: []qtypes.OpenAIChatMessage{{Role: "user", Content: "Reply exactly PONG."}},
	}
	body, err := adapter.ToAnthropic(req, req.Model)
	if err != nil {
		t.Fatal("cannot construct synthetic request")
	}
	var out bytes.Buffer
	err = newDatabricks(host, key).InvokeStreaming(ctx, req, body, &out,
		InvokeOptions{Provider: "databricks", UpstreamModel: "databricks-qwen35-122b-a10b"})
	if err != nil {
		status, _ := HTTPStatusFromError(err)
		t.Fatalf("adapter failed: status=%d error_type=%T", status, err)
	}
	result, err := adapter.CollectAnthropicTextStrict(&out)
	if err != nil || strings.TrimSpace(result.Text) != "PONG" || result.FinishReason != "stop" {
		t.Fatal("adapter did not preserve the exact answer and terminal state")
	}
	if result.Usage == nil || result.Usage.InputTokens <= 0 || result.Usage.OutputTokens <= 0 {
		t.Fatal("adapter did not preserve positive billable usage")
	}
	t.Logf("PONG and usage verified: input=%d output=%d", result.Usage.InputTokens, result.Usage.OutputTokens)
}
