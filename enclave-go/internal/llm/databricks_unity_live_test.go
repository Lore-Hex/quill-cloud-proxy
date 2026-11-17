//go:build live_provider_wave && llm_multi

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

func TestLiveDatabricksUnity(t *testing.T) {
	if os.Getenv("TR_LIVE_DATABRICKS_UNITY") != "1" {
		t.Skip("opt-in bounded Unity inference check")
	}
	boot := &qtypes.BootstrapData{DatabricksHost: os.Getenv("DATABRICKS_HOST"), DatabricksUnityToken: os.Getenv("DATABRICKS_UNITY_TOKEN")}
	m := New(boot).(*multiClient)
	if m.databricksUnity == nil {
		t.Fatal("Unity host and token required")
	}
	req := &qtypes.OpenAIChatRequest{Model: "meta-llama/llama-3.1-8b-instruct", Messages: []qtypes.OpenAIChatMessage{{Role: "user", Content: "Reply with only the word PONG."}}}
	limit := 32
	temperature := 0.0
	req.Temperature = &temperature
	req.MaxTokens = &limit
	body, err := adapter.ToAnthropic(req, req.Model)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	var out bytes.Buffer
	if err := m.InvokeStreaming(ctx, req, body, &out, InvokeOptions{Provider: "databricks", UpstreamModel: "databricks-meta-llama-3-1-8b-instruct"}); err != nil {
		status, _ := HTTPStatusFromError(err)
		t.Fatalf("Unity request failed: status=%d error_type=%T", status, err)
	}
	result, err := adapter.CollectAnthropicTextStrict(&out)
	if err != nil {
		t.Fatalf("invalid stream: %v", err)
	}
	if !strings.EqualFold(strings.TrimSpace(result.Text), "PONG") || result.FinishReason != "stop" || result.Usage == nil || result.Usage.InputTokens <= 0 || result.Usage.OutputTokens <= 0 {
		t.Fatalf("synthetic check: reply=%q finish=%q usage=%+v", result.Text, result.FinishReason, result.Usage)
	}
}
