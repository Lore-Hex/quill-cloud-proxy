package main

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestFusionPanelLogsOnlyErrorClass(t *testing.T) {
	const prompt = "private echoed prompt"
	gateway, _ := newFusionBudgetGateway(t)
	provider := streamingProviderFunc(func(context.Context, io.Writer, llm.InvokeOptions) error { return errors.New(prompt) })
	req := &types.OpenAIChatRequest{Model: "trustedrouter/synth", Messages: []types.OpenAIChatMessage{{Role: "user", Content: prompt}}}
	logs := captureStderr(t, func() {
		_, _ = runFusionPanel(t.Context(), provider, req, fusionConfig{AnalysisModels: []string{"model/test"}}, gateway, nil, "bearer", "id", "log")
	})
	if !strings.Contains(logs, "enclave.fusion_panel_failed") || strings.Contains(logs, prompt) || !strings.Contains(logs, `error="other:`) {
		t.Fatalf("panel error log retained provider text or lost class: %s", logs)
	}
}
