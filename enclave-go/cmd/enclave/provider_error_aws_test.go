//go:build cloud_aws

package main

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/upstreamerror"
	bedrocktypes "github.com/aws/aws-sdk-go-v2/service/bedrockruntime/types"
)

func TestBedrockStreamFailureRedactsAllAPIsAndPanelLogs(t *testing.T) {
	t.Setenv("QUILL_USAGE_HEARTBEAT", "off")
	const prompt = "private echoed prompt"
	const credential = "recorded-provider-credential"
	provider := streamingProviderFunc(func(ctx context.Context, _ io.Writer, _ llm.InvokeOptions) error {
		upstreamerror.RecordCredential(ctx, credential)
		message := prompt + " " + credential
		return &bedrocktypes.ModelStreamErrorException{Message: &message}
	})
	for _, route := range []string{"chat.completions", "responses", "messages"} {
		t.Run(route, func(t *testing.T) {
			gateway, auth, options, refunds := errorTestGateway(t, false, false)
			var out bytes.Buffer
			serveErrorTestRoute(t.Context(), route, true, &out, provider, gateway, auth, options)
			if strings.Contains(out.String(), credential) || !strings.Contains(out.String(), prompt+" ***") || !strings.Contains(out.String(), `\"message\":\"`+prompt+" ***") || !strings.Contains(out.String(), `"status":502`) || *refunds != 1 {
				t.Fatalf("SDK error lost redacted message/raw/status or refund: refunds=%d wire=%s", *refunds, &out)
			}
		})
	}
	gateway, recorder := newFusionBudgetGateway(t)
	req := &types.OpenAIChatRequest{Model: "trustedrouter/synth", Messages: []types.OpenAIChatMessage{{Role: "user", Content: prompt}}}
	logs := captureStderr(t, func() {
		_, _ = runFusionPanel(t.Context(), provider, req, fusionConfig{AnalysisModels: []string{"model/test"}}, gateway, nil, "bearer", "id", "log")
	})
	if !strings.Contains(logs, "enclave.fusion_panel_failed") || !strings.Contains(logs, `error="upstream_5xx"`) || strings.Contains(logs, prompt) || strings.Contains(logs, credential) {
		t.Errorf("SDK panel error log retained payload or lost class: %s", logs)
	}
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	if len(recorder.refund) != 1 || len(recorder.settle) != 0 {
		t.Errorf("refunds=%d settlements=%d", len(recorder.refund), len(recorder.settle))
	}
}
