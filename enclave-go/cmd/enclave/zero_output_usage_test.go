package main

import (
	"strings"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestZeroOutputCacheUsageSettlement(t *testing.T) {
	for _, tc := range []struct {
		name, output          string
		wantInput, wantOutput int
		wantEstimated         bool
	}{
		{"explicit_zero", `,"output_tokens":0`, 1000, 0, false},
		{"missing_output", "", 2000, 17, true},
		{"positive_output", `,"output_tokens":5`, 1000, 5, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stream := `event: message_delta` + "\ndata: " + `{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"input_tokens":1000,"cache_read_input_tokens":900` + tc.output + "}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"
			result, err := adapter.CollectAnthropicText(strings.NewReader(stream))
			if err != nil {
				t.Fatal(err)
			}
			input, output, estimated := realOrEstimatedTokens(result, 2000, 17)
			usage := trustedrouter.Usage{InputTokens: input, OutputTokens: output, UsageEstimated: estimated}
			applyCacheUsage(&usage, result)
			assertUsage := func(usage trustedrouter.Usage) {
				t.Helper()
				if usage.InputTokens != tc.wantInput || usage.OutputTokens != tc.wantOutput || usage.UsageEstimated != tc.wantEstimated || usage.CacheReadInputTokens != 900 {
					t.Fatalf("settlement=%#v", usage)
				}
				if !tc.wantEstimated && usage.InputTokens-usage.CacheReadInputTokens != 100 {
					t.Fatal("cached subset inflated the uncached remainder")
				}
			}
			assertUsage(usage)
			controller := &stageDController{
				started: time.Now(), endpointID: "hixtube/test",
				meter: stageDMeter{promptTokens: 2000, semanticBytes: 68},
			}
			assertUsage(controller.terminalUsage(adapter.StreamTerminal{Result: result, FinishReason: "stop"}, "request", "chat.completions", "deepseek/deepseek-v4.1-flash-1017", &types.OpenAIChatRequest{}, 0))
		})
	}
}
