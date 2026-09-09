package main

import (
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	"testing"
)

func TestScaleDownUsagePreservesNativeInputOnlyMeter(t *testing.T) {
	result := adapter.StreamResult{Usage: &adapter.StreamUsage{InputTokens: 394, OutputTokens: 0}}
	for _, model := range []string{"scaledown/compress", "scaledown/summarize", "scaledown/extract", "scaledown/classify"} {
		in, out, estimated := realOrEstimatedTokens(result, 10, 80, model)
		if in != 394 || out != 0 || estimated {
			t.Fatalf("%s got %d %d %v", model, in, out, estimated)
		}
	}
	for _, model := range []string{"openai/gpt-oss-120b", "scaledown/unknown", "trustedrouter/user-example", ""} {
		in, out, estimated := realOrEstimatedTokens(result, 10, 80, model)
		if in != 10 || out != 80 || !estimated {
			t.Fatalf("%s bypassed missing-output safety", model)
		}
	}
}
