//go:build llm_vertex || llm_bedrock

package llm

import (
	"io"
	"strings"
	"testing"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestNativeCustomSingleCloudDoesNotAttemptEgress(t *testing.T) {
	c := New(&qtypes.BootstrapData{})
	req := &qtypes.OpenAIChatRequest{Model: "openai/gpt-5.5", Response: &qtypes.ResponseRequestMeta{NativeCustom: &qtypes.NativeCustomTools{}}}
	err := c.InvokeStreaming(t.Context(), req, nil, io.Discard, InvokeOptions{Provider: "openai", UsageType: "Credits"})
	if err == nil || !strings.Contains(err.Error(), "native custom tools") {
		t.Fatalf("single-cloud client did not reject before egress: %v", err)
	}
}
