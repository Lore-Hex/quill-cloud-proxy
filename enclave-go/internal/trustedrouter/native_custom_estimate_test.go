package trustedrouter

import (
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
	"strings"
	"testing"
)

func TestNativeCustomEstimateCountsGrammarAndReplay(t *testing.T) {
	def := map[string]any{"type": "grammar", "syntax": "lark", "definition": "start: \"a\""}
	req := &types.OpenAIResponsesRequest{Model: "openai/gpt-5.5", Input: "hi", Tools: []any{map[string]any{"type": "custom", "name": "patch", "format": def}}}
	estimate := func() int {
		chat, err := adapter.ResponsesToChat(req)
		if err != nil {
			t.Fatal(err)
		}
		return EstimateInputTokens(chat)
	}
	base := estimate()
	def["definition"] = def["definition"].(string) + strings.Repeat(" ", 4096)
	if estimate()-base != 1024 {
		t.Fatal("grammar omitted from reservation estimate")
	}
	req.Input = []any{map[string]any{"type": "custom_tool_call", "call_id": "c", "name": "patch", "input": "a"}}
	base = estimate()
	req.Input.([]any)[0].(map[string]any)["input"] = strings.Repeat("a", 4097)
	if estimate()-base != 1024 {
		t.Fatal("custom input omitted from reservation estimate")
	}
}
