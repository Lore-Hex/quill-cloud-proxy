package adapter

import (
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestContextWebSearchSelection(t *testing.T) {
	for _, engine := range []string{"context", "context.dev"} {
		config, err := ResponsesWebSearchConfig([]any{map[string]any{"type": "web_search", "engine": engine}}, nil, nil)
		if err != nil || config.Engine != "context" || config.MaxCalls != 3 {
			t.Fatalf("config=%+v err=%v", config, err)
		}
		for _, tool := range []map[string]any{
			{"type": "web_search", "engine": engine},
			{"type": "openrouter:web_search", "parameters": map[string]any{"engine": engine, "max_uses": 1}},
		} {
			req := &types.OpenAIChatRequest{Tools: []any{tool}}
			if err := ConfigureChatWebSearch(req); err != nil || req.Response.WebSearch.Engine != "context" {
				t.Fatalf("chat: %v", err)
			}
		}
		req := &types.OpenAIChatRequest{Plugins: []any{map[string]any{"id": "web", "engine": engine}}}
		if err := ConfigureChatWebSearch(req); err != nil || req.Response.WebSearch.Engine != "context" {
			t.Fatalf("plugin: %v", err)
		}
	}
}

func TestContextWebSearchRejectsUnsupportedSettings(t *testing.T) {
	for _, parameters := range []map[string]any{
		{"engine": "context", "mode": "deep"},
		{"engine": "context", "max_characters": 20001},
		{"engine": "context", "api_key": "never-forward"},
		{"engine": "context", "credit_microdollars": 0},
		{"engine": true},
		{"engine": "unknown"},
	} {
		if _, err := parseExaWebSearchParameters(parameters, "tools.parameters"); err == nil {
			t.Fatalf("accepted %+v", parameters)
		}
	}
}
