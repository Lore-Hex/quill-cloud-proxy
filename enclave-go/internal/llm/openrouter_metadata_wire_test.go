//go:build llm_openrouter

package llm

import (
	"encoding/json"
	"strings"
	"testing"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestOpenRouterWireSerializerOmitsRouterOnlyMetadata(t *testing.T) {
	req := &qtypes.OpenAIChatRequest{
		User:          "router-user-marker",
		SessionID:     "router-session-marker",
		Trace:         map[string]any{"router-trace-marker": true},
		Tags:          qtypes.NewRequestTags(qtypes.TagMap{"router-tag-marker": "legal"}),
		App:           "router-app-marker",
		HTTPReferer:   "https://router-referer-marker.example/app",
		AppCategories: []string{"router-category-marker"},
	}
	body := &qtypes.AnthropicMessagesRequest{
		Messages: []qtypes.AnthropicMessage{{Role: "user", Content: "hello"}},
	}
	payload := (&openRouterClient{providers: []string{"anthropic"}}).buildWireRequest(
		"openai/gpt-4o-mini",
		req,
		body,
	)
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	text := string(encoded)
	for _, forbidden := range []string{
		"router-user-marker",
		"router-session-marker",
		"router-trace-marker",
		"router-tag-marker",
		"router-app-marker",
		"router-referer-marker",
		"router-category-marker",
		`"tags"`,
		`"trace"`,
		`"session_id"`,
		`"http_referer"`,
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("OpenRouter payload leaked %q: %s", forbidden, text)
		}
	}
}
