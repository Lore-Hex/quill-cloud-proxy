//go:build llm_multi

package llm

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestEveryMultiProviderWireSerializerOmitsRouterOnlyMetadata(t *testing.T) {
	maxTokens := 64
	req := &qtypes.OpenAIChatRequest{
		Model:         "openai/gpt-4o-mini",
		Messages:      []qtypes.OpenAIChatMessage{{Role: "user", Content: "hello"}},
		MaxTokens:     &maxTokens,
		User:          "router-user-marker",
		SessionID:     "router-session-marker",
		Trace:         map[string]any{"router-trace-marker": true},
		Tags:          qtypes.NewRequestTags(qtypes.TagMap{"router-tag-marker": "legal"}),
		App:           "router-app-marker",
		HTTPReferer:   "https://router-referer-marker.example/app",
		AppCategories: []string{"router-category-marker"},
	}
	body, err := adapter.ToAnthropic(req, req.Model)
	if err != nil {
		t.Fatalf("ToAnthropic: %v", err)
	}
	messages := []qtypes.AnthropicMessage{{Role: "user", Content: "hello"}}

	vertexGemini, err := vertexGeminiPayload(context.Background(), req, body, "gemini-2.5-flash")
	if err != nil {
		t.Fatalf("vertexGeminiPayload: %v", err)
	}
	openAICompatible := buildOpenAICompatibleRequest(
		"openai",
		"gpt-4o-mini",
		req,
		body,
		[]chatMessage{{Role: "user", Content: "hello"}},
	)

	embeddingReq := &qtypes.EmbeddingRequest{
		Model:         "openai/text-embedding-3-small",
		Input:         "hello",
		User:          req.User,
		SessionID:     req.SessionID,
		Trace:         req.Trace,
		Tags:          qtypes.CloneRequestTags(req.Tags),
		App:           req.App,
		HTTPReferer:   req.HTTPReferer,
		AppCategories: append([]string(nil), req.AppCategories...),
	}
	openAIEmbedding, err := openAICompatibleEmbeddingWirePayload("openai", embeddingReq, "text-embedding-3-small")
	if err != nil {
		t.Fatalf("openAICompatibleEmbeddingWirePayload: %v", err)
	}
	cohereEmbedding, err := cohereEmbeddingWirePayload(
		embeddingReq,
		InvokeOptions{UpstreamModel: "embed-v4.0"},
	)
	if err != nil {
		t.Fatalf("cohereEmbeddingWirePayload: %v", err)
	}

	payloads := map[string]any{
		"anthropic":         buildAnthropicWireRequest("claude-haiku-4-5", messages, body),
		"vertex-anthropic":  buildVertexAnthropicWireRequest("claude-haiku-4-5", messages, body),
		"openai-compatible": openAICompatible,
		"vertex-gemini":     vertexGemini,
		"openai-embedding":  openAIEmbedding,
		"cohere-embedding":  cohereEmbedding,
	}
	for name, payload := range payloads {
		t.Run(name, func(t *testing.T) {
			assertRouterMetadataAbsentFromWireJSON(t, payload)
		})
	}
}

func assertRouterMetadataAbsentFromWireJSON(t *testing.T, payload any) {
	t.Helper()
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
			t.Fatalf("wire payload leaked %q: %s", forbidden, text)
		}
	}
}
