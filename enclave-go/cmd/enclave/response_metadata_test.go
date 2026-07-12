package main

import (
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
)

func TestOpenRouterRoutingMetadataDescribesSelectedFallbackWithoutSensitiveFields(t *testing.T) {
	auth := &trustedrouter.Authorization{
		RequestedModel: "trustedrouter/auto",
		Model:          "openai/gpt-4o-mini",
		Provider:       "openai",
		ProviderName:   "OpenAI",
		EndpointID:     "openai-endpoint",
		UsageType:      "Credits",
		Region:         "us-central1",
		RouteCandidates: []trustedrouter.RouteCandidate{
			{EndpointID: "anthropic-endpoint", Model: "anthropic/claude-sonnet", Provider: "anthropic", ProviderName: "Anthropic"},
			{EndpointID: "openai-endpoint", Model: "openai/gpt-4o-mini", Provider: "openai", ProviderName: "OpenAI"},
		},
	}
	tracker := newSelectedRouteTracker()
	tracker.RecordCandidateAttempt(llm.InvokeOptions{EndpointID: "anthropic-endpoint"})
	tracker.RecordCandidateAttempt(llm.InvokeOptions{EndpointID: "openai-endpoint"})
	tracker.Select(llm.InvokeOptions{
		EndpointID: "openai-endpoint",
		Model:      "openai/gpt-4o-mini",
		Provider:   "openai",
	})
	metadata := openRouterRoutingMetadata(auth, tracker, nil)
	if metadata["requested"] != "trustedrouter/auto" || metadata["strategy"] != "fallback" {
		t.Fatalf("metadata = %#v", metadata)
	}
	if metadata["attempt"] != 2 || metadata["region"] != "us-central1" {
		t.Fatalf("metadata = %#v", metadata)
	}
	endpoints := metadata["endpoints"].(map[string]any)
	available := endpoints["available"].([]map[string]any)
	if len(available) != 2 || available[1]["selected"] != true {
		t.Fatalf("available = %#v", available)
	}
	for _, forbidden := range []string{"tags", "user", "session_id", "trace", "prompt", "output"} {
		if _, exists := metadata[forbidden]; exists {
			t.Fatalf("metadata contains forbidden field %q: %#v", forbidden, metadata)
		}
	}
}
