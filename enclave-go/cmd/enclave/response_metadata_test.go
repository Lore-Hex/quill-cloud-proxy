package main

import (
	"encoding/json"
	"strings"
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
	tracker.RecordCandidateAttempt(llm.InvokeOptions{EndpointID: "anthropic-endpoint", Model: "anthropic/claude-sonnet", Provider: "anthropic"})
	tracker.RecordCandidateAttempt(llm.InvokeOptions{EndpointID: "openai-endpoint", Model: "openai/gpt-4o-mini", Provider: "openai"})
	tracker.Select(llm.InvokeOptions{
		EndpointID: "openai-endpoint",
		Model:      "openai/gpt-4o-mini",
		Provider:   "openai",
	})
	metadata := openRouterRoutingMetadata(auth, tracker)
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

func TestOpenRouterRoutingMetadataMasksCustomModelAndUnattemptedTopology(t *testing.T) {
	auth := &trustedrouter.Authorization{
		RequestedModel: "custom/legal-review",
		Model:          "anthropic/claude-opus-4.8",
		Provider:       "anthropic",
		EndpointID:     "private-anthropic-endpoint",
		UsageType:      "BYOK",
		Region:         "us-central1",
		CustomModel:    &trustedrouter.CustomModel{ID: "custom/legal-review"},
		RouteCandidates: []trustedrouter.RouteCandidate{
			{EndpointID: "private-anthropic-endpoint", Model: "anthropic/claude-opus-4.8", Provider: "anthropic"},
			{EndpointID: "never-attempted", Model: "openai/gpt-5.5", Provider: "openai"},
		},
	}
	tracker := newSelectedRouteTracker()
	tracker.RecordCandidateAttempt(llm.InvokeOptions{
		EndpointID: "private-anthropic-endpoint",
		Model:      "anthropic/claude-opus-4.8",
		Provider:   "anthropic",
	})
	tracker.Select(llm.InvokeOptions{
		EndpointID: "private-anthropic-endpoint",
		Model:      "anthropic/claude-opus-4.8",
		Provider:   "anthropic",
	})
	metadata := openRouterRoutingMetadata(auth, tracker)
	encoded, err := json.Marshal(metadata)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	text := string(encoded)
	for _, forbidden := range []string{
		"anthropic/claude-opus-4.8",
		"openai/gpt-5.5",
		"private-anthropic-endpoint",
		"never-attempted",
		"us-central1",
		"is_byok",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("custom metadata leaked %q: %s", forbidden, text)
		}
	}
	if !strings.Contains(text, "custom/legal-review") || !strings.Contains(text, "trustedrouter") {
		t.Fatalf("masked metadata = %s", text)
	}
	endpoints := metadata["endpoints"].(map[string]any)
	if endpoints["total"] != 1 {
		t.Fatalf("endpoints = %#v, want attempted route only", endpoints)
	}
}
