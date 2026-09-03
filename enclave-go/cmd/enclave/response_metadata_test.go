package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
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

func TestPrivateProxyResponseMetadataMasksBackingRoute(t *testing.T) {
	t.Parallel()

	const (
		alias    = "trustedrouter/archimedes-1.0"
		backing  = "mistralai/mistral-large"
		provider = "mistral"
		endpoint = "credits:mistral:mistralai/mistral-large"
	)
	authorization := &trustedrouter.Authorization{
		RequestedModel:     alias,
		ResponseModel:      alias,
		HidePublicMetadata: true,
		Model:              backing,
		Provider:           provider,
		EndpointID:         endpoint,
		UsageType:          "Credits",
		Region:             "us-central1",
	}
	tracker := newSelectedRouteTracker()
	option := llm.InvokeOptions{Model: backing, Provider: provider, EndpointID: endpoint}
	tracker.RecordCandidateAttempt(option)
	tracker.Select(option)

	annotated, err := annotateSettledResponseMetadata(
		[]byte(`{"id":"chatcmpl_private","model":"trustedrouter/archimedes-1.0","usage":{"prompt_tokens":11,"completion_tokens":3}}`),
		authorization,
		&trustedrouter.SettleResult{
			CostMicrodollars: 17,
			UsageType:        "Credits",
			Model:            backing,
			Provider:         provider,
			Region:           "us-central1",
		},
		tracker,
		[]llm.InvokeOptions{option},
		adapter.StreamResult{},
		true,
	)
	if err != nil {
		t.Fatalf("annotateSettledResponseMetadata: %v", err)
	}
	encoded := string(annotated)
	for _, forbidden := range []string{backing, endpoint, `"selected_provider":"mistral"`, "us-central1"} {
		if strings.Contains(encoded, forbidden) {
			t.Fatalf("private proxy metadata leaked %q: %s", forbidden, encoded)
		}
	}
	if !strings.Contains(encoded, alias) || !strings.Contains(encoded, `"selected_provider":"trustedrouter"`) {
		t.Fatalf("private proxy metadata was not masked: %s", encoded)
	}
}

func TestPrivateProxyBatchUsageMasksBackingRoute(t *testing.T) {
	t.Parallel()

	authorization := &trustedrouter.Authorization{
		ResponseModel:      "trustedrouter/archimedes-1.0",
		HidePublicMetadata: true,
		Model:              "mistralai/mistral-large",
		Provider:           "mistral",
	}
	annotated, err := annotateSettlementOnlyUsage(
		[]byte(`{"id":"msg_private","usage":{"input_tokens":2,"output_tokens":1}}`),
		&trustedrouter.SettleResult{
			CostMicrodollars: 9,
			UsageType:        "Credits",
			Model:            "mistralai/mistral-large",
			Provider:         "mistral",
		},
		authorization,
	)
	if err != nil {
		t.Fatalf("annotateSettlementOnlyUsage: %v", err)
	}
	encoded := string(annotated)
	if strings.Contains(encoded, "mistralai/mistral-large") || strings.Contains(encoded, `"selected_provider":"mistral"`) {
		t.Fatalf("private proxy batch usage leaked backing route: %s", encoded)
	}
	if !strings.Contains(encoded, "trustedrouter/archimedes-1.0") || !strings.Contains(encoded, `"selected_provider":"trustedrouter"`) {
		t.Fatalf("private proxy batch usage was not masked: %s", encoded)
	}
}

func TestAnnotateSettlementOnlyUsageAddsIntegerCostWithoutContent(t *testing.T) {
	t.Parallel()

	body := []byte(`{"id":"msg_1","usage":{"input_tokens":11,"output_tokens":3}}`)
	annotated, err := annotateSettlementOnlyUsage(body, &trustedrouter.SettleResult{
		CostMicrodollars: 17,
		UsageType:        "Credits",
		Model:            "anthropic/claude-sonnet",
		Provider:         "anthropic",
		Region:           "us-central1",
	}, nil)
	if err != nil {
		t.Fatalf("annotateSettlementOnlyUsage: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(annotated, &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	usage := payload["usage"].(map[string]any)
	if usage["cost_microdollars"] != float64(17) || usage["total_cost_microdollars"] != float64(17) {
		t.Fatalf("usage = %#v", usage)
	}
	providerUsage := usage["provider_usage"].(map[string]any)
	if providerUsage["usage_type"] != "Credits" || providerUsage["contains_prompt_or_completion"] != false {
		t.Fatalf("provider_usage = %#v", providerUsage)
	}
	for _, forbidden := range []string{"prompt", "completion", "messages", "input", "output"} {
		if strings.Contains(string(annotated), `"`+forbidden+`"`) {
			t.Fatalf("annotated response contains %q: %s", forbidden, annotated)
		}
	}
}

func TestBatchSettlementUsageDoesNotChangeOrdinaryResponses(t *testing.T) {
	t.Parallel()

	body := []byte(`{"id":"msg_ordinary","usage":{"input_tokens":2,"output_tokens":1}}`)
	settlement := &trustedrouter.SettleResult{CostMicrodollars: 9, UsageType: "Credits"}
	ordinary, err := annotateBatchSettlementOnlyUsage(context.Background(), body, settlement, nil)
	if err != nil {
		t.Fatalf("ordinary response: %v", err)
	}
	if !bytes.Equal(ordinary, body) {
		t.Fatalf("ordinary response changed: %s", ordinary)
	}

	batchCtx := context.WithValue(context.Background(), batchExecutionContextKey{}, true)
	annotated, err := annotateBatchSettlementOnlyUsage(batchCtx, body, settlement, nil)
	if err != nil {
		t.Fatalf("batch response: %v", err)
	}
	if bytes.Equal(annotated, body) || !bytes.Contains(annotated, []byte(`"cost_microdollars":9`)) {
		t.Fatalf("batch response missing accounting metadata: %s", annotated)
	}
}
