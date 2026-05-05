package broadcast

import (
	"encoding/json"
	"strings"
	"testing"
)

func testGeneration() Generation {
	return Generation{
		ID:               "gen_1",
		WorkspaceID:      "ws_1",
		APIKeyHash:       "abcdef1234567890abcdef",
		Model:            "openai/gpt-4o-mini",
		Provider:         "openai",
		Region:           "us-central1",
		RouteType:        "responses",
		RequestID:        "resp_1",
		InputTokens:      12,
		OutputTokens:     8,
		ElapsedSeconds:   0.4,
		Streamed:         true,
		FinishReason:     "stop",
		CostMicrodollars: 42,
		User:             "user-1",
		SessionID:        "session-1",
		Trace:            map[string]any{"trace_id": "trace-1", "experiment": "alpha"},
		Metadata:         map[string]any{"app": "test"},
	}
}

func TestDestinationAdaptersRegistered(t *testing.T) {
	for _, destinationType := range []string{"posthog", "webhook"} {
		adapter, ok := adapterFor(destinationType)
		if !ok {
			t.Fatalf("missing adapter for %s", destinationType)
		}
		if adapter.Type() != destinationType {
			t.Fatalf("adapter type = %s, want %s", adapter.Type(), destinationType)
		}
	}
	if _, ok := adapterFor("missing"); ok {
		t.Fatal("unexpected adapter for unsupported destination type")
	}
}

func TestPostHogPayloadUsesAIGenerationAndContentFields(t *testing.T) {
	payload := posthogPayload(
		"phc_token",
		testGeneration(),
		[]map[string]string{{"role": "user", "content": "private prompt"}},
		"private output",
	)
	if payload["event"] != "$ai_generation" {
		t.Fatalf("event = %v", payload["event"])
	}
	if payload["api_key"] != "phc_token" {
		t.Fatalf("api key = %v", payload["api_key"])
	}
	properties := payload["properties"].(map[string]any)
	if properties["$ai_trace_id"] != "trace-1" || properties["$ai_model"] != "openai/gpt-4o-mini" {
		t.Fatalf("bad properties: %#v", properties)
	}
	if properties["$ai_input"] == nil || properties["$ai_output_choices"] == nil {
		t.Fatalf("content fields missing: %#v", properties)
	}
}

func TestOTLPPayloadUsesResourceSpansAndContentOnlyWhenEnabled(t *testing.T) {
	metadataOnly := otlpPayload(testGeneration(), false, "private prompt", "private output")
	metadataBody, _ := json.Marshal(metadataOnly)
	if !strings.Contains(string(metadataBody), "resourceSpans") {
		t.Fatalf("missing OTLP resourceSpans: %s", metadataBody)
	}
	if strings.Contains(string(metadataBody), "private prompt") || strings.Contains(string(metadataBody), "private output") {
		t.Fatalf("metadata-only payload leaked content: %s", metadataBody)
	}

	withContent := otlpPayload(testGeneration(), true, "private prompt", "private output")
	contentBody, _ := json.Marshal(withContent)
	if !strings.Contains(string(contentBody), "private prompt") || !strings.Contains(string(contentBody), "private output") {
		t.Fatalf("content payload missing content: %s", contentBody)
	}
}
