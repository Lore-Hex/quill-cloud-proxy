package broadcast

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
)

func TestStripContentClearsIncludeContent(t *testing.T) {
	in := []trustedrouter.BroadcastDestination{
		{ID: "a", Type: "webhook", Endpoint: "https://x.example", IncludeContent: true},
		{ID: "b", Type: "posthog", Endpoint: "https://y.example", IncludeContent: true},
	}
	out := StripContent(in)
	if len(out) != len(in) {
		t.Fatalf("len = %d, want %d", len(out), len(in))
	}
	for _, d := range out {
		if d.IncludeContent {
			t.Fatalf("destination %s still has IncludeContent set", d.ID)
		}
	}
	// The input slice must not be mutated in place.
	if !in[0].IncludeContent || !in[1].IncludeContent {
		t.Fatal("StripContent mutated its input")
	}
	if StripContent(nil) != nil {
		t.Fatal("StripContent(nil) should be nil")
	}
}

// DevProof G5: content-broadcast destinations from the (unattested) control
// plane must never cause the enclave to POST prompt/completion anywhere. Prove
// that a content destination WOULD be delivered, but is NOT after StripContent.
func TestDeliverContentNeverPostsAfterStripContent(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	dests := []trustedrouter.BroadcastDestination{{
		ID: "d1", Type: "webhook", Endpoint: srv.URL, Method: http.MethodPost, IncludeContent: true,
	}}
	input := []map[string]string{{"role": "user", "content": "private prompt"}}

	// Baseline: a content destination IS delivered without stripping.
	DeliverContent(context.Background(), srv.Client(), nil, dests, testGeneration(), input, "private output")
	if atomic.LoadInt32(&hits) == 0 {
		t.Fatal("baseline: content destination was not delivered (test cannot prove StripContent)")
	}
	before := atomic.LoadInt32(&hits)

	// After StripContent, no further POST is made regardless of the flag.
	DeliverContent(context.Background(), srv.Client(), nil, StripContent(dests), testGeneration(), input, "private output")
	if got := atomic.LoadInt32(&hits) - before; got != 0 {
		t.Fatalf("content POSTed %d times after StripContent; want 0", got)
	}
}

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
