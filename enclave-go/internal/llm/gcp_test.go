//go:build llm_vertex || llm_multi

package llm

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

type gcpRoundTripFunc func(*http.Request) (*http.Response, error)

func (f gcpRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestVertexAnthropicRequestCarriesParamsAndGuardsTemperature(t *testing.T) {
	invoke := func(t *testing.T, model string, temp float64) struct {
		payload map[string]any
		path    string
	} {
		t.Helper()
		var captured map[string]any
		var capturedPath string
		client := &gcpClient{
			projectID: "test-project",
			region:    "global",
			httpc: &http.Client{Transport: gcpRoundTripFunc(func(req *http.Request) (*http.Response, error) {
				capturedPath = req.URL.Path
				if !strings.Contains(req.URL.Path, "/publishers/anthropic/models/") {
					t.Fatalf("path = %q, want Anthropic Vertex route", req.URL.Path)
				}
				if got := req.Header.Get("Authorization"); got != "Bearer cached-token" {
					t.Fatalf("Authorization = %q", got)
				}
				if err := json.NewDecoder(req.Body).Decode(&captured); err != nil {
					t.Fatalf("decode request body: %v", err)
				}
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
					Body:       io.NopCloser(strings.NewReader("event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")),
				}, nil
			})},
			token:    "cached-token",
			tokenExp: time.Now().Add(time.Hour),
		}
		topK := 32
		var out bytes.Buffer
		err := client.InvokeStreaming(
			t.Context(),
			&qtypes.OpenAIChatRequest{Model: model},
			&qtypes.AnthropicMessagesRequest{
				Messages:      []qtypes.AnthropicMessage{{Role: "user", Content: "hi"}},
				MaxTokens:     4096,
				Temperature:   &temp,
				StopSequences: []string{"END"},
				Thinking:      map[string]any{"type": "enabled", "budget_tokens": 1024},
				Metadata:      map[string]any{"user_id": "user-123"},
				TopK:          &topK,
			},
			&out,
		)
		if err != nil {
			t.Fatalf("InvokeStreaming: %v", err)
		}
		return struct {
			payload map[string]any
			path    string
		}{payload: captured, path: capturedPath}
	}

	payload := invoke(t, "anthropic/claude-sonnet-4.6", 1.8).payload
	if payload["temperature"] != 1.0 {
		t.Fatalf("temperature = %#v, want clamped 1.0", payload["temperature"])
	}
	if payload["max_tokens"] != float64(4096) {
		t.Fatalf("max_tokens = %#v, want required native default", payload["max_tokens"])
	}
	stop := payload["stop_sequences"].([]any)
	if len(stop) != 1 || stop[0] != "END" {
		t.Fatalf("stop_sequences = %#v", payload["stop_sequences"])
	}
	thinking := payload["thinking"].(map[string]any)
	if thinking["type"] != "enabled" || thinking["budget_tokens"] != float64(1024) {
		t.Fatalf("thinking = %#v", thinking)
	}
	metadata := payload["metadata"].(map[string]any)
	if metadata["user_id"] != "user-123" {
		t.Fatalf("metadata = %#v", metadata)
	}

	opus := invoke(t, "anthropic/claude-opus-4.8", 0.5)
	if _, ok := opus.payload["temperature"]; ok {
		t.Fatalf("opus temperature present: %#v", opus.payload["temperature"])
	}
	opusVariant := invoke(t, "anthropic/claude-opus-4.7:extended", 0.5)
	if !strings.Contains(opusVariant.path, "/models/claude-opus-4-7:streamRawPredict") {
		t.Fatalf("path = %q, want normalized opus model id", opusVariant.path)
	}
	if _, ok := opusVariant.payload["temperature"]; ok {
		t.Fatalf("opus variant temperature present: %#v", opusVariant.payload["temperature"])
	}
}
