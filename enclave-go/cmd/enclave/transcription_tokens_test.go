package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/transcription"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
)

func TestTranscriptionTokenLifecycle(t *testing.T) {
	for _, scenario := range []string{"success", "missing-usage", "missing-reserve"} {
		var out bytes.Buffer
		settled, refunded := 0, 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			encoded, _ := json.Marshal(body)
			if strings.Contains(string(encoded), "private transcript") || strings.Contains(string(encoded), "private prompt") || strings.Contains(string(encoded), "input_audio") {
				t.Error("content leaked")
			}
			w.Header().Set("Content-Type", "application/json")
			switch r.URL.Path {
			case "/internal/gateway/validate":
				io.WriteString(w, `{"data":{"workspace_id":"ws","api_key_hash":"key"}}`)
			case "/internal/gateway/authorize":
				if body["estimated_input_tokens"] != float64(transcription.MaxInputTokens) || body["max_output_tokens"] != float64(transcription.MaxOutputTokens) {
					t.Error("token reserve incomplete")
				}
				reserve := 10000
				if scenario == "missing-reserve" {
					reserve = 0
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"authorization_id": "auth", "model": "mistralai/voxtral-small-24b", "provider": "tinfoil", "upstream_model": "voxtral-small-24b", "usage_type": "Credits", "endpoint_id": "audio@tinfoil", "estimated_cost_microdollars": reserve, "additional_cost_reservation_microdollars": 0}})
			case "/internal/gateway/settle":
				settled++
				if out.Len() != 0 || body["actual_input_tokens"] != float64(391) || body["actual_output_tokens"] != float64(13) {
					t.Error("premature response or incorrect settlement")
				}
				io.WriteString(w, `{"data":{"generation_id":"gen","cost":0.000091,"settled":true}}`)
			case "/internal/gateway/refund":
				refunded++
				io.WriteString(w, `{"data":{"settled":true}}`)
			default:
				t.Error("unexpected billing call")
			}
		}))
		fake := &fakeTranscription{}
		if scenario != "missing-usage" {
			fake.tokens = &transcription.TokenUsage{Input: 391, Output: 13}
		}
		old := transcriptionProviderGateway
		transcriptionProviderGateway = fake
		serveTranscription(context.Background(), &out, transcriptionBody("mistralai/voxtral-small-24b", nil), trustedrouter.New(server.URL, "internal", server.Client()), "key", "audio-id", requestAttributionHeaders{ContentType: "application/json"}, "rlog_test")
		transcriptionProviderGateway = old
		server.Close()
		if scenario == "missing-reserve" && fake.calls != 0 {
			t.Fatal("provider invoked without reserved credits")
		}
		if scenario == "success" {
			if settled != 1 || refunded != 0 || !strings.HasPrefix(out.String(), "HTTP/1.1 200") || !strings.Contains(out.String(), `"input_tokens":391`) || strings.Contains(out.String(), "_token_usage") {
				t.Fatal("token lifecycle failed")
			}
		} else if settled != 0 || refunded != 1 || !strings.HasPrefix(out.String(), "HTTP/1.1 502") {
			t.Fatal("missing usage billed")
		}
	}
}
