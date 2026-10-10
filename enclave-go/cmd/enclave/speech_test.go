package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/speech"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
)

type fakeSpeech struct {
	called int
	fail   bool
}

func (f *fakeSpeech) Generate(_ context.Context, r *speech.Request) (*speech.Result, error) {
	f.called++
	if f.fail {
		return nil, errors.New("private upstream error")
	}
	return &speech.Result{Audio: []byte("ID3audio"), ContentType: "audio/mpeg"}, nil
}

func TestSpeechLifecycle(t *testing.T) {
	for _, scenario := range []string{"success", "failure", "replay", "quote-missing", "route-mismatch", "denied"} {
		t.Run(scenario, func(t *testing.T) {
			var mu sync.Mutex
			var seen []string
			var authBody, settleBody map[string]any
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				seen = append(seen, r.URL.Path)
				var body map[string]any
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Error(err)
				}
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/internal/gateway/authorize":
					authBody = body
					if scenario == "denied" {
						w.WriteHeader(402)
						io.WriteString(w, `{"error":{"message":"insufficient credits"}}`)
						return
					}
					quote := 100
					if scenario == "quote-missing" {
						quote = 0
					}
					provider := "grok"
					if scenario == "route-mismatch" {
						provider = "openai"
					}
					json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
						"authorization_id": "auth_speech", "model": "x-ai/grok-voice-tts-1.0",
						"provider": provider, "upstream_model": "grok-voice-tts-1.0", "usage_type": "Credits",
						"endpoint_id": "x-ai/grok-voice-tts-1.0@grok/prepaid", "additional_cost_reservation_microdollars": quote,
						"idempotent_replay": scenario == "replay",
					}})
				case "/internal/gateway/settle":
					settleBody = body
					io.WriteString(w, `{"data":{"generation_id":"gen_speech","cost_microdollars":100,"cost":0.0001,"settled":true}}`)
				case "/internal/gateway/refund":
					io.WriteString(w, `{"data":{"settled":true}}`)
				default:
					t.Errorf("unexpected path %s", r.URL.Path)
					w.WriteHeader(500)
				}
			}))
			defer server.Close()
			generator := &fakeSpeech{fail: scenario == "failure"}
			old := speechProviderGateway
			speechProviderGateway = generator
			t.Cleanup(func() { speechProviderGateway = old })
			gateway := trustedrouter.New(server.URL, "internal", server.Client())
			var out bytes.Buffer
			serveSpeech(context.Background(), &out, []byte(`{"model":"x-ai/grok-voice-tts-1.0","input":"秘密é","voice":"eve","response_format":"mp3"}`), gateway, "tr-test-key", "speech-id", requestAttributionHeaders{}, "rlog_123")
			mu.Lock()
			defer mu.Unlock()
			serialized, _ := json.Marshal(authBody)
			if strings.Contains(string(serialized), "秘密") || strings.Contains(string(serialized), "tr-test-key") {
				t.Fatal("text or bearer leaked")
			}
			if authBody["speech_input_characters"] != float64(3) || authBody["estimated_input_tokens"] != float64(0) {
				t.Fatalf("bad usage: %v", authBody)
			}
			if len(authBody["request_fingerprint"].(string)) != 64 {
				t.Fatal("missing content binding")
			}
			if scenario == "success" {
				if !strings.HasPrefix(out.String(), "HTTP/1.1 200") || !strings.HasSuffix(out.String(), "ID3audio") || !strings.Contains(out.String(), "X-Generation-Id: gen_speech") {
					t.Fatalf("bad response %s", out.String())
				}
				if settleBody["additional_cost_microdollars"] != float64(100) || settleBody["actual_input_tokens"] != float64(0) {
					t.Fatalf("bad settlement: %v", settleBody)
				}
			} else {
				if strings.Contains(out.String(), "ID3audio") || strings.Contains(out.String(), "private upstream") || settleBody != nil {
					t.Fatal("failed request returned or billed audio")
				}
				if scenario != "failure" && generator.called != 0 {
					t.Fatal("unauthorized upstream call")
				}
				if scenario == "replay" && len(seen) != 1 {
					t.Fatal("replay touched existing hold")
				}
				if scenario == "failure" && seen[len(seen)-1] != "/internal/gateway/refund" {
					t.Fatal("failure did not refund")
				}
			}
		})
	}
}
