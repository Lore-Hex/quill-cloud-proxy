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
	called       int
	fail         bool
	inputTokens  int
	outputTokens int
}

func (f *fakeSpeech) Generate(_ context.Context, r *speech.Request) (*speech.Result, error) {
	f.called++
	if f.fail {
		return nil, errors.New("private upstream error")
	}
	return &speech.Result{Audio: []byte("ID3audio"), ContentType: "audio/mpeg", InputTokens: f.inputTokens, OutputTokens: f.outputTokens}, nil
}

func TestSpeechTokenBillingLifecycle(t *testing.T) {
	for _, scenario := range []string{"success", "missing-reservation", "mixed-billing", "settle-failure"} {
		t.Run(scenario, func(t *testing.T) {
			var authBody, settleBody map[string]any
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var body map[string]any
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Error(err)
				}
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/internal/gateway/authorize":
					authBody = body
					estimate, additional := 160000, 0
					if scenario == "missing-reservation" {
						estimate = 0
					}
					if scenario == "mixed-billing" {
						additional = 100
					}
					json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
						"authorization_id": "auth_speech", "model": "google/gemini-3.8-flash-tts",
						"provider": "google-ai-studio", "upstream_model": "gemini-3.8-flash-tts", "usage_type": "Credits",
						"endpoint_id":                 "google/gemini-3.8-flash-tts@google-ai-studio/prepaid",
						"estimated_cost_microdollars": estimate, "additional_cost_reservation_microdollars": additional,
					}})
				case "/internal/gateway/settle":
					settleBody = body
					if scenario == "settle-failure" {
						w.WriteHeader(400)
						io.WriteString(w, `{"error":{"message":"settlement unavailable"}}`)
						return
					}
					io.WriteString(w, `{"data":{"generation_id":"gen_tokens","cost_microdollars":200,"cost":0.0002,"settled":true}}`)
				case "/internal/gateway/refund":
					io.WriteString(w, `{"data":{"settled":true}}`)
				default:
					t.Errorf("unexpected path %s", r.URL.Path)
				}
			}))
			defer server.Close()
			generator := &fakeSpeech{inputTokens: 5, outputTokens: 21}
			old := speechProviderGateway
			speechProviderGateway = generator
			t.Cleanup(func() { speechProviderGateway = old })
			gateway := trustedrouter.New(server.URL, "internal", server.Client())
			var out bytes.Buffer
			serveSpeech(context.Background(), &out, []byte(`{"model":"google/gemini-3.8-flash-tts","input":"Hello","voice":"Kore"}`), gateway, "tr-test-key", "token-speech-id", requestAttributionHeaders{}, "rlog_123")
			if authBody["estimated_input_tokens"] != float64(speech.GeminiInputLimit) || authBody["max_output_tokens"] != float64(speech.GeminiOutputLimit) {
				t.Fatalf("bad token hold: %v", authBody)
			}
			if scenario == "missing-reservation" || scenario == "mixed-billing" {
				if generator.called != 0 || settleBody != nil {
					t.Fatal("unfunded generation")
				}
			} else {
				if settleBody["actual_input_tokens"] != float64(5) || settleBody["actual_output_tokens"] != float64(21) {
					t.Fatalf("lost native usage: %v", settleBody)
				}
				if additional, _ := settleBody["additional_cost_microdollars"].(float64); additional != 0 {
					t.Fatal("token speech charged as characters")
				}
			}
			if scenario == "success" {
				if !strings.HasPrefix(out.String(), "HTTP/1.1 200") || !strings.HasSuffix(out.String(), "ID3audio") {
					t.Fatalf("bad response: %s", out.String())
				}
			} else if strings.Contains(out.String(), "ID3audio") {
				t.Fatal("delivered unsettled audio")
			}
		})
	}
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
