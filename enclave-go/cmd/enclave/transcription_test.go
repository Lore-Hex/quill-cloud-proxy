package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/transcription"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
)

type fakeTranscription struct {
	calls   int
	failure bool
}

func (f *fakeTranscription) Transcribe(_ context.Context, _ *transcription.Request) (map[string]any, error) {
	f.calls++
	if f.failure {
		return nil, errors.New("private upstream transcript")
	}
	return map[string]any{"text": "private transcript"}, nil
}

func transcriptionBody(model string, provider map[string]any) []byte {
	wav := make([]byte, 44+32000)
	copy(wav, "RIFF")
	binary.LittleEndian.PutUint32(wav[4:], 36+32000)
	copy(wav[8:], "WAVEfmt ")
	binary.LittleEndian.PutUint32(wav[16:], 16)
	binary.LittleEndian.PutUint16(wav[20:], 1)
	binary.LittleEndian.PutUint16(wav[22:], 1)
	binary.LittleEndian.PutUint32(wav[24:], 16000)
	binary.LittleEndian.PutUint32(wav[28:], 32000)
	binary.LittleEndian.PutUint16(wav[32:], 2)
	binary.LittleEndian.PutUint16(wav[34:], 16)
	copy(wav[36:], "data")
	binary.LittleEndian.PutUint32(wav[40:], 32000)
	body, _ := json.Marshal(map[string]any{"model": model, "input_audio": map[string]string{"format": "wav", "data": base64.StdEncoding.EncodeToString(wav)}, "prompt": "private prompt", "provider": provider})
	return body
}

func TestTranscriptionLifecycle(t *testing.T) {
	for _, scenario := range []string{"success", "provider-failure", "denied", "quote-missing", "route-mismatch", "replay", "settle-failure"} {
		t.Run(scenario, func(t *testing.T) {
			var mu sync.Mutex
			var authBody, settleBody map[string]any
			var events []string
			var out bytes.Buffer
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				events = append(events, r.URL.Path)
				var body map[string]any
				if json.NewDecoder(r.Body).Decode(&body) != nil {
					t.Error("invalid billing JSON")
				}
				encoded, _ := json.Marshal(body)
				if strings.Contains(string(encoded), "private prompt") || strings.Contains(string(encoded), "private transcript") || strings.Contains(string(encoded), "input_audio") {
					t.Error("content crossed billing boundary")
				}
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/internal/gateway/validate":
					io.WriteString(w, `{"data":{"workspace_id":"ws_audio","api_key_hash":"key_audio"}}`)
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
					provider := "openai"
					if scenario == "route-mismatch" {
						provider = "mistral"
					}
					json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"authorization_id": "auth_audio", "model": "openai/whisper-1", "provider": provider, "upstream_model": "whisper-1", "usage_type": "Credits", "endpoint_id": "openai/whisper-1@openai/prepaid", "additional_cost_reservation_microdollars": quote, "idempotent_replay": scenario == "replay"}})
				case "/internal/gateway/settle":
					settleBody = body
					if out.Len() != 0 {
						t.Error("response written before settlement")
					}
					if scenario == "settle-failure" {
						w.WriteHeader(400)
						io.WriteString(w, `{"error":{"message":"settlement failed"}}`)
						return
					}
					io.WriteString(w, `{"data":{"generation_id":"gen_audio","cost":0.0001,"cost_microdollars":100,"settled":true}}`)
				case "/internal/gateway/refund":
					io.WriteString(w, `{"data":{"settled":true}}`)
				default:
					t.Error("unexpected billing endpoint")
				}
			}))
			defer server.Close()
			provider := &fakeTranscription{failure: scenario == "provider-failure"}
			old := transcriptionProviderGateway
			transcriptionProviderGateway = provider
			t.Cleanup(func() { transcriptionProviderGateway = old })
			serveTranscription(context.Background(), &out, transcriptionBody("openai/whisper-1", nil), trustedrouter.New(server.URL, "internal", server.Client()), "test-key", "transcription-id", requestAttributionHeaders{ContentType: "application/json"}, "rlog_audio")
			mu.Lock()
			defer mu.Unlock()
			if authBody["transcription_duration_ms"] != float64(1000) || authBody["estimated_input_tokens"] != float64(0) || len(authBody["request_fingerprint"].(string)) != 64 {
				t.Fatalf("bad metadata: %v", authBody)
			}
			if scenario == "success" {
				if !strings.HasPrefix(out.String(), "HTTP/1.1 200") || !strings.Contains(out.String(), "private transcript") || settleBody["additional_cost_microdollars"] != float64(100) || settleBody["actual_input_tokens"] != float64(0) {
					t.Fatal(out.String(), settleBody)
				}
				if len(events) != 3 {
					t.Fatal("duplicate billing")
				}
				var response struct {
					Usage struct {
						Type    string  `json:"type"`
						Seconds float64 `json:"seconds"`
						Cost    float64 `json:"cost"`
					} `json:"usage"`
				}
				_, body, _ := strings.Cut(out.String(), "\r\n\r\n")
				if json.Unmarshal([]byte(body), &response) != nil || response.Usage.Type != "duration" || response.Usage.Seconds != 1 || response.Usage.Cost != 0.0001 {
					t.Fatal("invalid OpenAI-compatible duration usage", body)
				}
			} else if strings.Contains(out.String(), "private transcript") || strings.HasPrefix(out.String(), "HTTP/1.1 200") {
				t.Fatal("returned unbilled or failed transcript")
			}
			if scenario == "provider-failure" || scenario == "route-mismatch" || scenario == "quote-missing" {
				if events[len(events)-1] != "/internal/gateway/refund" {
					t.Fatal("hold not refunded")
				}
			}
			if scenario == "replay" && (provider.calls != 0 || len(events) != 2) {
				t.Fatal("replay regenerated or changed hold")
			}
		})
	}
}

func TestTranscriptionConfidentialFloor(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/internal/gateway/validate" {
			t.Error("privacy rejection created a billing hold")
		}
		io.WriteString(w, `{"data":{"workspace_id":"ws_audio","api_key_hash":"key_audio"}}`)
	}))
	defer server.Close()
	for _, provider := range []map[string]any{nil, {"min_privacy": "standard"}, {"min_privacy": "confidential"}} {
		fake := &fakeTranscription{}
		old := transcriptionProviderGateway
		transcriptionProviderGateway = fake
		var out bytes.Buffer
		serveTranscription(trustedrouter.WithConfidentialOnly(context.Background()), &out, transcriptionBody("openai/whisper-1", provider), trustedrouter.New(server.URL, "internal", server.Client()), "key", "", requestAttributionHeaders{ContentType: "application/json"}, "rlog_test")
		transcriptionProviderGateway = old
		if !strings.HasPrefix(out.String(), "HTTP/1.1 400") || fake.calls != 0 {
			t.Fatal("confidential floor weakened", out.String())
		}
	}
}

func TestTranscriptionAuthenticatesBeforeParsingAudio(t *testing.T) {
	provider := &fakeTranscription{}
	old := transcriptionProviderGateway
	transcriptionProviderGateway = provider
	t.Cleanup(func() { transcriptionProviderGateway = old })
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/internal/gateway/validate" {
			t.Error("invalid credential reached billing authorization")
		}
		w.WriteHeader(http.StatusUnauthorized)
		io.WriteString(w, `{"error":{"message":"Invalid API key","type":"invalid_api_key"}}`)
	}))
	defer server.Close()
	var out bytes.Buffer
	serveTranscription(context.Background(), &out, []byte("invalid audio body"), trustedrouter.New(server.URL, "internal", server.Client()), "invalid-key", "", requestAttributionHeaders{ContentType: "application/json"}, "rlog_invalid")
	if !strings.HasPrefix(out.String(), "HTTP/1.1 401") || calls != 1 || provider.calls != 0 {
		t.Fatal("audio parsing happened before authentication", out.String(), calls)
	}
}
