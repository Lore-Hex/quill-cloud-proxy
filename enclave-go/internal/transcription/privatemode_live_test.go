//go:build linux && live_provider_wave

package transcription_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/privatemode"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/transcription"
)

func TestPrivatemodeTranscriptionLive(t *testing.T) {
	key := os.Getenv("PRIVATEMODE_API_KEY")
	if os.Getenv("TR_CONFIDENTIAL_MEDIA_LIVE") != "1" || key == "" {
		t.Skip("paid synthetic audio opt-in")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Minute)
	defer cancel()
	verified, err := privatemode.Start(ctx)
	if err != nil {
		t.Fatal(err)
	}
	c := transcription.New(nil, map[string]string{"privatemode": key}, nil).
		WithPrivatemodeAttestation(func() (*http.Client, error) { return verified, nil })
	for _, model := range []string{"openai/whisper-large-v3", "mistralai/voxtral-mini-3b-2507"} {
		for _, format := range []string{"json", "verbose_json"} {
			if transcription.Models[model].JSONOnly() && format != "json" {
				continue
			}
			t.Run(model+"/"+format, func(t *testing.T) {
				body := map[string]any{"model": model, "response_format": format, "input_audio": map[string]string{"data": base64.StdEncoding.EncodeToString(parisAudio), "format": "wav"}}
				if format == "verbose_json" {
					body["timestamp_granularities"] = []string{"segment"}
				}
				raw, _ := json.Marshal(body)
				req, err := transcription.Parse(raw, "application/json")
				if err != nil {
					t.Fatal(err)
				}
				if err := transcription.Measure(ctx, req); err != nil {
					t.Fatal(err)
				}
				result, err := c.Transcribe(ctx, req)
				if err != nil {
					t.Fatal(err)
				}
				text, ok := result["text"].(string)
				if !ok || !strings.Contains(strings.ToLower(text), "paris") {
					t.Fatal("synthetic transcript mismatch")
				}
				t.Logf("encrypted transcription verified duration_ms=%d format=%s", req.DurationMS, format)
			})
		}
	}
}
