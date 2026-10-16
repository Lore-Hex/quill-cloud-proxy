package transcription_test

import (
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/transcription"
)

// Generated public test sentence, never a user recording.
//
//go:embed testdata/paris.wav
var parisAudio []byte

func TestTranscriptionLive(t *testing.T) {
	if os.Getenv("TR_TRANSCRIPTION_LIVE_TEST") != "1" {
		t.Skip("paid provider transcription opt-in")
	}
	c := transcription.New(http.DefaultClient, map[string]string{"openai": os.Getenv("OPENAI_API_KEY"), "mistral": os.Getenv("MISTRAL_API_KEY"), "tinfoil": os.Getenv("TINFOIL_API_KEY")}, llm.TinfoilAttestedHTTPClient)
	for _, model := range []string{"openai/whisper-large-v3-turbo", "openai/whisper-1", "mistralai/voxtral-mini-2602"} {
		for _, mode := range []string{"json", "verbose_json", "word", "diarize"} {
			if mode == "diarize" && model != "mistralai/voxtral-mini-2602" {
				continue
			}
			t.Run(model+"/"+mode, func(t *testing.T) {
				format := mode
				if mode == "word" || mode == "diarize" {
					format = "verbose_json"
				}
				body := map[string]any{"model": model, "response_format": format, "input_audio": map[string]string{"data": base64.StdEncoding.EncodeToString(parisAudio), "format": "wav"}}
				if format == "verbose_json" {
					body["timestamp_granularities"] = []string{"segment"}
				}
				if mode == "word" {
					body["timestamp_granularities"] = []string{"word"}
				}
				if mode == "diarize" {
					body["diarize"] = true
					body["keyterms"] = []string{"TrustedRouter", "Paris"}
				}
				raw, _ := json.Marshal(body)
				req, err := transcription.Parse(raw, "application/json")
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
				defer cancel()
				if err := transcription.Measure(ctx, req); err != nil {
					t.Fatal(err)
				}
				result, err := c.Transcribe(ctx, req)
				if err != nil {
					t.Fatalf("provider=%s error=%v", transcription.Models[model].Provider, err)
				}
				text, ok := result["text"].(string)
				if !ok || !strings.Contains(strings.ToLower(text), "paris") {
					t.Fatal("known speech transcription did not match")
				}
				t.Logf("provider=%s format=%s transcript_bytes=%d duration_ms=%d", transcription.Models[model].Provider, format, len(text), req.DurationMS)
			})
		}
	}
}
