package speech

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"testing"
	"time"
)

// Explicit opt-in only: these probes incur a small real provider charge.
func TestSpeechLive(t *testing.T) {
	if os.Getenv("TR_SPEECH_LIVE_TEST") != "1" {
		t.Skip("set TR_SPEECH_LIVE_TEST=1 with provider keys to run paid smoke")
	}
	client := New(http.DefaultClient, map[string]string{"grok": os.Getenv("GROK_API_KEY"), "mistral": os.Getenv("MISTRAL_API_KEY"), "google-ai-studio": os.Getenv("GEMINI_API_KEY"), "azure": os.Getenv("AZURE_FOUNDRY_API_KEY"), "elevenlabs": os.Getenv("ELEVEN_LABS_API_KEY")})
	for id, spec := range Models {
		for _, format := range spec.Formats {
			t.Run(id+"/"+format, func(t *testing.T) {
				body, _ := json.Marshal(map[string]any{"model": id, "input": "Hello from TrustedRouter.", "voice": spec.Voices[0], "response_format": format})
				req, err := Parse(body)
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
				defer cancel()
				result, err := client.Generate(ctx, req)
				if err != nil {
					t.Fatal(err)
				}
				if len(result.Audio) < 1000 {
					t.Fatal("unexpectedly short audio")
				}
				t.Logf("audio_bytes=%d content_type=%s", len(result.Audio), result.ContentType)
			})
		}
	}
}
