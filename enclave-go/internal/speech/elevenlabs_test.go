package speech

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"
)

func TestElevenLabsAllowedVoices(t *testing.T) {
	// Keep expectations independent of Models so missing voices/models fail.
	models := map[string]string{
		"elevenlabs/eleven-v3":              "eleven_v3",
		"elevenlabs/eleven-multilingual-v2": "eleven_multilingual_v2",
		"elevenlabs/eleven-flash-v2.5":      "eleven_flash_v2_5",
		"elevenlabs/eleven-turbo-v2.5":      "eleven_turbo_v2_5",
	}
	voices := []string{
		"JBFqnCBsd6RMkjVDRZzb", // George
		"EXAVITQu4vr4xnSDxMaL", // Sarah
		"Xb7hH8MSUJpSbSDYk0k2", // Alice
		"XrExE9yKIg1WjnnlVkGX", // Matilda
		"hpp4J3VqNfWAUOO0d1Us", // Bella
		"cgSgspJ2msm6clMCkdW9", // Jessica
		"FGY2WhTYpPnrIDTdsKH5", // Laura
		"pFZP5JQG7iQjIQuC4Bku", // Lily
	}
	for model, upstream := range models {
		t.Run(model, func(t *testing.T) {
			if !slices.Equal(Models[model].Voices, voices) {
				t.Errorf("allowed voices = %v, want %v", Models[model].Voices, voices)
			}
			for _, voice := range voices {
				for _, format := range []string{"pcm", "mp3"} {
					t.Run(voice+"/"+format, func(t *testing.T) {
						body, err := json.Marshal(Request{Model: model, Input: "Hello", Voice: voice, Format: format})
						if err != nil {
							t.Fatal(err)
						}
						req, err := Parse(body)
						if err != nil {
							t.Fatal(err)
						}
						calls := 0
						client := New(&http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
							calls++
							if r.Method != http.MethodPost || r.URL.Scheme != "https" || r.URL.Host != "api.elevenlabs.io" || r.URL.Path != "/v1/text-to-speech/"+voice {
								t.Fatalf("unexpected upstream request: %s %s", r.Method, r.URL)
							}
							var payload map[string]any
							if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
								t.Fatal(err)
							}
							if payload["model_id"] != upstream || payload["text"] != "Hello" {
								t.Fatalf("unexpected payload: %v", payload)
							}
							data, media := "\x01\x02", "audio/pcm"
							if format == "mp3" {
								data, media = "ID3test", "audio/mpeg"
							}
							return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {media}}, Body: io.NopCloser(strings.NewReader(data))}, nil
						})}, map[string]string{"elevenlabs": "operator-key"})
						if _, err := client.Generate(context.Background(), req); err != nil {
							t.Fatal(err)
						}
						if calls != 1 {
							t.Fatalf("upstream calls = %d, want 1", calls)
						}
					})
				}
			}
			for _, voice := range []string{"unknown-voice-id", "private-voice-id", "eve", "Kore", "Sarah", ""} {
				t.Run("reject/"+voice, func(t *testing.T) {
					body, err := json.Marshal(Request{Model: model, Input: "Hello", Voice: voice})
					if err != nil {
						t.Fatal(err)
					}
					_, err = Parse(body)
					var invalid *RequestError
					if !errors.As(err, &invalid) || invalid.Param != "voice" {
						t.Fatalf("expected voice validation error, got %v", err)
					}
				})
			}
		})
	}
}

func TestOtherProvidersVoiceListsUnchanged(t *testing.T) {
	gemini := strings.Fields("Zephyr Puck Charon Kore Fenrir Leda Orus Aoede Callirrhoe Autonoe Enceladus Iapetus Umbriel Algieba Despina Erinome Algenib Rasalgethi Laomedeia Achernar Alnilam Schedar Gacrux Pulcherrima Achird Zubenelgenubi Vindemiatrix Sadachbia Sadaltager Sulafat")
	for model, voices := range map[string][]string{
		"x-ai/grok-voice-tts-1.0":          {"eve", "ara", "rex", "sal", "leo"},
		"mistralai/voxtral-mini-tts-2603":  {"en_paul_neutral"},
		"google/gemini-3.8-flash-tts":      gemini,
		"google/gemini-3.8-flash-lite-tts": gemini,
		"microsoft/mai-voice-2.1":          {"en-US-Harper", "en-US-Grant"},
		"microsoft/mai-voice-2.1-flash":    {"en-US-Harper", "en-US-Grant"},
	} {
		t.Run(model, func(t *testing.T) {
			if !slices.Equal(Models[model].Voices, voices) {
				t.Fatalf("allowed voices = %v, want %v", Models[model].Voices, voices)
			}
		})
	}
}
