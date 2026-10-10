package speech

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/xml"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestElevenLabsAndMicrosoftNativeContracts(t *testing.T) {
	for id, spec := range Models {
		if spec.Provider != "elevenlabs" && spec.Provider != "azure" {
			continue
		}
		for _, format := range spec.Formats {
			t.Run(id+"/"+format, func(t *testing.T) {
				input := `Hello <audio src="https://invalid"/> & goodbye`
				body, _ := json.Marshal(map[string]any{"model": id, "input": input, "voice": spec.Voices[0], "response_format": format})
				req, err := Parse(body)
				if err != nil {
					t.Fatal(err)
				}
				client := New(&http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
					if r.Header.Get("Authorization") != "" {
						t.Fatal("wrong credential header")
					}
					if spec.Provider == "elevenlabs" {
						if r.URL.Host != "api.elevenlabs.io" || r.URL.Path != "/v1/text-to-speech/"+spec.Voices[0] || r.Header.Get("xi-api-key") != "operator-key" {
							t.Fatal("wrong ElevenLabs target")
						}
						want := "pcm_24000"
						if format == "mp3" {
							want = "mp3_44100_128"
						}
						if r.URL.Query().Get("output_format") != want {
							t.Fatal("wrong audio format")
						}
						var p map[string]any
						if json.NewDecoder(r.Body).Decode(&p) != nil || len(p) != 2 || p["text"] != input || p["model_id"] != spec.Upstream {
							t.Fatal("wrong speech payload")
						}
					} else {
						if r.URL.String() != "https://eastus2.tts.speech.microsoft.com/cognitiveservices/v1" || r.Header.Get("Ocp-Apim-Subscription-Key") != "operator-key" || r.Header.Get("Content-Type") != "application/ssml+xml" {
							t.Fatal("wrong Azure target")
						}
						var p struct {
							Voice struct {
								Name     string     `xml:"name,attr"`
								Text     string     `xml:",chardata"`
								Children []struct{} `xml:",any"`
							} `xml:"voice"`
						}
						if xml.NewDecoder(r.Body).Decode(&p) != nil || p.Voice.Name != spec.Voices[0]+":"+spec.Upstream || p.Voice.Text != input || len(p.Voice.Children) != 0 {
							t.Fatal("SSML injection or voice mismatch")
						}
						want := "raw-24khz-16bit-mono-pcm"
						if format == "mp3" {
							want = "audio-24khz-160kbitrate-mono-mp3"
						}
						if r.Header.Get("X-Microsoft-OutputFormat") != want {
							t.Fatal("wrong Azure format")
						}
					}
					data, media := "\x01\x02", "audio/pcm"
					if spec.Provider == "azure" {
						media = "audio/basic"
					}
					if format == "mp3" {
						data, media = "ID3test", "audio/mpeg"
					}
					return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {media}}, Body: io.NopCloser(strings.NewReader(data))}, nil
				})}, map[string]string{spec.Provider: "operator-key"})
				if _, err := client.Generate(context.Background(), req); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func wavFixture() []byte {
	b := make([]byte, 46)
	copy(b, "RIFF")
	binary.LittleEndian.PutUint32(b[4:], 38)
	copy(b[8:], "WAVEfmt ")
	binary.LittleEndian.PutUint32(b[16:], 16)
	binary.LittleEndian.PutUint16(b[20:], 1)
	binary.LittleEndian.PutUint16(b[22:], 1)
	binary.LittleEndian.PutUint32(b[24:], 24000)
	binary.LittleEndian.PutUint32(b[28:], 48000)
	binary.LittleEndian.PutUint16(b[32:], 2)
	binary.LittleEndian.PutUint16(b[34:], 16)
	copy(b[36:], "data")
	binary.LittleEndian.PutUint32(b[40:], 2)
	return b
}

func geminiFixture(format string) map[string]any {
	part := map[string]any{"type": "audio", "mime_type": "audio/l16;rate=24000;channels=1", "sample_rate": 24000, "channels": 1, "data": base64.StdEncoding.EncodeToString([]byte{1, 2})}
	if format == "wav" {
		part = map[string]any{"type": "audio", "mime_type": "audio/wav", "data": base64.StdEncoding.EncodeToString(wavFixture())}
	}
	return map[string]any{"status": "completed", "model": "gemini-3.8-flash-tts", "service_tier": "standard", "usage": map[string]any{"total_input_tokens": 6, "total_output_tokens": 52}, "steps": []any{map[string]any{"type": "model_output", "content": []any{part}}}}
}

func TestGeminiSpeechNativeContract(t *testing.T) {
	for _, format := range []string{"pcm", "wav"} {
		t.Run(format, func(t *testing.T) {
			raw, _ := json.Marshal(map[string]any{"model": "google/gemini-3.8-flash-tts", "input": "Hello", "voice": "Kore", "response_format": format})
			req, _ := Parse(raw)
			client := New(&http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
				if r.URL.String() != "https://generativelanguage.googleapis.com/v1beta/interactions" || r.Header.Get("x-goog-api-key") != "operator-key" || r.Header.Get("Authorization") != "" {
					t.Fatal("wrong Gemini target")
				}
				var p map[string]any
				if json.NewDecoder(r.Body).Decode(&p) != nil || p["store"] != false || p["model"] != "gemini-3.8-flash-tts" {
					t.Fatal("wrong Gemini privacy/model")
				}
				if p["generation_config"].(map[string]any)["max_output_tokens"] != float64(GeminiOutputLimit) {
					t.Fatal("missing output cap")
				}
				data, _ := json.Marshal(geminiFixture(format))
				return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(string(data)))}, nil
			})}, map[string]string{"google-ai-studio": "operator-key"})
			result, err := client.Generate(context.Background(), req)
			if err != nil || result.InputTokens != 6 || result.OutputTokens != 52 {
				t.Fatalf("usage/audio: %v %v", result, err)
			}
		})
	}
}

func TestGeminiSpeechRejectsUnbillableOrMalformedResponses(t *testing.T) {
	spec := Models["google/gemini-3.8-flash-tts"]
	for _, mutate := range []func(map[string]any){
		func(p map[string]any) { delete(p, "usage") },
		func(p map[string]any) { p["status"] = "in_progress" },
		func(p map[string]any) { p["model"] = "other" },
		func(p map[string]any) { p["service_tier"] = "priority" },
		func(p map[string]any) { p["usage"].(map[string]any)["total_output_tokens"] = 16385 },
		func(p map[string]any) { p["usage"].(map[string]any)["total_input_tokens"] = -1 },
		func(p map[string]any) { p["usage"].(map[string]any)["total_cached_tokens"] = 1 },
		func(p map[string]any) { p["steps"] = []any{} },
		func(p map[string]any) {
			p["steps"].([]any)[0].(map[string]any)["content"].([]any)[0].(map[string]any)["data"] = "broken base64"
		},
		func(p map[string]any) {
			p["steps"].([]any)[0].(map[string]any)["content"].([]any)[0].(map[string]any)["sample_rate"] = 16000
		},
	} {
		p := geminiFixture("pcm")
		mutate(p)
		raw, _ := json.Marshal(p)
		if _, err := decodeGeminiAudio(raw, spec, "pcm"); err == nil {
			t.Fatal("accepted malformed speech")
		}
	}
	b := wavFixture()
	if !validWAV(b) {
		t.Fatal("valid fixture rejected")
	}
	for _, offset := range []int{0, 4, 8, 16, 20, 22, 24, 28, 32, 34, 40} {
		bad := append([]byte(nil), b...)
		bad[offset] ^= 1
		if validWAV(bad) {
			t.Fatalf("accepted malformed WAV at %d", offset)
		}
	}
	for _, offset := range []int{16, 40} {
		for _, size := range []uint32{MaxAudioBytes + 1, 1 << 31, ^uint32(0)} {
			bad := append([]byte(nil), b...)
			binary.LittleEndian.PutUint32(bad[offset:offset+4], size)
			if validWAV(bad) {
				t.Fatalf("accepted oversized WAV chunk at %d: %d", offset, size)
			}
		}
	}
}
