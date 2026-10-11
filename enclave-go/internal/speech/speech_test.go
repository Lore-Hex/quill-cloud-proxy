package speech

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"unicode/utf8"
)

const valid = `{"model":"x-ai/grok-voice-tts-1.0","input":"Hello","voice":"eve","response_format":"mp3"}`

func TestParseSpeech(t *testing.T) {
	for _, input := range []string{
		`null`, `{}`, valid + `{}`, strings.Replace(valid, `"Hello"`, `[]`, 1),
		strings.Replace(valid, `"Hello"`, `" "`, 1),
		strings.Replace(valid, `"eve"`, `"private-voice-id"`, 1),
		strings.Replace(valid, `"mp3"`, `"wav"`, 1),
		strings.Replace(valid, `"Hello"`, `"`+strings.Repeat("a", 60001)+`"`, 1),
		strings.TrimSuffix(valid, "}") + `,"speed":0}`,
		strings.TrimSuffix(valid, "}") + `,"speed":2}`,
		strings.TrimSuffix(valid, "}") + `,"input_references":[{"url":"http://localhost"}]}`,
		strings.TrimSuffix(valid, "}") + `,"provider":{"options":{"grok":{"with_timestamps":true}}}}`,
		strings.TrimSuffix(valid, "}") + `,"provider":{"unknown":true}}`,
		strings.TrimSuffix(valid, "}") + `,"instructions":"ignored?"}`,
	} {
		if _, err := Parse([]byte(input)); err == nil {
			t.Fatalf("accepted invalid request: %.140s", input)
		}
	}
	req, err := Parse([]byte(strings.Replace(valid, `"Hello"`, `"你好é"`, 1)))
	if err != nil || utf8.RuneCountInString(req.Input) != 3 {
		t.Fatalf("unicode count: %v", err)
	}
	req, err = Parse([]byte(strings.Replace(valid, `,"response_format":"mp3"`, "", 1)))
	if err != nil || req.Format != "pcm" || *req.Speed != 1 {
		t.Fatalf("defaults: %#v %v", req, err)
	}
	if _, err := Parse([]byte(`{"model":"mistralai/voxtral-mini-tts-2603","input":"Hello","voice":"en_paul_neutral"}`)); err == nil {
		t.Fatal("Mistral silently changed default PCM")
	}
}

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestSpeechNativeContracts(t *testing.T) {
	for _, model := range []string{"x-ai/grok-voice-tts-1.0", "mistralai/voxtral-mini-tts-2603"} {
		t.Run(model, func(t *testing.T) {
			spec := Models[model]
			body, _ := json.Marshal(map[string]any{"model": model, "input": "Hello", "voice": spec.Voices[0], "response_format": "mp3"})
			req, err := Parse(body)
			if err != nil {
				t.Fatal(err)
			}
			audio := "ID3audio-fixture"
			client := New(&http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
				if r.Header.Get("Authorization") != "Bearer managed-key" {
					t.Error("wrong credential")
				}
				var payload map[string]any
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					t.Fatal(err)
				}
				if payload["voice_id"] != spec.Voices[0] {
					t.Fatal("voice mapping")
				}
				response, contentType := audio, "audio/mpeg"
				if spec.Provider == "mistral" {
					if r.URL.String() != "https://api.mistral.ai/v1/audio/speech" || payload["model"] != spec.Upstream || payload["input"] != "Hello" {
						t.Fatal("Mistral contract")
					}
					response = `{"audio_data":"` + base64.StdEncoding.EncodeToString([]byte(audio)) + `"}`
					contentType = "application/json"
				} else if r.URL.String() != "https://api.x.ai/v1/tts" || payload["text"] != "Hello" || payload["language"] != "auto" {
					t.Fatal("xAI contract")
				}
				return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {contentType}}, Body: io.NopCloser(strings.NewReader(response))}, nil
			})}, map[string]string{spec.Provider: "managed-key"})
			result, err := client.Generate(context.Background(), req)
			if err != nil || string(result.Audio) != audio || result.ContentType != "audio/mpeg" {
				t.Fatalf("result: %#v %v", result, err)
			}
		})
	}
}

func TestSpeechRejectsBadUpstreamResponses(t *testing.T) {
	req, _ := Parse([]byte(valid))
	for _, tc := range []struct {
		status      int
		media, body string
	}{
		{200, "application/json", `{"error":"echo private text"}`},
		{200, "audio/mpeg", ""}, {200, "audio/mpeg", "not audio"},
		{302, "audio/mpeg", "ID3"}, {429, "application/json", `{"error":"private text"}`},
	} {
		calls := 0
		client := New(&http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
			calls++
			return &http.Response{StatusCode: tc.status, Header: http.Header{"Content-Type": {tc.media}, "Location": {"https://attacker.invalid"}}, Body: io.NopCloser(strings.NewReader(tc.body))}, nil
		})}, map[string]string{"grok": "secret"})
		_, err := client.Generate(context.Background(), req)
		if err == nil || strings.Contains(err.Error(), "private text") || calls != 1 {
			t.Fatalf("response accepted or leaked: %v calls=%d", err, calls)
		}
	}
}
