package speech

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestTinfoilSpeechVerifiedTransport(t *testing.T) {
	for model, native := range map[string]string{"qwen/qwen3-tts": "qwen3-tts", "mistralai/voxtral-4b-tts-2603": "voxtral-tts"} {
		t.Run(model, func(t *testing.T) {
			plain := &http.Client{Transport: roundTrip(func(*http.Request) (*http.Response, error) {
				t.Fatal("confidential speech used plain HTTPS")
				return nil, nil
			})}
			raw, _ := json.Marshal(map[string]any{"model": model, "input": "Private words", "voice": Models[model].Voices[0]})
			req, err := Parse(raw)
			if err != nil {
				t.Fatal(err)
			}
			for _, scenario := range []string{"valid", "missing-verifier", "invalid-attestation", "nil-client", "plain-client", "provider-error", "truncated", "wrong-type", "empty", "redirect", "cancelled"} {
				t.Run(scenario, func(t *testing.T) {
					called := 0
					verified := &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
						called++
						if r.URL.String() != "https://inference.tinfoil.sh/v1/audio/speech" || r.Header.Get("Authorization") != "Bearer key" {
							t.Fatal("wrong upstream")
						}
						var p map[string]any
						if json.NewDecoder(r.Body).Decode(&p) != nil || len(p) != 3 || p["model"] != native || p["input"] != req.Input || p["voice"] != req.Voice {
							t.Fatal("wrong payload")
						}
						data, media, status := wavFixture(), "audio/wav", 200
						if scenario == "truncated" {
							data = data[:len(data)-1]
						}
						if scenario == "empty" {
							data = nil
						}
						if scenario == "wrong-type" {
							media = "application/json"
						}
						if scenario == "provider-error" {
							status = 500
							data = []byte("Private words")
						}
						if scenario == "redirect" {
							status = 307
						}
						return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {media}, "Location": {"https://elsewhere.invalid"}}, Body: io.NopCloser(bytes.NewReader(data)), Request: r}, nil
					})}
					client := New(plain, map[string]string{"tinfoil": "key"})
					if scenario != "missing-verifier" {
						client.WithTinfoilAttestation(func() (*http.Client, error) {
							if scenario == "invalid-attestation" {
								return nil, errors.New("Private words")
							}
							if scenario == "nil-client" {
								return nil, nil
							}
							if scenario == "plain-client" {
								return http.DefaultClient, nil
							}
							return verified, nil
						})
					}
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					if scenario == "cancelled" {
						cancel()
					}
					result, err := client.Generate(ctx, req)
					if scenario == "valid" {
						if err != nil || !bytes.Equal(result.Audio, wavFixture()) || result.ContentType != "audio/wav" || result.InputTokens != 0 || result.OutputTokens != 0 {
							t.Fatalf("invalid audio result: %v", err)
						}
					} else if err == nil || result != nil || strings.Contains(err.Error(), "Private words") {
						t.Fatal("failure returned audio or leaked content")
					}
					if called > 1 {
						t.Fatal("followed a redirect")
					}
					if (scenario == "cancelled" || scenario == "invalid-attestation" || scenario == "nil-client" || scenario == "plain-client" || scenario == "missing-verifier") && called != 0 {
						t.Fatal("sent text before verification")
					}
					if verified.Timeout != 0 || verified.CheckRedirect != nil {
						t.Fatal("mutated shared verified client")
					}
				})
			}
		})
	}
}

func TestTinfoilSpeechAdmission(t *testing.T) {
	for model, voices := range map[string][]string{
		"qwen/qwen3-tts":                strings.Fields("aiden dylan eric ono_anna ryan serena sohee uncle_fu vivian"),
		"mistralai/voxtral-4b-tts-2603": strings.Fields("neutral_female neutral_male casual_female casual_male cheerful_female ar_male de_female de_male es_female es_male fr_female fr_male hi_female hi_male it_female it_male nl_female nl_male pt_female pt_male"),
	} {
		t.Run(model, func(t *testing.T) {
			for _, voice := range voices {
				body, _ := json.Marshal(map[string]any{"model": model, "input": "Hello", "voice": voice})
				req, err := Parse(body)
				if err != nil {
					t.Fatal(err)
				}
				if req.Format != "wav" {
					t.Fatal("Tinfoil must default to WAV")
				}
			}
			for _, change := range []map[string]any{
				{"voice": "alloy"}, {"response_format": "pcm"}, {"response_format": "mp3"},
				{"speed": 1.1}, {"input": strings.Repeat("a", 4097)}, {"input": ""},
				{"provider": map[string]any{"options": map[string]any{"reference_audio": "https://invalid"}}},
			} {
				p := map[string]any{"model": model, "input": "Hello", "voice": voices[0]}
				for k, v := range change {
					p[k] = v
				}
				body, _ := json.Marshal(p)
				if _, err := Parse(body); err == nil {
					t.Fatalf("accepted unsupported option: %v", change)
				}
			}
		})
	}
}
