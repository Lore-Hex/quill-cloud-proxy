package transcription

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestProviderContracts(t *testing.T) {
	for model, spec := range Models {
		t.Run(model, func(t *testing.T) {
			calls, attestations := 0, 0
			client := &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.URL.String() != spec.URL || r.Header.Get("Authorization") != "Bearer private-key" {
					t.Fatal("wrong destination or credential")
				}
				reader, err := r.MultipartReader()
				if err != nil {
					t.Fatal(err)
				}
				fields := map[string]string{}
				for {
					p, err := reader.NextPart()
					if err == io.EOF {
						break
					}
					if err != nil {
						t.Fatal(err)
					}
					b, _ := io.ReadAll(p)
					fields[p.FormName()] = string(b)
				}
				if fields["model"] != spec.Upstream || fields["file"] != "audio-bytes" {
					t.Fatal("lost audio or native model")
				}
				if fields["user"] != "" || fields["trace"] != "" {
					t.Fatal("routing metadata sent upstream")
				}
				if spec.Provider == "mistral" {
					if fields["timestamp_granularities"] != "segment" || fields["response_format"] != "" {
						t.Fatal(fields)
					}
				} else if fields["timestamp_granularities[]"] != "segment" || fields["response_format"] != "verbose_json" {
					t.Fatal(fields)
				}
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"text":"Paris","segments":[],"private_echo":"secret"}`)), Header: http.Header{}}, nil
			})}
			c := New(client, map[string]string{spec.Provider: "private-key"}, func() (*http.Client, error) { attestations++; return client, nil })
			result, err := c.Transcribe(context.Background(), &Request{Model: model, Audio: []byte("audio-bytes"), AudioFormat: "wav", DurationMS: 1000, Format: "verbose_json", Timestamps: []string{"segment"}, User: "private-user"})
			if err != nil || result["text"] != "Paris" || result["private_echo"] != nil || calls != 1 {
				t.Fatalf("result=%v err=%v calls=%d", result, err, calls)
			}
			if (spec.Provider == "tinfoil") != (attestations == 1) {
				t.Fatal("attestation bypass")
			}
		})
	}
}

func TestProviderFailureIsClosedAndRedacted(t *testing.T) {
	for _, scenario := range []string{"attestation", "credentials", "redirect", "429", "malformed", "missing-text", "missing-timestamps", "oversized"} {
		t.Run(scenario, func(t *testing.T) {
			calls := 0
			client := &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				status, body := 200, `{"text":"secret"}`
				switch scenario {
				case "redirect":
					status = 307
				case "429":
					status = 429
				case "malformed":
					body = "secret garbage"
				case "missing-text":
					body = `{}`
				case "oversized":
					body = strings.Repeat("x", (4<<20)+1)
				}
				return &http.Response{StatusCode: status, Header: http.Header{"Location": []string{"https://untrusted.example/"}}, Body: io.NopCloser(strings.NewReader(body))}, nil
			})}
			keys := map[string]string{"tinfoil": "private-key"}
			if scenario == "credentials" {
				keys = nil
			}
			c := New(client, keys, func() (*http.Client, error) {
				if scenario == "attestation" {
					return nil, errors.New("private attestation evidence")
				}
				return client, nil
			})
			_, err := c.Transcribe(context.Background(), &Request{Model: "openai/whisper-large-v3-turbo", Audio: []byte("audio"), AudioFormat: "wav", Format: "verbose_json", Timestamps: []string{"segment"}})
			if err == nil || strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "private") {
				t.Fatalf("unsafe failure: %v", err)
			}
			if (scenario == "credentials" || scenario == "attestation") && calls != 0 {
				t.Fatal("sent before verification")
			}
			if calls > 1 {
				t.Fatal("redirect followed")
			}
		})
	}
}
