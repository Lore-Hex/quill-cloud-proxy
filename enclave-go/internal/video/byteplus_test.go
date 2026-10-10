package video

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func bytePlusRequest(t *testing.T, model string) *ResolvedRequest {
	t.Helper()
	r, err := ResolveRequest(&CreateRequest{Model: model, Prompt: "A blue cube", Duration: 4, Resolution: "480p"})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestBytePlusNativeLifecycleAndUsage(t *testing.T) {
	for public, native := range bytePlusVideoModels {
		t.Run(public, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer test-only" {
					t.Error("missing auth")
				}
				switch r.Method {
				case http.MethodPost:
					var body map[string]any
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
						t.Fatal(err)
					}
					if r.URL.Path != "/contents/generations/tasks" || body["model"] != native || body["duration"] != float64(4) {
						t.Errorf("bad queue: %#v", body)
					}
					if body["seed"] != float64(1101) {
						t.Errorf("seed not forwarded: %#v", body)
					}
					fmt.Fprint(w, `{"id":"cgt-test"}`)
				case http.MethodGet:
					fmt.Fprintf(w, `{"id":"cgt-test","model":%q,"status":"succeeded","usage":{"completion_tokens":38830},"content":{"video_url":"https://%s/test.mp4"}}`, native, bytePlusVideoCDN)
				case http.MethodDelete:
					w.WriteHeader(204)
				default:
					t.Fatal(r.Method)
				}
			}))
			defer server.Close()
			client := NewBytePlusClientAt("test-only", server.URL, server.Client())
			r := bytePlusRequest(t, public)
			seed := int64(1101)
			r.Seed = &seed
			if quote, err := client.QuoteResolved(context.Background(), r); err != nil || quote != 0 {
				t.Fatalf("quote %d %v", quote, err)
			}
			if limit, err := client.OutputTokenLimit(r); err != nil || limit != 80_000 {
				t.Fatalf("bound %d %v", limit, err)
			}
			job, err := client.QueueResolved(context.Background(), r)
			if err != nil {
				t.Fatal(err)
			}
			result, err := client.Retrieve(context.Background(), job.ProviderModel, job.QueueID)
			if err != nil {
				t.Fatal(err)
			}
			if result.State != PollCompleted || result.OutputTokens != 38_830 {
				t.Fatalf("bad usage %+v", result)
			}
			if err := client.Complete(context.Background(), native, job.QueueID); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestBytePlusRejectsWrongTariffBeforeSending(t *testing.T) {
	c := NewBytePlusClient("test-only", nil)
	for _, change := range []func(*ResolvedRequest){
		func(r *ResolvedRequest) { r.Resolution = "1080p" },
		func(r *ResolvedRequest) { r.DurationSeconds = 30 },
		func(r *ResolvedRequest) { r.VideoReference = "https://example.com/a.mp4" },
		func(r *ResolvedRequest) { r.AudioReference = "https://example.com/a.mp3" },
		func(r *ResolvedRequest) { r.NegativePrompt = "extra" },
		func(r *ResolvedRequest) { r.LastFrame = "https://example.com/a.png" },
	} {
		r := bytePlusRequest(t, "bytedance/seedance-2.5")
		change(r)
		if c.Supports(r) {
			t.Fatal("unsupported tariff accepted")
		}
		if _, err := c.QueueResolved(context.Background(), r); err == nil {
			t.Fatal("queued unsupported mode")
		}
	}
}

func TestBytePlusInvalidUsageAndIdentityFailClosed(t *testing.T) {
	for _, usage := range []string{`{}`, `{"completion_tokens":0}`, `{"completion_tokens":-1}`, `{"completion_tokens":1.5}`, `{"completion_tokens":"10"}`, `{"completion_tokens":2000001}`} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, `{"id":"cgt-test","model":"native","status":"succeeded","usage":%s,"content":{"video_url":"https://%s/a.mp4"}}`, usage, bytePlusVideoCDN)
		}))
		c := NewBytePlusClientAt("test-only", server.URL, server.Client())
		if _, err := c.Retrieve(context.Background(), "native", "cgt-test"); err == nil {
			t.Fatalf("invalid usage accepted %s", usage)
		}
		if _, err := c.Retrieve(context.Background(), "wrong-model", "cgt-test"); err == nil {
			t.Fatal("wrong identity accepted")
		}
		server.Close()
	}
}

type bytePlusTestTransport func(*http.Request) (*http.Response, error)

func (f bytePlusTestTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestBytePlusDownloadNoCredentialsAndRedirectAllowlist(t *testing.T) {
	for _, redirect := range []bool{false, true} {
		calls := 0
		httpc := &http.Client{Transport: bytePlusTestTransport(func(r *http.Request) (*http.Response, error) {
			calls++
			if r.Header.Get("Authorization") != "" || r.URL.Hostname() != bytePlusVideoCDN {
				t.Fatal("unsafe download")
			}
			if redirect {
				return &http.Response{StatusCode: 302, Header: http.Header{"Location": {"https://example.com/stolen"}}, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
			}
			return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"video/mp4"}}, Body: io.NopCloser(strings.NewReader("video")), Request: r}, nil
		})}
		c := NewBytePlusClient("never-send", httpc)
		result, err := c.Download(context.Background(), "https://"+bytePlusVideoCDN+"/video")
		if (err != nil) != redirect {
			t.Fatalf("redirect=%t err=%v", redirect, err)
		}
		if result != nil {
			result.Body.Close()
		}
		if calls != 1 {
			t.Fatal("followed unsafe redirect")
		}
		if _, err := c.Download(context.Background(), "https://example.com/a"); err == nil {
			t.Fatal("bad host accepted")
		}
	}
}
