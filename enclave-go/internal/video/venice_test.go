package video

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

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return fn(req) }

func response(status int, contentType, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": []string{contentType}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func TestQuoteUsesDirectVeniceAndExactFivePercentIntegerMarkup(t *testing.T) {
	client := NewVeniceClient("venice-secret", &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.String() != "https://api.venice.ai/api/v1/video/quote" {
			t.Fatalf("unexpected provider URL %q", req.URL.String())
		}
		if req.Header.Get("Authorization") != "Bearer venice-secret" {
			t.Fatal("missing Venice authorization")
		}
		var payload map[string]any
		if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		if _, found := payload["prompt"]; found {
			t.Fatalf("quote payload contains prompt: %#v", payload)
		}
		return response(200, "application/json", `{"quote":0.81}`), nil
	})})

	quoted, err := client.Quote(context.Background(), map[string]any{
		"model": "minimax-h3-text-to-video", "duration": "5s", "resolution": "2K",
	})
	if err != nil {
		t.Fatal(err)
	}
	if quoted != 850_500 {
		t.Fatalf("quoted microdollars = %d, want 850500", quoted)
	}
}

func TestQueueRetrieveDownloadAndComplete(t *testing.T) {
	requests := make([]string, 0, 4)
	client := NewVeniceClient("venice-secret", &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		requests = append(requests, req.Method+" "+req.URL.String())
		switch req.URL.Path {
		case "/api/v1/video/queue":
			return response(200, "application/json", `{"model":"minimax-h3-text-to-video","queue_id":"queue-1"}`), nil
		case "/api/v1/video/retrieve":
			return response(200, "application/json", `{"status":"COMPLETED","download_url":"https://media.example/video.mp4?signature=secret"}`), nil
		case "/video.mp4":
			if req.Header.Get("Authorization") != "" {
				t.Fatal("provider API key leaked to pre-signed media host")
			}
			return response(200, "video/mp4", "video-bytes"), nil
		case "/api/v1/video/complete":
			return response(200, "application/json", `{"success":true}`), nil
		default:
			t.Fatalf("unexpected request path %q", req.URL.Path)
			return nil, nil
		}
	})})

	queued, err := client.Queue(context.Background(), map[string]any{"model": "minimax-h3-text-to-video", "prompt": "private"})
	if err != nil || queued.QueueID != "queue-1" {
		t.Fatalf("queue result=%#v err=%v", queued, err)
	}
	poll, err := client.Retrieve(context.Background(), queued.ProviderModel, queued.QueueID)
	if err != nil || poll.State != PollCompleted || poll.DownloadURL == "" || poll.Body != nil {
		t.Fatalf("poll result=%#v err=%v", poll, err)
	}
	download, err := client.Download(context.Background(), poll.DownloadURL)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(download.Body)
	download.Body.Close()
	if !bytes.Equal(body, []byte("video-bytes")) {
		t.Fatalf("download body = %q", body)
	}
	if err := client.Complete(context.Background(), queued.ProviderModel, queued.QueueID); err != nil {
		t.Fatal(err)
	}
	if len(requests) != 4 {
		t.Fatalf("request count = %d: %#v", len(requests), requests)
	}
}

func TestCompleteFallsBackToDeleteOnRetrieveAfterProviderBadRequest(t *testing.T) {
	requests := 0
	client := NewVeniceClient("venice-secret", &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		requests++
		switch req.URL.Path {
		case "/api/v1/video/complete":
			return response(400, "application/json", `{"error":"Request ID is invalid."}`), nil
		case "/api/v1/video/retrieve":
			var payload map[string]any
			if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			if payload["delete_media_on_completion"] != true {
				t.Fatalf("cleanup retrieve payload = %#v", payload)
			}
			return response(200, "video/mp4", "provider-copy"), nil
		default:
			t.Fatalf("unexpected path %q", req.URL.Path)
			return nil, nil
		}
	})})
	if err := client.Complete(context.Background(), "minimax-h3-text-to-video", "queue-1"); err != nil {
		t.Fatal(err)
	}
	if requests != 2 {
		t.Fatalf("request count = %d, want 2", requests)
	}
}

func TestCompleteFallbackTreatsMissingMediaAsCleaned(t *testing.T) {
	client := NewVeniceClient("venice-secret", &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path == "/api/v1/video/complete" {
			return response(400, "application/json", `{"error":"Request ID is invalid."}`), nil
		}
		return response(404, "application/json", `{"error":"record not found"}`), nil
	})})
	if err := client.Complete(context.Background(), "model", "queue-1"); err != nil {
		t.Fatal(err)
	}
}

func TestCompleteDoesNotHideRetryableProviderFailure(t *testing.T) {
	requests := 0
	client := NewVeniceClient("venice-secret", &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		requests++
		return response(503, "application/json", `{"error":"unavailable"}`), nil
	})})
	err := client.Complete(context.Background(), "model", "queue-1")
	var httpErr *HTTPError
	if !errors.As(err, &httpErr) || !httpErr.Retryable || httpErr.Status != 503 {
		t.Fatalf("error = %#v", err)
	}
	if requests != 1 {
		t.Fatalf("request count = %d, want 1", requests)
	}
}

func TestRetrieveStreamsVideoWithoutBuffering(t *testing.T) {
	client := NewVeniceClient("secret", &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return response(200, "video/mp4", "streamed-video"), nil
	})})
	result, err := client.Retrieve(context.Background(), "model", "job")
	if err != nil {
		t.Fatal(err)
	}
	if result.State != PollCompleted || result.Body == nil {
		t.Fatalf("result = %#v", result)
	}
	body, _ := io.ReadAll(result.Body)
	result.Body.Close()
	if string(body) != "streamed-video" {
		t.Fatalf("body = %q", body)
	}
}

func TestDownloadRejectsUnsafeURLs(t *testing.T) {
	client := NewVeniceClient("secret", &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		t.Fatal("unsafe URL reached transport")
		return nil, nil
	})})
	for _, rawURL := range []string{
		"http://media.example/a.mp4",
		"https://127.0.0.1/a.mp4",
		"https://metadata.google.internal/a.mp4",
		"https://user:password@media.example/a.mp4",
	} {
		if _, err := client.Download(context.Background(), rawURL); err == nil {
			t.Fatalf("expected rejection for %q", rawURL)
		}
	}
}

func TestDollarParsingAndMarkupBoundaryCases(t *testing.T) {
	tests := map[string]int{
		"0":           0,
		"0.000001":    1,
		"1.234567":    1_234_567,
		"1.234567001": 1_234_568,
		"81":          81_000_000,
	}
	for raw, want := range tests {
		got, err := dollarsToMicrodollars(raw)
		if err != nil || got != want {
			t.Fatalf("dollarsToMicrodollars(%q) = %d, %v; want %d", raw, got, err, want)
		}
	}
	for _, raw := range []string{"", "-1", "1e3", "1.2.3", "NaN", strings.Repeat("9", 100)} {
		if _, err := dollarsToMicrodollars(raw); err == nil {
			t.Fatalf("expected invalid amount for %q", raw)
		}
	}
}
