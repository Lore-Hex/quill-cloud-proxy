package video

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

func TestFALH3MaxTextQuoteQueueAndInlineResult(t *testing.T) {
	request := resolvedVideoRequest(t, CreateRequest{
		Model: "minimax/h3-max", Prompt: "move", Duration: 5,
		Resolution: "768p", AspectRatio: "16:9",
	})
	videoBytes := []byte("mp4-video")
	encodedVideo := base64.StdEncoding.EncodeToString(videoBytes)
	var queuedPayload map[string]any
	client := NewFALVideoClient("fal-secret", &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Header.Get("Authorization") != "Key fal-secret" {
			t.Fatal("missing fal authorization")
		}
		switch req.URL.Path {
		case "/minimax/h3-max/text-to-video":
			if err := json.NewDecoder(req.Body).Decode(&queuedPayload); err != nil {
				t.Fatal(err)
			}
			return response(200, "application/json", `{"request_id":"fal-job-1"}`), nil
		case "/minimax/h3-max/requests/fal-job-1/status":
			return response(200, "application/json", `{"status":"COMPLETED"}`), nil
		case "/minimax/h3-max/requests/fal-job-1":
			payload, _ := json.Marshal(map[string]any{"video": map[string]any{
				"url":          "data:video/mp4;base64," + encodedVideo,
				"content_type": "video/mp4", "file_size": len(videoBytes),
			}})
			return response(200, "application/json", string(payload)), nil
		default:
			t.Fatalf("unexpected fal path %q", req.URL.Path)
			return nil, nil
		}
	})})

	quoted, err := client.QuoteResolved(context.Background(), request)
	if err != nil || quoted != 480_000 {
		t.Fatalf("quote=%d err=%v, want 480000", quoted, err)
	}
	queued, err := client.QueueResolved(context.Background(), request)
	if err != nil || queued.QueueID != "fal-job-1" || queued.ProviderModel != "minimax/h3-max/text-to-video" {
		t.Fatalf("queued=%#v err=%v", queued, err)
	}
	if queuedPayload["duration"] != float64(5) || queuedPayload["resolution"] != "768P" ||
		queuedPayload["aspect_ratio"] != "16:9" || queuedPayload["sync_mode"] != true {
		t.Fatalf("bad fal payload: %#v", queuedPayload)
	}
	poll, err := client.Retrieve(context.Background(), queued.ProviderModel, queued.QueueID)
	if err != nil || poll.State != PollCompleted || poll.Body == nil || poll.DownloadURL != "" {
		t.Fatalf("poll=%#v err=%v", poll, err)
	}
	got, err := io.ReadAll(poll.Body)
	poll.Body.Close()
	if err != nil || string(got) != string(videoBytes) {
		t.Fatalf("video=%q err=%v", got, err)
	}
}

func TestFALH3MaxImageUsesImageEndpointWithoutAspect(t *testing.T) {
	request := resolvedVideoRequest(t, CreateRequest{
		Model: "minimax/h3-max", Prompt: "move", Duration: 5, Resolution: "480p",
		FrameImages: []FrameImage{
			{FrameType: "first_frame", ImageURL: "https://assets.example/first.png"},
			{FrameType: "last_frame", ImageURL: "https://assets.example/last.png"},
		},
	})
	var payload map[string]any
	client := NewFALVideoClient("fal-secret", &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path != "/minimax/h3-max/image-to-video" {
			t.Fatalf("unexpected fal path %q", req.URL.Path)
		}
		if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		return response(200, "application/json", `{"request_id":"fal-image-job"}`), nil
	})})
	quoted, err := client.QuoteResolved(context.Background(), request)
	if err != nil || quoted != 300_000 {
		t.Fatalf("quote=%d err=%v, want 300000", quoted, err)
	}
	queued, err := client.QueueResolved(context.Background(), request)
	if err != nil || queued.ProviderModel != "minimax/h3-max/image-to-video" {
		t.Fatalf("queued=%#v err=%v", queued, err)
	}
	if payload["image_url"] != "https://assets.example/first.png" ||
		payload["end_image_url"] != "https://assets.example/last.png" {
		t.Fatalf("bad image payload: %#v", payload)
	}
	if _, present := payload["aspect_ratio"]; present {
		t.Fatalf("image request included aspect ratio: %#v", payload)
	}
}

func TestFALH3MaxRejectsReferencesAndMalformedInlineVideo(t *testing.T) {
	referenceRequest := resolvedVideoRequest(t, CreateRequest{Model: "minimax/h3-max", Prompt: "move"})
	referenceRequest.ReferenceImages = []string{"https://assets.example/ref.png"}
	client := NewFALVideoClient("fal-secret", nil)
	if client.Supports(referenceRequest) {
		t.Fatal("reference mode must remain disabled until variable input billing is supported")
	}

	client = NewFALVideoClient("fal-secret", &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path == "/minimax/h3-max/requests/fal-bad/status" {
			return response(200, "application/json", `{"status":"COMPLETED"}`), nil
		}
		return response(200, "application/json", `{"video":{"url":"https://cdn.example/video.mp4","content_type":"video/mp4","file_size":10}}`), nil
	})})
	_, err := client.Retrieve(context.Background(), "minimax/h3-max/text-to-video", "fal-bad")
	var httpErr *HTTPError
	if err == nil || !AsHTTPError(err, &httpErr) || httpErr.Retryable {
		t.Fatal("non-inline fal result must fail closed")
	}
}
