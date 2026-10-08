package video

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"image"
	"image/png"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

const vertexTestOperation = "projects/proj/locations/us-central1/publishers/google/models/veo-3.1-fast-generate-001/operations/op-1"

func staticToken(context.Context) (string, error) { return "vertex-token", nil }

func TestVertexVeoQueuePollAndInlineVideo(t *testing.T) {
	seed := int64(42)
	request := resolvedVideoRequest(t, CreateRequest{
		Model: "google/veo-3.1-fast", Prompt: "move", NegativePrompt: "blur", Duration: 8,
		Resolution: "1080p", AspectRatio: "9:16", Seed: &seed,
		FrameImages: []FrameImage{{FrameType: "first_frame", ImageURL: "data:image/png;base64," + base64.StdEncoding.EncodeToString([]byte("png"))}},
	})
	request.UpstreamModel = "veo-3.1-fast-generate-001"
	video := []byte("mp4-bytes")
	var queued map[string]any
	var polls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Authorization") != "Bearer vertex-token" {
			t.Errorf("bad request %s auth=%q", r.Method, r.Header.Get("Authorization"))
		}
		base := "/v1/projects/proj/locations/us-central1/publishers/google/models/veo-3.1-fast-generate-001"
		switch r.URL.Path {
		case base + ":predictLongRunning":
			_ = json.NewDecoder(r.Body).Decode(&queued)
			_, _ = io.WriteString(w, `{"name":"`+vertexTestOperation+`"}`)
		case base + ":fetchPredictOperation":
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["operationName"] != vertexTestOperation {
				t.Errorf("operationName=%q", body["operationName"])
			}
			if polls.Add(1) == 1 {
				_, _ = io.WriteString(w, `{"name":"`+vertexTestOperation+`","done":false}`)
				return
			}
			_, _ = io.WriteString(w, `{"name":"x","done":true,"response":{"@type":"type.googleapis.com/cloud.ai.large_models.vision.GenerateVideoResponse","raiMediaFilteredCount":0,"videos":[{"bytesBase64Encoded":"`+
				base64.StdEncoding.EncodeToString(video)+`","mimeType":"video/mp4"}]}}`)
		default:
			t.Errorf("unexpected path %q", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	client := NewVertexVeoClientAt("proj", "us-central1", server.URL, staticToken, server.Client())
	if client.ID() != "google-vertex" || !client.Supports(request) {
		t.Fatal("vertex client should support this request")
	}
	quoted, err := client.QuoteResolved(context.Background(), request)
	if err != nil || quoted != 1_152_000 {
		t.Fatalf("quote=%d err=%v, want 1152000 (same as AI Studio 1080p fast)", quoted, err)
	}
	result, err := client.QueueResolved(context.Background(), request)
	if err != nil || result.QueueID != vertexTestOperation || result.ProviderModel != "veo-3.1-fast-generate-001" {
		t.Fatalf("queued=%#v err=%v", result, err)
	}
	instance := queued["instances"].([]any)[0].(map[string]any)
	image := instance["image"].(map[string]any)
	if instance["prompt"] != "move" || image["mimeType"] != "image/png" || image["bytesBase64Encoded"] == "" {
		t.Fatalf("bad instance: %#v", instance)
	}
	params := queued["parameters"].(map[string]any)
	if params["durationSeconds"] != float64(8) || params["aspectRatio"] != "16:9" || params["resolution"] != "1080p" ||
		params["generateAudio"] != true || params["negativePrompt"] != "blur" || params["seed"] != float64(42) ||
		params["sampleCount"] != float64(1) {
		t.Fatalf("bad parameters: %#v", params)
	}
	if request.AspectRatio != "source" {
		t.Fatalf("image request aspect=%q, want source (derived from the frame upstream)", request.AspectRatio)
	}
	if _, present := params["storageUri"]; present {
		t.Fatal("storageUri must not be sent; video is returned inline")
	}
	poll, err := client.Retrieve(context.Background(), result.ProviderModel, result.QueueID)
	if err != nil || poll.State != PollProcessing {
		t.Fatalf("poll=%#v err=%v", poll, err)
	}
	poll, err = client.Retrieve(context.Background(), result.ProviderModel, result.QueueID)
	if err != nil || poll.State != PollCompleted || poll.ContentType != "video/mp4" {
		t.Fatalf("poll=%#v err=%v", poll, err)
	}
	got, _ := io.ReadAll(poll.Body)
	_ = poll.Body.Close()
	if string(got) != string(video) {
		t.Fatalf("video=%q", got)
	}
}

func TestVertexVeoDefaultsToGAModelAndRejectsUnknownUpstream(t *testing.T) {
	request := resolvedVideoRequest(t, CreateRequest{Model: "google/veo-3.1", Prompt: "p", Duration: 8, Resolution: "720p", AspectRatio: "16:9"})
	var path string
	var payload map[string]any
	client := NewVertexVeoClientAt("proj", "us-central1", "https://vertex.test", staticToken, &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		path = req.URL.Path
		_ = json.NewDecoder(req.Body).Decode(&payload)
		return response(200, "application/json", `{"name":"projects/proj/locations/us-central1/publishers/google/models/veo-3.1-generate-001/operations/o"}`), nil
	})})
	if _, err := client.QueueResolved(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if path != "/v1/projects/proj/locations/us-central1/publishers/google/models/veo-3.1-generate-001:predictLongRunning" {
		t.Fatalf("path=%q", path)
	}
	if payload["parameters"].(map[string]any)["aspectRatio"] != "16:9" {
		t.Fatalf("text request must send aspectRatio: %#v", payload)
	}
	request.UpstreamModel = "veo-3.1-generate-preview/../../x"
	if _, err := client.QueueResolved(context.Background(), request); err == nil {
		t.Fatal("unknown upstream model must be rejected")
	}
}

func TestVertexVeoRejectsForeignOperationNames(t *testing.T) {
	client := NewVertexVeoClientAt("proj", "us-central1", "https://vertex.test", staticToken, &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("no request expected")
		return nil, nil
	})})
	for _, name := range []string{
		"projects/other/locations/us-central1/publishers/google/models/veo-3.1-generate-001/operations/o",
		"projects/proj/locations/us-central1/publishers/google/models/gemini/operations/o",
		"projects/proj/locations/us-central1/publishers/google/models/veo-3.1-generate-001/operations/",
		"operations/o",
	} {
		if _, err := client.Retrieve(context.Background(), "", name); err == nil {
			t.Fatalf("operation %q accepted", name)
		}
	}
}

func TestVertexVeoErrorMapping(t *testing.T) {
	cases := []struct {
		status    int
		body      string
		state     PollState
		retryable bool
		wantErr   bool
	}{
		{status: 200, body: `{"done":true,"error":{"code":3,"message":"bad"}}`, state: PollFailed},
		{status: 200, body: `{"done":true,"response":{"raiMediaFilteredCount":1,"videos":[]}}`, state: PollFailed},
		{status: 200, body: `{"done":true,"response":{"videos":[{"gcsUri":"gs://b/v.mp4"}]}}`, wantErr: true},
		{status: 429, body: `{}`, wantErr: true, retryable: true},
		{status: 400, body: `{}`, wantErr: true},
	}
	for _, tc := range cases {
		client := NewVertexVeoClientAt("proj", "us-central1", "https://vertex.test", staticToken, &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return response(tc.status, "application/json", tc.body), nil
		})})
		poll, err := client.Retrieve(context.Background(), "", vertexTestOperation)
		if tc.wantErr {
			if err == nil {
				t.Fatalf("%d %s: want error", tc.status, tc.body)
			}
			var httpErr *HTTPError
			if tc.status != 200 && (!errors.As(err, &httpErr) || httpErr.Retryable != tc.retryable) {
				t.Fatalf("%d: err=%v", tc.status, err)
			}
			continue
		}
		if err != nil || poll.State != tc.state {
			t.Fatalf("%s: poll=%#v err=%v", tc.body, poll, err)
		}
	}
}

func TestVertexVeoSupportAndRegistryDispatch(t *testing.T) {
	request := resolvedVideoRequest(t, CreateRequest{Model: "google/veo-3.1", Prompt: "p", Duration: 8, Resolution: "720p", AspectRatio: "16:9"})
	if NewVertexVeoClient("", "us-central1", nil).Enabled() {
		t.Fatal("vertex veo must be disabled without a project")
	}
	registry := NewRegistry(ProviderKeys{VertexProject: "proj", VertexLocation: "us-central1"}, nil)
	provider, ok := registry.Provider("google-vertex")
	if !ok || provider.ID() != "google-vertex" || !provider.Supports(request) {
		t.Fatal("registry did not enable google-vertex for Veo")
	}
	if _, ok := registry.Provider("google-ai-studio"); ok {
		t.Fatal("AI Studio must stay disabled without its key")
	}
	if NewRegistry(ProviderKeys{}, nil).Enabled() {
		t.Fatal("registry enabled with no keys")
	}
	other := resolvedVideoRequest(t, CreateRequest{Model: "x-ai/grok-imagine-video", Prompt: "p", Duration: 5, Resolution: "720p", AspectRatio: "16:9"})
	if provider.Supports(other) {
		t.Fatal("vertex veo must not claim non-Veo models")
	}
	reference := *request
	reference.ReferenceImages = []string{"https://x"}
	if provider.Supports(&reference) {
		t.Fatal("reference images are not mapped")
	}
	webp := *request
	webp.FirstFrame = "data:image/webp;base64,AAAA"
	lastOnly := *request
	lastOnly.LastFrame = "data:image/png;base64,AAAA"
	if provider.Supports(&webp) || provider.Supports(&lastOnly) {
		t.Fatal("webp frames and lastFrame without image must be rejected before quoting")
	}
	if !strings.HasPrefix(vertexHost("us-central1"), "us-central1-aiplatform") || vertexHost("global") != "aiplatform.googleapis.com" {
		t.Fatal("vertex host mapping drifted from internal/llm")
	}
}

func pngDataURL(t *testing.T, width, height int) string {
	t.Helper()
	var buf bytes.Buffer
	if err := png.Encode(&buf, image.NewGray(image.Rect(0, 0, width, height))); err != nil {
		t.Fatal(err)
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes())
}

func TestVertexVeoDerivesAspectFromPortraitFirstFrame(t *testing.T) {
	request := resolvedVideoRequest(t, CreateRequest{
		Model: "google/veo-3.1", Prompt: "p", Duration: 8, Resolution: "720p",
		FrameImages: []FrameImage{{FrameType: "first_frame", ImageURL: pngDataURL(t, 9, 16)}},
	})
	var payload map[string]any
	client := NewVertexVeoClientAt("proj", "us-central1", "https://vertex.test", staticToken, &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		_ = json.NewDecoder(req.Body).Decode(&payload)
		return response(200, "application/json", `{"name":"projects/proj/locations/us-central1/publishers/google/models/veo-3.1-generate-001/operations/o"}`), nil
	})})
	if _, err := client.QueueResolved(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if got := payload["parameters"].(map[string]any)["aspectRatio"]; got != "9:16" {
		t.Fatalf("portrait first frame aspectRatio=%v, want 9:16", got)
	}
	if sourceAspectRatio(pngDataURL(t, 16, 9)) != "16:9" || sourceAspectRatio("data:image/png;base64,bm9wZQ==") != "16:9" {
		t.Fatal("landscape/undecodable frames must use 16:9")
	}
}

func TestVertexVeoOversizedResultIsPermanentAndReleasesSlot(t *testing.T) {
	previous := maxVertexVeoBytes
	maxVertexVeoBytes = 16
	defer func() { maxVertexVeoBytes = previous }()
	huge := base64.StdEncoding.EncodeToString(make([]byte, 4*1024*1024))
	client := NewVertexVeoClientAt("proj", "us-central1", "https://vertex.test", staticToken, &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return response(200, "application/json", `{"done":true,"response":{"videos":[{"bytesBase64Encoded":"`+huge+`"}]}}`), nil
	})})
	for i := 0; i < cap(vertexVeoInlineSlots)+1; i++ {
		_, err := client.Retrieve(context.Background(), "", vertexTestOperation)
		var httpErr *HTTPError
		if !errors.As(err, &httpErr) || httpErr.Retryable {
			t.Fatalf("oversized result err=%v, want permanent provider error", err)
		}
	}
	if len(vertexVeoInlineSlots) != 0 {
		t.Fatal("failed retrieval leaked an inline slot")
	}
}

func TestVertexVeoInlineBodyHoldsSlotUntilClosed(t *testing.T) {
	client := NewVertexVeoClientAt("proj", "us-central1", "https://vertex.test", staticToken, &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return response(200, "application/json", `{"done":true,"response":{"videos":[{"bytesBase64Encoded":"bXA0","mimeType":"video/mp4"}]}}`), nil
	})})
	poll, err := client.Retrieve(context.Background(), "", vertexTestOperation)
	if err != nil || len(vertexVeoInlineSlots) != 1 {
		t.Fatalf("err=%v slots=%d", err, len(vertexVeoInlineSlots))
	}
	_ = poll.Body.Close()
	_ = poll.Body.Close()
	if len(vertexVeoInlineSlots) != 0 {
		t.Fatal("closing the body must release exactly one slot")
	}
}
