package video

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"testing"
)

func TestAtlasCloudH3QuoteQueuePollAndDownload(t *testing.T) {
	request := resolvedVideoRequest(t, CreateRequest{
		Model: "minimax/hailuo-3", Prompt: "move", Duration: 5,
		Resolution: "2K", AspectRatio: "16:9",
	})
	var payload map[string]any
	client := NewAtlasCloudVideoClientAt("atlas-secret", "https://api.atlas.test", &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if req.URL.Host == "media.atlas.test" {
				if req.Header.Get("Authorization") != "" {
					t.Fatal("Atlas key leaked to the output URL")
				}
				return response(http.StatusOK, "video/mp4", "atlas-video"), nil
			}
			if req.Header.Get("Authorization") != "Bearer atlas-secret" {
				t.Fatal("missing Atlas authorization")
			}
			switch req.URL.Path {
			case "/api/v1/model/generateVideo":
				if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
					t.Fatal(err)
				}
				return response(http.StatusOK, "application/json", `{"data":{"id":"atlas-job","status":"created","model":"minimax/h3/text-to-video"}}`), nil
			case "/api/v1/model/prediction/atlas-job":
				return response(http.StatusOK, "application/json", `{"id":"atlas-job","status":"completed","outputs":["https://media.atlas.test/result.mp4"]}`), nil
			default:
				t.Fatalf("unexpected Atlas path %q", req.URL.Path)
				return nil, nil
			}
		}),
	})

	quoted, err := client.QuoteResolved(context.Background(), request)
	if err != nil || quoted != 840_000 {
		t.Fatalf("quote=%d err=%v, want 840000", quoted, err)
	}
	queued, err := client.QueueResolved(context.Background(), request)
	if err != nil || queued.QueueID != "atlas-job" || queued.ProviderModel != "minimax/h3/text-to-video" {
		t.Fatalf("queued=%#v err=%v", queued, err)
	}
	if payload["model"] != "minimax/h3/text-to-video" || payload["prompt"] != "move" ||
		payload["resolution"] != "2K" || payload["duration"] != float64(5) || payload["ratio"] != "16:9" {
		t.Fatalf("bad Atlas payload: %#v", payload)
	}
	poll, err := client.Retrieve(context.Background(), queued.ProviderModel, queued.QueueID)
	if err != nil || poll.State != PollCompleted || poll.DownloadURL != "https://media.atlas.test/result.mp4" {
		t.Fatalf("poll=%#v err=%v", poll, err)
	}
	download, err := client.Download(context.Background(), poll.DownloadURL)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(download.Body)
	download.Body.Close()
	if string(body) != "atlas-video" {
		t.Fatalf("download body=%q", body)
	}
}

func TestAtlasCloudH3SelectsImageAndReferenceContracts(t *testing.T) {
	tests := []struct {
		name    string
		request CreateRequest
		model   string
		keys    []string
	}{
		{
			name: "image",
			request: CreateRequest{Model: "minimax/hailuo-3", Prompt: "move", Duration: 5,
				FrameImages: []FrameImage{
					{FrameType: "first_frame", ImageURL: "https://assets.example/first.png"},
					{FrameType: "last_frame", ImageURL: "https://assets.example/last.png"},
				}},
			model: "minimax/h3/image-to-video",
			keys:  []string{"image", "end_image"},
		},
		{
			name: "reference",
			request: CreateRequest{Model: "minimax/hailuo-3", Prompt: "move", Duration: 5,
				InputReferences: []InputReference{
					{Type: "image", URL: "https://assets.example/reference.png"},
					{Type: "video", URL: "https://assets.example/reference.mp4"},
					{Type: "audio", URL: "https://assets.example/reference.mp3"},
				}},
			model: "minimax/h3/reference-to-video",
			keys:  []string{"refers"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := resolvedVideoRequest(t, tt.request)
			var payload map[string]any
			client := NewAtlasCloudVideoClientAt("atlas-secret", "https://api.atlas.test", &http.Client{
				Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
					if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
						t.Fatal(err)
					}
					return response(http.StatusOK, "application/json", `{"id":"atlas-job","status":"created"}`), nil
				}),
			})
			if _, err := client.QueueResolved(context.Background(), request); err != nil {
				t.Fatal(err)
			}
			if payload["model"] != tt.model || payload["ratio"] != "adaptive" {
				t.Fatalf("bad Atlas mode payload: %#v", payload)
			}
			for _, key := range tt.keys {
				if payload[key] == nil {
					t.Fatalf("Atlas payload missing %q: %#v", key, payload)
				}
			}
			if tt.name == "reference" {
				got := payload["refers"].([]any)
				wantTypes := []string{"image", "video", "audio"}
				gotTypes := make([]string, 0, len(got))
				for _, raw := range got {
					gotTypes = append(gotTypes, raw.(map[string]any)["type"].(string))
				}
				if !reflect.DeepEqual(gotTypes, wantTypes) {
					t.Fatalf("reference types=%v, want %v", gotTypes, wantTypes)
				}
			}
		})
	}
}

func TestAtlasCloudH3SupportAndRegistryOrder(t *testing.T) {
	fourSeconds := resolvedVideoRequest(t, CreateRequest{
		Model: "minimax/hailuo-3", Prompt: "move", Duration: 4,
	})
	fiveSeconds := resolvedVideoRequest(t, CreateRequest{
		Model: "minimax/hailuo-3", Prompt: "move", Duration: 5,
	})
	atlas := NewAtlasCloudVideoClient("atlas", nil)
	if atlas.Supports(fourSeconds) {
		t.Fatal("Atlas documents H3 durations starting at five seconds")
	}
	if !atlas.Supports(fiveSeconds) {
		t.Fatal("Atlas should support a five-second H3 request")
	}
	seed := int64(7)
	withUnsupportedField := *fiveSeconds
	withUnsupportedField.Seed = &seed
	if atlas.Supports(&withUnsupportedField) {
		t.Fatal("Atlas must not silently drop fields outside its published H3 schema")
	}
	registry := NewRegistry(ProviderKeys{MiniMax: "minimax", AtlasCloud: "atlas", Venice: "venice"}, nil)
	providers := registry.Supporting(fiveSeconds)
	got := make([]string, 0, len(providers))
	for _, provider := range providers {
		got = append(got, provider.ID())
	}
	want := []string{"minimax", "atlas-cloud", "venice"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("providers=%v, want %v", got, want)
	}
}
