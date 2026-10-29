package video

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestRunwayKling4QuoteRoundsWholeCreditsBeforeFee(t *testing.T) {
	client := NewRunwayClient("key", nil)
	for _, tc := range []struct {
		resolution string
		duration   int
		want       int
	}{
		{"720p", 3, 576_000}, // ceil(3 * 15.7) credits * $0.01 * 1.2
		{"720p", 5, 948_000},
		{"720p", 30, 5_652_000},
		{"1080p", 3, 852_000},
		{"1080p", 5, 1_416_000},
		{"1080p", 30, 8_460_000},
	} {
		request := resolvedVideoRequest(t, CreateRequest{Model: "kling/v4", Prompt: "private prompt", Duration: tc.duration, Resolution: tc.resolution})
		quote, err := client.QuoteResolved(context.Background(), request)
		if err != nil || quote != tc.want {
			t.Fatalf("%s %ds: quote=%d err=%v want=%d", tc.resolution, tc.duration, quote, err, tc.want)
		}
	}
}

func TestRunwayKling4NativePayload(t *testing.T) {
	for _, tc := range []struct {
		resolution, aspect, ratio string
		image, last               bool
	}{
		{"720p", "16:9", "1280:720", false, false},
		{"720p", "9:16", "720:1280", false, false},
		{"720p", "1:1", "940:940", false, false},
		{"720p", "21:9", "1460:624", false, false},
		{"1080p", "16:9", "1920:1080", false, false},
		{"1080p", "9:16", "1080:1920", false, false},
		{"1080p", "1:1", "1440:1440", false, false},
		{"1080p", "21:9", "2200:940", false, false},
		{"720p", "16:9", "auto_720p", true, false},
		{"1080p", "16:9", "auto_1080p", true, true},
	} {
		req := CreateRequest{Model: "kling/v4", Prompt: "private prompt", Resolution: tc.resolution, AspectRatio: tc.aspect, Duration: 3}
		if tc.image {
			req.FrameImages = []FrameImage{{FrameType: "first", URL: "https://assets.example/first.png"}}
		}
		if tc.last {
			req.FrameImages = append(req.FrameImages, FrameImage{FrameType: "last", URL: "https://assets.example/last.png"})
		}
		resolved := resolvedVideoRequest(t, req)
		client := NewRunwayClient("test-key", &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			path := "/v1/text_to_video"
			if tc.image {
				path = "/v1/image_to_video"
			}
			if r.URL.Path != path || r.Header.Get("Authorization") != "Bearer test-key" || r.Header.Get("X-Runway-Version") != "2024-11-06" {
				t.Fatal("incorrect native path or authentication")
			}
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			if payload["model"] != "kling_4" || payload["ratio"] != tc.ratio || payload["duration"] != float64(3) || payload["promptText"] != req.Prompt {
				t.Fatalf("wrong payload: %#v", payload)
			}
			wantFields := 4
			if tc.image {
				wantFields++
				if tc.last {
					frames := payload["promptImage"].([]any)
					if len(frames) != 2 || frames[0].(map[string]any)["position"] != "first" || frames[1].(map[string]any)["uri"] != "https://assets.example/last.png" {
						t.Fatalf("wrong frames: %#v", frames)
					}
				} else if payload["promptImage"] != "https://assets.example/first.png" {
					t.Fatal("lost first frame")
				}
			}
			if len(payload) != wantFields {
				t.Fatalf("unexpected fields sent to strict upstream: %#v", payload)
			}
			return response(200, "application/json", `{"id":"kling4-job"}`), nil
		})})
		queued, err := client.QueueResolved(context.Background(), resolved)
		if err != nil || queued.ProviderModel != "kling_4" {
			t.Fatalf("queued=%#v err=%v", queued, err)
		}
	}
}

func TestKling4RejectsUnsupportedInputsBeforeQueue(t *testing.T) {
	client := NewRunwayClient("key", nil)
	zero := int64(0)
	for _, mutate := range []func(*CreateRequest){
		func(r *CreateRequest) { r.Duration = 2 },
		func(r *CreateRequest) { r.Duration = 31 },
		func(r *CreateRequest) { r.Resolution = "4k" },
		func(r *CreateRequest) { r.AspectRatio = "4:3" },
		func(r *CreateRequest) { r.Prompt = strings.Repeat("a", 26_001) },
		func(r *CreateRequest) { off := false; r.GenerateAudio = &off },
		func(r *CreateRequest) { r.Seed = &zero },
		func(r *CreateRequest) { r.NegativePrompt = "no" },
		func(r *CreateRequest) {
			r.FrameImages = []FrameImage{{FrameType: "last", URL: "https://assets.example/a.png"}}
		},
		func(r *CreateRequest) {
			r.InputReferences = []InputReference{{Type: "video", URL: "https://assets.example/a.mp4"}}
		},
		func(r *CreateRequest) {
			r.InputReferences = []InputReference{{Type: "image", URL: "https://assets.example/a.png"}}
		},
	} {
		req := CreateRequest{Model: "kling/v4", Prompt: "test"}
		mutate(&req)
		resolved, err := ResolveRequest(&req)
		if err == nil && client.Supports(resolved) {
			t.Fatalf("unsupported input accepted: %#v", req)
		}
	}
}

func TestKling4DirectOnlyAndContentFreeQuote(t *testing.T) {
	model, _, quote, err := Resolve(&CreateRequest{Model: "kling/v4", Prompt: "PRIVATE"})
	if err != nil || !model.DirectOnly || !model.AudioAlwaysOn || directProviderForModel(model.ID) != "runway" {
		t.Fatalf("model=%#v err=%v", model, err)
	}
	encoded, _ := json.Marshal(quote)
	if strings.Contains(string(encoded), "PRIVATE") {
		t.Fatal("quote leaked prompt")
	}
	body, err := ModelsJSON(nil)
	if err != nil {
		t.Fatal(err)
	}
	var public struct {
		Data []struct {
			ID            string `json:"id"`
			TrustedRouter struct {
				AudioMode string   `json:"audio_mode"`
				Providers []string `json:"provider_routes"`
			} `json:"trustedrouter"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &public); err != nil {
		t.Fatal(err)
	}
	for _, row := range public.Data {
		if row.ID == "kling/v4" {
			if row.TrustedRouter.AudioMode != "always" || strings.Join(row.TrustedRouter.Providers, ",") != "runway" {
				t.Fatalf("unqualified route or audio toggle advertised: %#v", row)
			}
			return
		}
	}
	t.Fatal("Kling 4.0 missing from video catalog")
}
