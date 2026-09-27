package video

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSeedance25ModesAndContentFreeQuotes(t *testing.T) {
	for _, mode := range []string{"text", "image", "reference", "audio"} {
		t.Run(mode, func(t *testing.T) {
			req := &CreateRequest{Model: "bytedance/seedance-2.5", Prompt: "PRIVATE prompt", Duration: 30, Resolution: "1080p", GenerateAudio: boolPointer(false)}
			want := "seedance-2-5-text-to-video-basic"
			switch mode {
			case "image":
				req.FrameImages = []FrameImage{{ImageURL: "https://assets.example/PRIVATE.png"}}
				want = "seedance-2-5-image-to-video-basic"
			case "reference", "audio":
				req.InputReferences = []InputReference{{Type: mode, URL: "https://assets.example/PRIVATE"}}
				if mode == "reference" {
					req.InputReferences[0].Type = "image"
				}
				want = "seedance-2-5-reference-to-video-basic"
			}
			resolved, err := ResolveRequest(req)
			if err != nil {
				t.Fatal(err)
			}
			queue, quote := resolved.VeniceQueuePayload(), resolved.VeniceQuotePayload()
			if queue["model"] != want || quote["model"] != want || queue["duration"] != "30s" || quote["audio"] != false || quote["resolution"] != "1080p" {
				t.Fatalf("incorrect queue/quote: %#v / %#v", queue, quote)
			}
			if mode == "image" && (queue["aspect_ratio"] != nil || quote["aspect_ratio"] != nil) {
				t.Fatal("image-to-video aspect ratio must come from the source image")
			}
			encoded, _ := json.Marshal(quote)
			if strings.Contains(string(encoded), "PRIVATE") || strings.Contains(string(encoded), "assets.example") {
				t.Fatal("quote contains caller content")
			}
		})
	}
}

func TestSeedance25Constraints(t *testing.T) {
	for _, resolution := range []string{"480p", "720p", "1080p"} {
		for _, duration := range []int{4, 30} {
			if _, err := ResolveRequest(&CreateRequest{Model: "bytedance/seedance-2.5", Prompt: strings.Repeat("a", 15_000), Duration: duration, Resolution: resolution}); err != nil {
				t.Fatalf("valid %s/%ds request: %v", resolution, duration, err)
			}
		}
	}
	for _, invalid := range []CreateRequest{
		{Duration: 3}, {Duration: 31}, {Resolution: "2160p"}, {AspectRatio: "2:3"},
		{Prompt: strings.Repeat("a", 15_001)},
		{InputReferences: []InputReference{{Type: "video", URL: "https://assets.example/video.mp4"}}},
	} {
		invalid.Model = "bytedance/seedance-2.5"
		if invalid.Prompt == "" {
			invalid.Prompt = "move"
		}
		if _, err := ResolveRequest(&invalid); err == nil {
			t.Fatalf("accepted unsupported request: %#v", invalid)
		}
	}
}
