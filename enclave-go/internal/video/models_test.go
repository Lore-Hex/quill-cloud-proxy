package video

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestVideoModelsIncludeLaunchAndExpansionSet(t *testing.T) {
	want := map[string]bool{
		"bytedance/seedance-2.0":      false,
		"bytedance/seedance-2.0-fast": false,
		"google/veo-3.1":              false,
		"google/veo-3.1-fast":         false,
		"openai/sora-2":               false,
		"openai/sora-2-pro":           false,
		"runway/gen-4.5":              false,
		"kling/v3-pro":                false,
		"kling/o3-pro":                false,
		"alibaba/wan-2.7":             false,
		"shengshu/vidu-q3":            false,
		"pixverse/c1":                 false,
		"lightricks/ltx-2.3":          false,
		"lightricks/ltx-2.3-fast":     false,
		"google/gemini-omni-flash":    false,
		"minimax/hailuo-3":            false,
		"x-ai/grok-imagine-video":     false,
	}
	for _, model := range Models() {
		if _, ok := want[model.ID]; !ok {
			t.Fatalf("unexpected launch model %q", model.ID)
		}
		want[model.ID] = true
		if model.ID == "minimax/hailuo-3" && model.Name != "MiniMax Hailuo 3 (H3)" {
			t.Fatalf("H3 display name = %q", model.Name)
		}
	}
	for id, seen := range want {
		if !seen {
			t.Fatalf("missing launch model %q", id)
		}
	}
}

func TestResolveExpandedModelsUsesExactDirectProviderIDs(t *testing.T) {
	tests := []struct {
		model string
		want  string
	}{
		{model: "google/veo-3.1", want: "veo3.1-full-text-to-video"},
		{model: "google/veo-3.1-fast", want: "veo3.1-fast-text-to-video"},
		{model: "openai/sora-2", want: "sora-2-text-to-video"},
		{model: "openai/sora-2-pro", want: "sora-2-pro-text-to-video"},
		{model: "runway/gen-4.5", want: "runway-gen4-5-text"},
		{model: "kling/v3-pro", want: "kling-v3-pro-text-to-video"},
		{model: "kling/o3-pro", want: "kling-o3-pro-text-to-video"},
		{model: "alibaba/wan-2.7", want: "wan-2-7-text-to-video"},
		{model: "shengshu/vidu-q3", want: "vidu-q3-text-to-video"},
		{model: "pixverse/c1", want: "pixverse-c1-text-to-video"},
		{model: "x-ai/grok-imagine-video", want: "grok-imagine-video"},
	}
	for _, tc := range tests {
		t.Run(tc.model, func(t *testing.T) {
			_, queue, quote, err := Resolve(&CreateRequest{Model: tc.model, Prompt: "move"})
			if err != nil {
				t.Fatal(err)
			}
			if queue["model"] != tc.want || quote["model"] != tc.want {
				t.Fatalf("models queue=%#v quote=%#v, want %q", queue["model"], quote["model"], tc.want)
			}
		})
	}
}

func TestResolveExpandedModelsUsesExactImageProviderIDs(t *testing.T) {
	tests := []struct {
		model string
		want  string
	}{
		{model: "google/veo-3.1", want: "veo3.1-full-image-to-video"},
		{model: "google/veo-3.1-fast", want: "veo3.1-fast-image-to-video"},
		{model: "openai/sora-2", want: "sora-2-image-to-video"},
		{model: "openai/sora-2-pro", want: "sora-2-pro-image-to-video"},
		{model: "runway/gen-4.5", want: "runway-gen4-5"},
		{model: "kling/v3-pro", want: "kling-v3-pro-image-to-video"},
		{model: "kling/o3-pro", want: "kling-o3-pro-image-to-video"},
		{model: "alibaba/wan-2.7", want: "wan-2-7-image-to-video"},
		{model: "shengshu/vidu-q3", want: "vidu-q3-image-to-video"},
		{model: "pixverse/c1", want: "pixverse-c1-image-to-video"},
		{model: "x-ai/grok-imagine-video", want: "grok-imagine-video"},
	}
	for _, tc := range tests {
		t.Run(tc.model, func(t *testing.T) {
			model, queue, quote, err := Resolve(&CreateRequest{
				Model:  tc.model,
				Prompt: "move",
				FrameImages: []FrameImage{{
					FrameType: "first_frame",
					ImageURL:  "https://assets.example/frame.jpg",
				}},
			})
			if err != nil {
				t.Fatal(err)
			}
			if queue["model"] != tc.want || quote["model"] != tc.want {
				t.Fatalf("models queue=%#v quote=%#v, want %q", queue["model"], quote["model"], tc.want)
			}
			metadata := Metadata(model, queue)
			if metadata.InputMode != "image" || metadata.DurationSeconds <= 0 || metadata.Resolution == "" {
				t.Fatalf("metadata = %#v", metadata)
			}
			serialized, _ := json.Marshal(quote)
			if strings.Contains(string(serialized), "assets.example") {
				t.Fatalf("quote leaked image URL: %s", serialized)
			}
		})
	}
}

func TestResolveHailuo3UsesH3ProviderModelAndContentFreeQuote(t *testing.T) {
	generateAudio := true
	req := &CreateRequest{
		Model:          "minimax/hailuo-3",
		Prompt:         "PRIVATE prompt that must not be quoted",
		NegativePrompt: "PRIVATE negative prompt",
		Duration:       5,
		Resolution:     "2K",
		GenerateAudio:  &generateAudio,
	}
	model, queue, quote, err := Resolve(req)
	if err != nil {
		t.Fatal(err)
	}
	if model.Name != "MiniMax Hailuo 3 (H3)" {
		t.Fatalf("model name = %q", model.Name)
	}
	if queue["model"] != "minimax-h3-text-to-video" {
		t.Fatalf("queue model = %#v", queue["model"])
	}
	if queue["prompt"] != req.Prompt || queue["negative_prompt"] != req.NegativePrompt {
		t.Fatalf("queue payload lost request content: %#v", queue)
	}
	if _, found := queue["audio"]; found {
		t.Fatalf("H3 audio is always-on; provider payload must omit its non-configurable audio field: %#v", queue)
	}
	serialized, _ := json.Marshal(quote)
	if strings.Contains(string(serialized), "PRIVATE") || quote["prompt"] != nil || quote["negative_prompt"] != nil {
		t.Fatalf("quote leaked content: %s", serialized)
	}
	if quote["model"] != "minimax-h3-text-to-video" || quote["resolution"] != "2K" {
		t.Fatalf("bad quote settings: %#v", quote)
	}
}

func TestResolveHailuo3RejectsDisablingAlwaysOnAudio(t *testing.T) {
	generateAudio := false
	_, _, _, err := Resolve(&CreateRequest{
		Model: "minimax/hailuo-3", Prompt: "move", GenerateAudio: &generateAudio,
	})
	if err == nil || err.Error() != "model always generates audio and does not support disabling it" {
		t.Fatalf("error = %v", err)
	}
}

func TestResolveProviderNativeDurationAndAudioConstraints(t *testing.T) {
	if _, _, _, err := Resolve(&CreateRequest{
		Model: "minimax/hailuo-3", Prompt: "move", Duration: 4,
	}); err != nil {
		t.Fatalf("H3 must accept its documented 4-second minimum: %v", err)
	}
	if _, _, _, err := Resolve(&CreateRequest{
		Model: "alibaba/wan-2.7", Prompt: "move", Duration: 2,
	}); err != nil {
		t.Fatalf("Wan 2.7 must accept its documented 2-second minimum: %v", err)
	}
	generateAudio := false
	if _, _, _, err := Resolve(&CreateRequest{
		Model: "google/veo-3.1-fast", Prompt: "move", GenerateAudio: &generateAudio,
	}); err == nil {
		t.Fatal("Veo audio is always on and must not accept generate_audio=false")
	}
	if _, _, _, err := Resolve(&CreateRequest{
		Model: "google/veo-3.1-fast", Prompt: "move", Duration: 4, Resolution: "1080p",
	}); err == nil {
		t.Fatal("1080p Veo generation must require an 8-second duration")
	}
}

func TestResolveNormalizesAudioFlagsByProviderCapability(t *testing.T) {
	t.Run("configurable model forwards true", func(t *testing.T) {
		_, queue, quote, err := Resolve(&CreateRequest{
			Model: "bytedance/seedance-2.0-fast", Prompt: "move", GenerateAudio: boolPointer(true),
		})
		if err != nil {
			t.Fatal(err)
		}
		if queue["audio"] != true || quote["audio"] != true {
			t.Fatalf("audio flags queue=%#v quote=%#v", queue, quote)
		}
	})
	t.Run("video-only model omits explicit false", func(t *testing.T) {
		_, queue, quote, err := Resolve(&CreateRequest{
			Model: "google/gemini-omni-flash", Prompt: "move", GenerateAudio: boolPointer(false),
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, found := queue["audio"]; found {
			t.Fatalf("queue forwarded unsupported false audio toggle: %#v", queue)
		}
		if _, found := quote["audio"]; found {
			t.Fatalf("quote forwarded unsupported false audio toggle: %#v", quote)
		}
	})
}

func TestResolveSelectsImageAndReferenceVariants(t *testing.T) {
	tests := []struct {
		name string
		req  CreateRequest
		want string
	}{
		{
			name: "seedance image",
			req:  CreateRequest{Model: "bytedance/seedance-2.0-fast", Prompt: "move", FrameImages: []FrameImage{{FrameType: "first_frame", ImageURL: "https://assets.example/frame.jpg"}}},
			want: "seedance-2-0-fast-image-to-video",
		},
		{
			name: "omni reference",
			req:  CreateRequest{Model: "google/gemini-omni-flash", Prompt: "move", InputReferences: []InputReference{{Type: "image", URL: "https://assets.example/reference.jpg"}}},
			want: "gemini-omni-flash-reference-to-video",
		},
		{
			name: "hailuo h3 audio reference",
			req:  CreateRequest{Model: "minimax/hailuo-3", Prompt: "move", InputReferences: []InputReference{{Type: "audio", URL: "https://assets.example/reference.mp3"}}},
			want: "minimax-h3-reference-to-video",
		},
		{
			name: "hailuo h3 video reference",
			req:  CreateRequest{Model: "minimax/hailuo-3", Prompt: "move", InputReferences: []InputReference{{Type: "video", URL: "https://assets.example/reference.mp4"}}},
			want: "minimax-h3-reference-to-video",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, queue, quote, err := Resolve(&tc.req)
			if err != nil {
				t.Fatal(err)
			}
			if queue["model"] != tc.want || quote["model"] != tc.want {
				t.Fatalf("models queue=%#v quote=%#v, want %q", queue["model"], quote["model"], tc.want)
			}
			if quote["image_url"] != nil || quote["video_url"] != nil || quote["reference_image_urls"] != nil {
				t.Fatalf("quote leaked media reference: %#v", quote)
			}
		})
	}
}

func TestResolveRejectsUnsupportedAndUnsafeInputs(t *testing.T) {
	tests := []struct {
		name string
		req  CreateRequest
	}{
		{name: "callback", req: CreateRequest{Model: "minimax/hailuo-3", Prompt: "x", CallbackURL: "https://example.com/callback"}},
		{name: "metadata url", req: CreateRequest{Model: "minimax/hailuo-3", Prompt: "x", FrameImages: []FrameImage{{ImageURL: "https://metadata.google.internal/computeMetadata/v1/"}}}},
		{name: "private ip", req: CreateRequest{Model: "minimax/hailuo-3", Prompt: "x", FrameImages: []FrameImage{{ImageURL: "https://127.0.0.1/a.png"}}}},
		{name: "http", req: CreateRequest{Model: "minimax/hailuo-3", Prompt: "x", FrameImages: []FrameImage{{ImageURL: "http://example.com/a.png"}}}},
		{name: "omni audio toggle", req: CreateRequest{Model: "google/gemini-omni-flash", Prompt: "x", GenerateAudio: boolPointer(true)}},
		{name: "ltx bad duration", req: CreateRequest{Model: "lightricks/ltx-2.3", Prompt: "x", Duration: 7}},
		{name: "unknown field model", req: CreateRequest{Model: "unknown/video", Prompt: "x"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, _, err := Resolve(&tc.req); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func boolPointer(value bool) *bool { return &value }

func TestModelsJSONIsTruthfulAboutProviderPrivacy(t *testing.T) {
	body, err := ModelsJSON()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(string(body)), "openrouter") {
		t.Fatalf("video model catalog must not advertise an OpenRouter serving path: %s", body)
	}
	var payload struct {
		Data []struct {
			ID           string `json:"id"`
			Architecture struct {
				InputModalities []string `json:"input_modalities"`
			} `json:"architecture"`
			TrustedRouter map[string]any `json:"trustedrouter"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Data) != 17 {
		t.Fatalf("model count = %d", len(payload.Data))
	}
	for _, row := range payload.Data {
		wantProvider := directProviderForModel(row.ID)
		if wantProvider == "" {
			wantProvider = "venice"
		}
		if row.TrustedRouter["provider"] != wantProvider || row.TrustedRouter["provider_e2ee"] != false || row.TrustedRouter["provider_zero_data_retention"] != false {
			t.Fatalf("untruthful privacy metadata for %s: %#v", row.ID, row.TrustedRouter)
		}
		if row.TrustedRouter["stores_content"] != false || row.TrustedRouter["provider_temporarily_stores_generated_media"] != true {
			t.Fatalf("bad storage boundary for %s: %#v", row.ID, row.TrustedRouter)
		}
		modalities := strings.Join(row.Architecture.InputModalities, ",")
		switch row.ID {
		case "google/gemini-omni-flash":
			if modalities != "text,image" {
				t.Fatalf("omni modalities = %q", modalities)
			}
		case "minimax/hailuo-3":
			if modalities != "text,image,audio,video" {
				t.Fatalf("H3 modalities = %q", modalities)
			}
			if row.TrustedRouter["audio_mode"] != "always" {
				t.Fatalf("H3 audio mode = %#v", row.TrustedRouter["audio_mode"])
			}
		}
	}
}
