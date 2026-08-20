//go:build llm_multi

package llm

import (
	"bytes"
	"context"
	"strings"
	"testing"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestVertexGeminiImageGenerationUsesImageOnlyResponseFormat(t *testing.T) {
	maxTokens := 2520
	req := &qtypes.OpenAIChatRequest{
		Model:            "google/gemini-3.1-flash-image",
		Messages:         []qtypes.OpenAIChatMessage{{Role: "user", Content: "landscape"}},
		MaxTokens:        &maxTokens,
		ImageGeneration:  true,
		ImageResolution:  "4K",
		ImageAspectRatio: "21:9",
	}
	payload, err := vertexGeminiPayload(context.Background(), req, nil, "gemini-3.1-flash-image")
	if err != nil {
		t.Fatalf("payload: %v", err)
	}
	config := payload["generationConfig"].(map[string]any)
	if _, exists := config["maxOutputTokens"]; exists {
		t.Fatalf("image output token budget leaked to Gemini: %#v", config)
	}
	modalities := config["responseModalities"].([]string)
	if len(modalities) != 1 || modalities[0] != "IMAGE" {
		t.Fatalf("modalities = %#v", modalities)
	}
	imageConfig := config["responseFormat"].(map[string]any)["image"].(map[string]any)
	if imageConfig["imageSize"] != "IMAGE_SIZE_FOUR_K" ||
		imageConfig["aspectRatio"] != "ASPECT_RATIO_TWENTY_ONE_BY_NINE" ||
		imageConfig["mimeType"] != "IMAGE_JPEG" {
		t.Fatalf("responseFormat.image = %#v", imageConfig)
	}
}

func TestGeminiImageEnumsCoverEveryNormalizedValue(t *testing.T) {
	for input, want := range map[string]string{
		"512": "IMAGE_SIZE_FIVE_TWELVE",
		"1K":  "IMAGE_SIZE_ONE_K",
		"2K":  "IMAGE_SIZE_TWO_K",
		"4K":  "IMAGE_SIZE_FOUR_K",
	} {
		if got := geminiImageSize(input); got != want {
			t.Fatalf("size %q = %q, want %q", input, got, want)
		}
	}
	for input, want := range map[string]string{
		"1:1": "ASPECT_RATIO_ONE_BY_ONE", "1:4": "ASPECT_RATIO_ONE_BY_FOUR",
		"1:8": "ASPECT_RATIO_ONE_BY_EIGHT", "2:3": "ASPECT_RATIO_TWO_BY_THREE",
		"3:2": "ASPECT_RATIO_THREE_BY_TWO", "3:4": "ASPECT_RATIO_THREE_BY_FOUR",
		"4:1": "ASPECT_RATIO_FOUR_BY_ONE", "4:3": "ASPECT_RATIO_FOUR_BY_THREE",
		"4:5": "ASPECT_RATIO_FOUR_BY_FIVE", "5:4": "ASPECT_RATIO_FIVE_BY_FOUR",
		"8:1": "ASPECT_RATIO_EIGHT_BY_ONE", "9:16": "ASPECT_RATIO_NINE_BY_SIXTEEN",
		"16:9": "ASPECT_RATIO_SIXTEEN_BY_NINE", "21:9": "ASPECT_RATIO_TWENTY_ONE_BY_NINE",
	} {
		if got := geminiImageAspectRatio(input); got != want {
			t.Fatalf("aspect ratio %q = %q, want %q", input, got, want)
		}
	}
}

func TestStrictGeminiStreamRejectsMalformedAndTruncatedEvents(t *testing.T) {
	for name, stream := range map[string]string{
		"malformed": "data: {not-json}\n\n",
		"truncated": "data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"x\"}]}}]}\n\n",
	} {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			if err := translateGeminiStreamToAnthropicMode(strings.NewReader(stream), &out, true); err == nil {
				t.Fatalf("strict stream succeeded: %s", out.String())
			}
		})
	}
}

func TestStrictGeminiStreamAcceptsTerminalImage(t *testing.T) {
	stream := `data: {"candidates":[{"content":{"parts":[{"inlineData":{"mimeType":"image/png","data":"UE5H"}}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":5,"candidatesTokenCount":1120}}

`
	var out bytes.Buffer
	if err := translateGeminiStreamToAnthropicMode(strings.NewReader(stream), &out, true); err != nil {
		t.Fatalf("strict stream: %v", err)
	}
	if !strings.Contains(out.String(), "data:image/png;base64,UE5H") || !strings.Contains(out.String(), "message_stop") {
		t.Fatalf("translated stream = %s", out.String())
	}
}
