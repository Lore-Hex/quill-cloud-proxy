package llm

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"image"
	"image/color"
	"image/png"
	"os"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/decide"
)

// Explicitly opt in to tiny paid tests; credentials never appear in results.
func TestSystem1Live(t *testing.T) {
	if os.Getenv("TR_RUN_SYSTEM1_LIVE") != "1" {
		t.Skip("live provider calls disabled")
	}
	for _, profile := range []struct{ provider, key string }{
		{"system1models", "SYSTEM1MODELS_GLOBAL_API_KEY"}, {"system1models-eu", "SYSTEM1MODELS_EU_API_KEY"},
	} {
		key := os.Getenv(profile.key)
		if key == "" {
			t.Fatalf("%s missing", profile.key)
		}
		for _, model := range []string{"s1-fast", "s1-pro", "s1-vision"} {
			var images []string
			if model == "s1-vision" {
				img := image.NewRGBA(image.Rect(0, 0, 128, 128))
				for y := 0; y < 128; y++ {
					for x := 0; x < 128; x++ {
						img.Set(x, y, color.RGBA{R: 255, A: 255})
					}
				}
				var data bytes.Buffer
				if err := png.Encode(&data, img); err != nil {
					t.Fatal(err)
				}
				images = []string{"data:image/png;base64," + base64.StdEncoding.EncodeToString(data.Bytes())}
			}
			for _, question := range []string{
				`{"q":{"type":"boolean","instructions":"Does Mia own a red bicycle?"}}`,
				`{"q":{"type":"choice","instructions":"What color is the bicycle?","criteria":{"red":null,"blue":null}}}`,
				`{"q":{"type":"score","instructions":"How certain is it that the bicycle is red?","criteria":["not red","possibly red","definitely red"]}}`,
			} {
				var questions map[string]decide.Question
				if err := json.Unmarshal([]byte(question), &questions); err != nil {
					t.Fatal(err)
				}
				specs, err := decide.Parse(questions)
				if err != nil {
					t.Fatal(err)
				}
				client := &openAICompatibleClient{provider: profile.provider, baseURL: "https://api.system1models.ai/v1", apiKey: key}
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				result, err := client.InvokeDecide(ctx, &DecideRequest{Model: model, State: json.RawMessage(`"Mia owns a red bicycle."`), Questions: questions, Images: images})
				cancel()
				if err != nil {
					t.Fatalf("%s %s: %s", profile.provider, model, DecideErrorClass(err))
				}
				if _, err := decide.Verify(specs, result.Answers); err != nil {
					t.Fatalf("%s %s: answer verification failed", profile.provider, model)
				}
				if result.InputTokens <= 0 || result.OutputTokens != 0 {
					t.Fatal("invalid billing usage")
				}
			}
		}
	}
}
