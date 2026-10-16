//go:build linux && live_provider_wave && llm_multi

package llm

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/privatemode"
	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
	"golang.org/x/image/font"
	"golang.org/x/image/font/basicfont"
	"golang.org/x/image/math/fixed"
)

func TestPrivatemodeMediaLive(t *testing.T) {
	key := os.Getenv("PRIVATEMODE_API_KEY")
	if os.Getenv("TR_CONFIDENTIAL_MEDIA_LIVE") != "1" || key == "" {
		t.Skip("paid synthetic model opt-in")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()
	verified, err := privatemode.Start(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ConfigurePrivatemode(verified)
	defer ConfigurePrivatemode(nil)
	assertPrivatemodeUnprivileged(t)
	c := newOpenAICompatible("privatemode", key)
	for _, dim := range []int{1024, 2560} {
		t.Run("embeddings", func(t *testing.T) {
			out, err := c.InvokeEmbedding(ctx, &qtypes.EmbeddingRequest{Model: "qwen/qwen3-embedding-4b", Input: "Synthetic public text.", Dimensions: &dim}, InvokeOptions{UpstreamModel: "qwen3-embedding-4b"})
			if err != nil {
				t.Fatal(err)
			}
			if len(out.Data) != 1 || out.Usage.PromptTokens <= 0 {
				t.Fatal("missing vector or usage")
			}
			var vector []float64
			if json.Unmarshal(out.Data[0].Embedding, &vector) != nil || len(vector) != dim {
				t.Fatal("incorrect vector dimensions")
			}
			t.Logf("encrypted embeddings verified dimensions=%d input_tokens=%d", dim, out.Usage.PromptTokens)
		})
	}
	t.Run("ocr", func(t *testing.T) {
		img := image.NewRGBA(image.Rect(0, 0, 160, 60))
		draw.Draw(img, img.Bounds(), image.NewUniform(color.White), image.Point{}, draw.Src)
		d := font.Drawer{Dst: img, Src: image.NewUniform(color.Black), Face: basicfont.Face7x13, Dot: fixed.P(15, 30)}
		d.DrawString("PARIS 12345")
		large := image.NewRGBA(image.Rect(0, 0, 800, 300))
		for y := 0; y < 300; y++ {
			for x := 0; x < 800; x++ {
				large.Set(x, y, img.At(x/5, y/5))
			}
		}
		var data bytes.Buffer
		if err := png.Encode(&data, large); err != nil {
			t.Fatal(err)
		}
		content := []any{map[string]any{"type": "image_url", "image_url": map[string]any{"url": "data:image/png;base64," + base64.StdEncoding.EncodeToString(data.Bytes())}}, map[string]any{"type": "text", "text": "Free OCR."}}
		body := &qtypes.AnthropicMessagesRequest{MaxTokens: 128, MaxTokensExplicit: true, Messages: []qtypes.AnthropicMessage{{Role: "user", Content: content}}}
		var out bytes.Buffer
		err := c.InvokeStreaming(ctx, &qtypes.OpenAIChatRequest{Model: "deepseek/deepseek-ocr-2"}, body, &out, InvokeOptions{Provider: "privatemode", UpstreamModel: "deepseek-ocr-2", ProviderCacheScope: "synthetic-ocr-test"})
		if err != nil {
			t.Fatal(err)
		}
		var text strings.Builder
		for _, line := range strings.Split(out.String(), "\n") {
			if !strings.HasPrefix(line, "data: ") {
				continue
			}
			var event struct {
				Delta struct {
					Text string `json:"text"`
				} `json:"delta"`
			}
			if json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &event) == nil {
				text.WriteString(event.Delta.Text)
			}
		}
		if !strings.Contains(strings.ToUpper(text.String()), "PARIS") {
			t.Fatal("synthetic OCR mismatch")
		}
		t.Log("encrypted synthetic OCR verified")
	})
}
