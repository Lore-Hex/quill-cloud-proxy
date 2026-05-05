package llm

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"hash/crc32"
	"image"
	"image/color"
	"image/png"
	"strings"
	"testing"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestAnthropicMessagesFetchesDataURLImagesInsideEnclave(t *testing.T) {
	imageURL := "data:image/png;base64," + base64.StdEncoding.EncodeToString(testPNG(t))
	body := &qtypes.AnthropicMessagesRequest{
		Messages: []qtypes.AnthropicMessage{{
			Role: "user",
			Content: []qtypes.ChatContentPart{
				{Type: "text", Text: "describe"},
				{Type: "image_url", ImageURL: &qtypes.ChatImageURL{URL: imageURL, Detail: "low"}},
			},
		}},
	}

	messages, err := anthropicMessagesWithFetchedImages(t.Context(), body)
	if err != nil {
		t.Fatalf("anthropicMessagesWithFetchedImages: %v", err)
	}
	parts, ok := messages[0].Content.([]map[string]any)
	if !ok {
		t.Fatalf("content type = %T, want []map[string]any", messages[0].Content)
	}
	if len(parts) != 2 || parts[0]["type"] != "text" || parts[1]["type"] != "image" {
		t.Fatalf("bad anthropic parts: %#v", parts)
	}
	source, ok := parts[1]["source"].(map[string]any)
	if !ok {
		t.Fatalf("missing image source: %#v", parts[1])
	}
	if source["media_type"] != "image/png" || source["type"] != "base64" {
		t.Fatalf("bad source metadata: %#v", source)
	}
	if _, err := base64.StdEncoding.DecodeString(source["data"].(string)); err != nil {
		t.Fatalf("source data is not base64: %v", err)
	}
	if strings.Contains(source["data"].(string), "data:image") {
		t.Fatalf("source leaked raw data URL: %#v", source)
	}
}

func TestImageFetcherRejectsPrivateHosts(t *testing.T) {
	_, _, err := loadImageBytes(t.Context(), "http://127.0.0.1/private.png")
	if err == nil || !strings.Contains(err.Error(), "fetch failed") {
		t.Fatalf("err = %v, want private host fetch failure", err)
	}
}

func TestNormalizeImageBytesRejectsHugeDimensionsBeforeDecode(t *testing.T) {
	_, _, err := normalizeImageBytes("image/png", pngHeaderWithDimensions(t, maxImageDimension+1, 1))
	if err == nil || !strings.Contains(err.Error(), "image dimensions too large") {
		t.Fatalf("err = %v, want dimension cap error", err)
	}

	_, _, err = normalizeImageBytes("image/png", pngHeaderWithDimensions(t, 5000, 5000))
	if err == nil || !strings.Contains(err.Error(), "image dimensions too large") {
		t.Fatalf("err = %v, want pixel cap error", err)
	}
}

func testPNG(t *testing.T) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 1, 1))
	img.Set(0, 0, color.RGBA{R: 255, A: 255})
	var out bytes.Buffer
	if err := png.Encode(&out, img); err != nil {
		t.Fatalf("png encode: %v", err)
	}
	return out.Bytes()
}

func pngHeaderWithDimensions(t *testing.T, width, height int) []byte {
	t.Helper()
	var out bytes.Buffer
	out.Write([]byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'})
	ihdr := make([]byte, 13)
	binary.BigEndian.PutUint32(ihdr[0:4], uint32(width))
	binary.BigEndian.PutUint32(ihdr[4:8], uint32(height))
	ihdr[8] = 8
	ihdr[9] = 2
	writePNGChunk(t, &out, "IHDR", ihdr)
	writePNGChunk(t, &out, "IEND", nil)
	return out.Bytes()
}

func writePNGChunk(t *testing.T, out *bytes.Buffer, kind string, data []byte) {
	t.Helper()
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(data)))
	out.Write(length[:])
	out.WriteString(kind)
	out.Write(data)
	crc := crc32.NewIEEE()
	_, _ = crc.Write([]byte(kind))
	_, _ = crc.Write(data)
	var checksum [4]byte
	binary.BigEndian.PutUint32(checksum[:], crc.Sum32())
	out.Write(checksum[:])
}
