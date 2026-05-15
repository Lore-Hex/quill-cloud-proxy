package llm

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"hash/crc32"
	"image"
	"image/color"
	"image/png"
	"io"
	"net/http"
	"net/http/httptest"
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

func TestOpenAICompatibleRequestFetchesImagesInsideEnclave(t *testing.T) {
	imageURL := "data:image/png;base64," + base64.StdEncoding.EncodeToString(testPNG(t))
	var captured map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read request body: %v", err)
		}
		if err := json.Unmarshal(body, &captured); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte(strings.Join([]string{
			`data: {"choices":[{"delta":{"content":"ok"},"finish_reason":null}]}`,
			``,
			`data: {"choices":[{"delta":{},"finish_reason":"stop"}]}`,
			``,
			`data: [DONE]`,
			``,
		}, "\n")))
	}))
	defer server.Close()

	req := &qtypes.OpenAIChatRequest{
		Model: "moonshotai/kimi-k2.6",
		Messages: []qtypes.OpenAIChatMessage{{
			Role: "user",
			Content: []qtypes.ChatContentPart{
				{Type: "text", Text: "describe"},
				{Type: "image_url", ImageURL: &qtypes.ChatImageURL{URL: imageURL, Detail: "low"}},
			},
		}},
		ResponseFormat: map[string]any{"type": "json_object"},
		Tools: []any{map[string]any{
			"type": "function",
			"function": map[string]any{
				"name":       "get_weather",
				"parameters": map[string]any{"type": "object"},
			},
		}},
		ToolChoice:    map[string]any{"type": "function", "function": map[string]any{"name": "get_weather"}},
		ParallelTools: func() *bool { v := false; return &v }(),
	}
	anthropicReq := &qtypes.AnthropicMessagesRequest{
		Messages: []qtypes.AnthropicMessage{{
			Role:    "user",
			Content: req.Messages[0].Content,
		}},
		MaxTokens: 16,
	}
	var out bytes.Buffer
	if err := invokeOpenAICompatibleStreamingWithClient(
		t.Context(),
		server.Client(),
		"kimi",
		server.URL,
		"operator-key",
		req,
		anthropicReq,
		&out,
		"moonshotai/kimi-k2.6",
	); err != nil {
		t.Fatalf("invokeOpenAICompatibleStreamingWithClient: %v", err)
	}

	messages := captured["messages"].([]any)
	content := messages[0].(map[string]any)["content"].([]any)
	imagePart := content[1].(map[string]any)
	imageURLBlock := imagePart["image_url"].(map[string]any)
	gotURL := imageURLBlock["url"].(string)
	if !strings.HasPrefix(gotURL, "data:image/png;base64,") {
		t.Fatalf("image URL = %.32q, want normalized data URL", gotURL)
	}
	if strings.Contains(gotURL, "example.com") {
		t.Fatalf("raw remote image URL leaked upstream: %s", gotURL)
	}
	if imageURLBlock["detail"] != "low" {
		t.Fatalf("image detail = %#v, want low", imageURLBlock["detail"])
	}
	responseFormat := captured["response_format"].(map[string]any)
	if responseFormat["type"] != "json_object" {
		t.Fatalf("response_format = %#v, want json_object", responseFormat)
	}
	tools := captured["tools"].([]any)
	if len(tools) != 1 {
		t.Fatalf("tools = %#v, want one tool", tools)
	}
	choice := captured["tool_choice"].(map[string]any)
	if choice["type"] != "function" {
		t.Fatalf("tool_choice = %#v, want forced function", choice)
	}
	if captured["parallel_tool_calls"] != false {
		t.Fatalf("parallel_tool_calls = %#v, want false", captured["parallel_tool_calls"])
	}
	thinking := captured["thinking"].(map[string]any)
	if thinking["type"] != "disabled" {
		t.Fatalf("thinking = %#v, want disabled for Kimi tool calls", thinking)
	}
	if !strings.Contains(out.String(), "content_block_delta") {
		t.Fatalf("stream was not translated: %s", out.String())
	}
}

func TestOpenAICompatibleStreamTranslatesToolCalls(t *testing.T) {
	stream := strings.NewReader(strings.Join([]string{
		`data: {"choices":[{"delta":{"tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"get_weather","arguments":"{\"location\""}}]},"finish_reason":null}]}`,
		``,
		`data: {"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":":\"Paris\"}"}}]},"finish_reason":null}]}`,
		``,
		`data: {"choices":[{"delta":{},"finish_reason":"tool_calls"}]}`,
		``,
		`data: [DONE]`,
		``,
	}, "\n"))
	var out bytes.Buffer
	if err := translateOpenAIStreamToAnthropic(stream, &out); err != nil {
		t.Fatalf("translateOpenAIStreamToAnthropic: %v", err)
	}
	body := out.String()
	for _, want := range []string{"content_block_start", "input_json_delta", "content_block_stop", `"stop_reason":"tool_use"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("translated stream missing %s: %s", want, body)
		}
	}
	if !strings.Contains(body, `get_weather`) || !strings.Contains(body, `Paris`) {
		t.Fatalf("tool call details missing: %s", body)
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

func pngHeaderWithDimensions(t *testing.T, width, height uint32) []byte {
	t.Helper()
	var out bytes.Buffer
	out.Write([]byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'})
	ihdr := make([]byte, 13)
	binary.BigEndian.PutUint32(ihdr[0:4], width)
	binary.BigEndian.PutUint32(ihdr[4:8], height)
	ihdr[8] = 8
	ihdr[9] = 2
	writePNGChunk(t, &out, "IHDR", ihdr)
	writePNGChunk(t, &out, "IEND", nil)
	return out.Bytes()
}

func writePNGChunk(t *testing.T, out *bytes.Buffer, kind string, data []byte) {
	t.Helper()
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(data))) //nolint:gosec // Test PNG chunks are fixed tiny fixtures.
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
