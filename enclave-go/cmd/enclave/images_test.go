//go:build llm_multi

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/auth"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestParseImageGenerationRequestNormalizesNativeSizes(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		wantRes    string
		wantAspect string
		wantParam  string
	}{
		{name: "defaults", body: `{"model":"google/gemini-3.1-flash-image","prompt":"cat"}`, wantRes: "1K", wantAspect: "1:1"},
		{name: "tier shorthand", body: `{"model":"google/gemini-3.1-flash-image","prompt":"cat","size":"2k","aspect_ratio":"16:9"}`, wantRes: "2K", wantAspect: "16:9"},
		{name: "pixels", body: `{"model":"google/gemini-3.1-flash-image","prompt":"cat","size":"2752x1536"}`, wantRes: "2K", wantAspect: "16:9"},
		{name: "conflicting pixels", body: `{"model":"google/gemini-3.1-flash-image","prompt":"cat","size":"2752x1536","resolution":"4K"}`, wantParam: "size"},
		{name: "multiple images", body: `{"model":"google/gemini-3.1-flash-image","prompt":"cat","n":2}`, wantParam: "n"},
		{name: "unsupported output", body: `{"model":"google/gemini-3.1-flash-image","prompt":"cat","output_format":"jpeg"}`, wantParam: "output_format"},
		{name: "unsupported seed", body: `{"model":"google/gemini-3.1-flash-image","prompt":"cat","seed":42}`, wantParam: "seed"},
		{name: "passthrough", body: `{"model":"google/gemini-3.1-flash-image","prompt":"cat","provider":{"options":{"google-ai-studio":{"foo":1}}}}`, wantParam: "provider.options"},
		{name: "unknown", body: `{"model":"google/gemini-3.1-flash-image","prompt":"cat","surprise":true}`, wantParam: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseImageGenerationRequest([]byte(tt.body))
			if tt.wantParam != "" || tt.name == "unknown" {
				if err == nil {
					t.Fatalf("expected rejection, got %#v", got)
				}
				var requestErr *imageRequestError
				if !errorsAs(err, &requestErr) {
					t.Fatalf("error = %T %v", err, err)
				}
				if requestErr.param != tt.wantParam {
					t.Fatalf("param = %q, want %q", requestErr.param, tt.wantParam)
				}
				return
			}
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if got.resolution != tt.wantRes || got.aspectRatio != tt.wantAspect {
				t.Fatalf("resolved = %s %s, want %s %s", got.resolution, got.aspectRatio, tt.wantRes, tt.wantAspect)
			}
		})
	}
}

func TestParseImageGenerationRequestEnforcesReferenceLimit(t *testing.T) {
	for count := 14; count <= 15; count++ {
		references := make([]map[string]any, count)
		for i := range references {
			references[i] = map[string]any{
				"type":      "image_url",
				"image_url": map[string]any{"url": "data:image/png;base64,UE5H"},
			}
		}
		body, err := json.Marshal(map[string]any{
			"model": "google/gemini-3.1-flash-image", "prompt": "cat",
			"input_references": references,
		})
		if err != nil {
			t.Fatal(err)
		}
		_, err = parseImageGenerationRequest(body)
		if count == 14 && err != nil {
			t.Fatalf("14 references rejected: %v", err)
		}
		if count == 15 {
			var requestErr *imageRequestError
			if !errors.As(err, &requestErr) || requestErr.param != "input_references" {
				t.Fatalf("15 references error = %v", err)
			}
		}
	}
}

// errorsAs keeps the table above readable without shadowing the package name
// in all of the larger integration helpers below.
func errorsAs(err error, target any) bool { return errors.As(err, target) }

func TestParseGeneratedImageValidatesBytesAndDimensions(t *testing.T) {
	b64 := pngBase64(t, 1376, 768)
	got, err := parseGeneratedImage("data:image/png;base64," + b64)
	if err != nil {
		t.Fatalf("parse image: %v", err)
	}
	if got.mediaType != "image/png" || got.b64 != b64 {
		t.Fatalf("image = %#v", got)
	}
	jpegB64 := jpegBase64(t, 1376, 768)
	jpegImage, err := parseGeneratedImage("data:image/jpeg;base64," + jpegB64)
	if err != nil || jpegImage.mediaType != "image/jpeg" {
		t.Fatalf("parse jpeg = %#v, %v", jpegImage, err)
	}
	for _, invalid := range []string{
		"not-an-image",
		"data:image/png;base64,%%%%",
		"data:image/jpeg;base64," + b64,
		"data:image/png;base64," + b64 + "\nextra",
	} {
		if _, err := parseGeneratedImage(invalid); err == nil {
			t.Fatalf("accepted invalid output %q", invalid)
		}
	}
}

type imageTestLLM struct {
	mu        sync.Mutex
	request   *types.OpenAIChatRequest
	stream    string
	invokeErr error
}

func (f *imageTestLLM) InvokeStreaming(
	_ context.Context,
	req *types.OpenAIChatRequest,
	_ *types.AnthropicMessagesRequest,
	out io.Writer,
	_ ...llm.InvokeOptions,
) error {
	f.mu.Lock()
	copy := *req
	f.request = &copy
	f.mu.Unlock()
	if f.stream != "" {
		_, _ = io.WriteString(out, f.stream)
	}
	return f.invokeErr
}

func (f *imageTestLLM) captured() *types.OpenAIChatRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.request
}

type imageControlRecorder struct {
	mu        sync.Mutex
	authorize []map[string]any
	settle    []map[string]any
	refund    []map[string]any
}

func (r *imageControlRecorder) handler(t *testing.T) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, request *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Errorf("decode %s: %v", request.URL.Path, err)
			http.Error(w, "bad body", 400)
			return
		}
		r.mu.Lock()
		defer r.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/internal/gateway/authorize":
			r.authorize = append(r.authorize, body)
			_, _ = io.WriteString(w, `{"data":{"authorization_id":"auth_image","workspace_id":"ws_image","api_key_hash":"hash_image","model":"google/gemini-3.1-flash-image","upstream_model":"gemini-3.1-flash-image","endpoint_id":"google/gemini-3.1-flash-image@google-ai-studio/prepaid","provider":"google-ai-studio","usage_type":"Credits","route_candidates":[{"endpoint_id":"google/gemini-3.1-flash-image@google-ai-studio/prepaid","model":"google/gemini-3.1-flash-image","upstream_model":"gemini-3.1-flash-image","provider":"google-ai-studio","usage_type":"Credits"}]}}`)
		case "/internal/gateway/settle":
			r.settle = append(r.settle, body)
			_, _ = io.WriteString(w, `{"data":{"generation_id":"gen_image","cost_microdollars":70896,"cost":0.070896,"input_tokens":5,"output_tokens":1120,"usage_type":"Credits","model":"google/gemini-3.1-flash-image","provider":"google-ai-studio","region":"us-central1","settled":true}}`)
		case "/internal/gateway/refund":
			r.refund = append(r.refund, body)
			_, _ = io.WriteString(w, `{"data":{"settled":true,"finalization_outcome":"refunded"}}`)
		default:
			http.Error(w, "unexpected path", 404)
		}
	}
}

func (r *imageControlRecorder) snapshot() (authorize, settle, refund []map[string]any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]map[string]any(nil), r.authorize...), append([]map[string]any(nil), r.settle...), append([]map[string]any(nil), r.refund...)
}

func TestServeImagesSettlesCompleteValidatedImageWithoutLeakingContent(t *testing.T) {
	control := &imageControlRecorder{}
	server := httptest.NewServer(control.handler(t))
	defer server.Close()
	gateway := trustedrouter.New(server.URL, "internal", server.Client())
	b64 := jpegBase64(t, 1376, 768)
	streamer := &imageTestLLM{stream: completeImageSSE(t, b64, "image/jpeg", true)}
	body := `{"model":"google/gemini-3.1-flash-image","prompt":"private red panda","resolution":"1K","aspect_ratio":"16:9","input_references":[{"type":"image_url","image_url":{"url":"data:image/png;base64,` + b64 + `"}}]}`
	request := fmt.Sprintf("POST /v1/images HTTP/1.1\r\nHost: api.trustedrouter.com\r\nAuthorization: Bearer sk-secret\r\nIdempotency-Key: img-one\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
	conn := newScriptedConn(request, nil)
	serveOne(context.Background(), conn, auth.New(nil), streamer, nil, nil, gateway, nil)

	head, responseBody := splitHTTPResponse(t, conn.writes.String())
	if !strings.Contains(head, "HTTP/1.1 200 OK") {
		t.Fatalf("response head = %s", head)
	}
	var response struct {
		Data []struct {
			B64JSON   string `json:"b64_json"`
			MediaType string `json:"media_type"`
		} `json:"data"`
		Usage map[string]any `json:"usage"`
	}
	if err := json.Unmarshal([]byte(responseBody), &response); err != nil {
		t.Fatalf("decode response: %v\n%s", err, responseBody)
	}
	if len(response.Data) != 1 || response.Data[0].B64JSON != b64 || response.Data[0].MediaType != "image/jpeg" {
		t.Fatalf("image response = %#v", response.Data)
	}
	if response.Usage["cost"] != 0.070896 {
		t.Fatalf("usage = %#v", response.Usage)
	}
	authorize, settle, refund := control.snapshot()
	if len(authorize) != 1 || len(settle) != 1 || len(refund) != 0 {
		t.Fatalf("control calls authorize=%d settle=%d refund=%d", len(authorize), len(settle), len(refund))
	}
	authorizeJSON, _ := json.Marshal(authorize[0])
	if bytes.Contains(authorizeJSON, []byte("private red panda")) || bytes.Contains(authorizeJSON, []byte(b64)) {
		t.Fatalf("content leaked to authorize: %s", authorizeJSON)
	}
	if authorize[0]["route_type"] != "images" || authorize[0]["max_output_tokens"] != float64(1120) {
		t.Fatalf("authorize = %#v", authorize[0])
	}
	if got, _ := authorize[0]["estimated_input_tokens"].(float64); got < 1_700 {
		t.Fatalf("estimated input tokens = %v, want a conservative image reservation", got)
	}
	if fingerprint, _ := authorize[0]["request_fingerprint"].(string); len(fingerprint) != 64 {
		t.Fatalf("fingerprint = %q", fingerprint)
	}
	if settle[0]["route_type"] != "images" || settle[0]["actual_output_tokens"] != float64(1120) {
		t.Fatalf("settle = %#v", settle[0])
	}
	captured := streamer.captured()
	if captured == nil || !captured.ImageGeneration || captured.ImageResolution != "1K" || captured.ImageAspectRatio != "16:9" {
		t.Fatalf("provider request = %#v", captured)
	}
}

func TestServeImagesStreamsCompletedEventAndDone(t *testing.T) {
	control := &imageControlRecorder{}
	server := httptest.NewServer(control.handler(t))
	defer server.Close()
	gateway := trustedrouter.New(server.URL, "internal", server.Client())
	b64 := jpegBase64(t, 1024, 1024)
	streamer := &imageTestLLM{stream: completeImageSSE(t, b64, "image/jpeg", true)}
	body := `{"model":"google/gemini-3.1-flash-image","prompt":"cat","stream":true}`
	request := fmt.Sprintf("POST /v1/images HTTP/1.1\r\nHost: test\r\nAuthorization: Bearer sk-secret\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
	conn := newScriptedConn(request, nil)
	serveOne(context.Background(), conn, auth.New(nil), streamer, nil, nil, gateway, nil)
	response := conn.writes.String()
	if !strings.Contains(response, "Content-Type: text/event-stream") ||
		!strings.Contains(response, `"type":"image_generation.completed"`) ||
		!strings.Contains(response, "data: [DONE]") {
		t.Fatalf("stream response = %s", response)
	}
}

func TestServeImagesRefundsTruncatedProviderStream(t *testing.T) {
	control := &imageControlRecorder{}
	server := httptest.NewServer(control.handler(t))
	defer server.Close()
	gateway := trustedrouter.New(server.URL, "internal", server.Client())
	streamer := &imageTestLLM{stream: completeImageSSE(t, jpegBase64(t, 2, 2), "image/jpeg", false)}
	body := `{"model":"google/gemini-3.1-flash-image","prompt":"cat"}`
	request := fmt.Sprintf("POST /v1/images HTTP/1.1\r\nHost: test\r\nAuthorization: Bearer sk-secret\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
	conn := newScriptedConn(request, nil)
	serveOne(context.Background(), conn, auth.New(nil), streamer, nil, nil, gateway, nil)
	if !strings.Contains(conn.writes.String(), "HTTP/1.1 502 Bad Gateway") {
		t.Fatalf("response = %s", conn.writes.String())
	}
	_, settle, refund := control.snapshot()
	if len(settle) != 0 || len(refund) != 1 {
		t.Fatalf("settle=%d refund=%d", len(settle), len(refund))
	}
}

func TestServeImagesRefundsACompleteImageWithWrongDimensions(t *testing.T) {
	control := &imageControlRecorder{}
	server := httptest.NewServer(control.handler(t))
	defer server.Close()
	gateway := trustedrouter.New(server.URL, "internal", server.Client())
	streamer := &imageTestLLM{stream: completeImageSSE(t, jpegBase64(t, 2, 2), "image/jpeg", true)}
	body := `{"model":"google/gemini-3.1-flash-image","prompt":"cat","resolution":"1K","aspect_ratio":"1:1"}`
	request := fmt.Sprintf("POST /v1/images HTTP/1.1\r\nHost: test\r\nAuthorization: Bearer sk-secret\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
	conn := newScriptedConn(request, nil)
	serveOne(context.Background(), conn, auth.New(nil), streamer, nil, nil, gateway, nil)
	if !strings.Contains(conn.writes.String(), "HTTP/1.1 502 Bad Gateway") {
		t.Fatalf("response = %s", conn.writes.String())
	}
	_, settle, refund := control.snapshot()
	if len(settle) != 0 || len(refund) != 1 || refund[0]["error_type"] != "invalid_image_dimensions" {
		t.Fatalf("settle=%d refund=%#v", len(settle), refund)
	}
}

func TestServeImagesRefundsOutputThatDoesNotMatchRequestedFormat(t *testing.T) {
	control := &imageControlRecorder{}
	server := httptest.NewServer(control.handler(t))
	defer server.Close()
	gateway := trustedrouter.New(server.URL, "internal", server.Client())
	streamer := &imageTestLLM{stream: completeImageSSE(t, pngBase64(t, 1024, 1024), "image/png", true)}
	body := `{"model":"google/gemini-3.1-flash-image","prompt":"cat"}`
	request := fmt.Sprintf("POST /v1/images HTTP/1.1\r\nHost: test\r\nAuthorization: Bearer sk-secret\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
	conn := newScriptedConn(request, nil)
	serveOne(context.Background(), conn, auth.New(nil), streamer, nil, nil, gateway, nil)
	if !strings.Contains(conn.writes.String(), "HTTP/1.1 502 Bad Gateway") {
		t.Fatalf("response = %s", conn.writes.String())
	}
	_, settle, refund := control.snapshot()
	if len(settle) != 0 || len(refund) != 1 || refund[0]["error_type"] != "invalid_image_output" {
		t.Fatalf("settle=%d refund=%#v", len(settle), refund)
	}
}

func tinyPNGBase64(t *testing.T) string {
	return pngBase64(t, 2, 2)
}

func pngBase64(t *testing.T, width, height int) string {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	img.Set(0, 0, color.RGBA{R: 255, A: 255})
	var out bytes.Buffer
	if err := png.Encode(&out, img); err != nil {
		t.Fatalf("encode png: %v", err)
	}
	return base64.StdEncoding.EncodeToString(out.Bytes())
}

func jpegBase64(t *testing.T, width, height int) string {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	img.Set(0, 0, color.RGBA{R: 255, A: 255})
	var out bytes.Buffer
	if err := jpeg.Encode(&out, img, &jpeg.Options{Quality: 90}); err != nil {
		t.Fatalf("encode jpeg: %v", err)
	}
	return base64.StdEncoding.EncodeToString(out.Bytes())
}

func completeImageSSE(t *testing.T, b64, mediaType string, terminal bool) string {
	t.Helper()
	delta, err := json.Marshal(map[string]any{
		"type": "content_block_delta", "index": 0,
		"delta": map[string]any{"type": "text_delta", "text": "data:" + mediaType + ";base64," + b64},
	})
	if err != nil {
		t.Fatal(err)
	}
	stream := "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":5,\"output_tokens\":0}}}\n\n" +
		"event: content_block_delta\ndata: " + string(delta) + "\n\n" +
		"event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":1120}}\n\n"
	if terminal {
		stream += "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"
	}
	return stream
}

func splitHTTPResponse(t *testing.T, raw string) (string, string) {
	t.Helper()
	parts := strings.SplitN(raw, "\r\n\r\n", 2)
	if len(parts) != 2 {
		t.Fatalf("malformed HTTP response: %s", raw)
	}
	return parts[0], parts[1]
}
