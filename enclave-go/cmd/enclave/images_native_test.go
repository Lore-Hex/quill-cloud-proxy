//go:build llm_multi

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/auth"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/imagegen"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
)

type imageRoundTripFunc func(*http.Request) (*http.Response, error)

func (f imageRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestServeNativeXAIImageUsesFixedQuoteAndSettlesBeforeResponse(t *testing.T) {
	var mu sync.Mutex
	var authorize, settle map[string]any
	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
			t.Errorf("decode %s: %v", req.URL.Path, err)
			http.Error(w, "bad request", 400)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch req.URL.Path {
		case "/internal/gateway/authorize":
			authorize = body
			_, _ = io.WriteString(w, `{"data":{"authorization_id":"auth_xai_image","workspace_id":"ws_image","api_key_hash":"hash_image","model":"x-ai/grok-imagine-image-2.0","upstream_model":"grok-imagine-image-2.0","endpoint_id":"x-ai/grok-imagine-image-2.0@grok/prepaid","provider":"grok","usage_type":"Credits","additional_cost_reservation_microdollars":63300,"route_candidates":[{"endpoint_id":"x-ai/grok-imagine-image-2.0@grok/prepaid","model":"x-ai/grok-imagine-image-2.0","upstream_model":"grok-imagine-image-2.0","provider":"grok","usage_type":"Credits"}]}}`)
		case "/internal/gateway/settle":
			settle = body
			_, _ = io.WriteString(w, `{"data":{"generation_id":"gen_xai_image","cost_microdollars":63300,"cost":0.0633,"input_tokens":0,"output_tokens":0,"usage_type":"Credits","model":"x-ai/grok-imagine-image-2.0","provider":"grok","region":"us-central1","settled":true}}`)
		case "/internal/gateway/refund":
			_, _ = io.WriteString(w, `{"data":{"settled":true,"finalization_outcome":"refunded"}}`)
		default:
			http.Error(w, "unexpected path", 404)
		}
	}))
	defer control.Close()
	gateway := trustedrouter.New(control.URL, "internal", control.Client())

	var providerBody map[string]any
	providerClient := &http.Client{Transport: imageRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.String() != "https://api.x.ai/v1/images/generations" {
			t.Fatalf("provider URL = %s", req.URL)
		}
		if req.Header.Get("Authorization") != "Bearer managed-xai" ||
			req.Header.Get("Idempotency-Key") != "native-xai-one" {
			t.Fatalf("provider headers = %#v", req.Header)
		}
		if err := json.NewDecoder(req.Body).Decode(&providerBody); err != nil {
			t.Fatal(err)
		}
		payload, _ := json.Marshal(map[string]any{
			"created": 123,
			"data":    []map[string]any{{"b64_json": jpegBase64(t, 1024, 1024)}},
			"usage":   map[string]any{},
		})
		return &http.Response{
			StatusCode: 200, Header: make(http.Header),
			Body: io.NopCloser(bytes.NewReader(payload)),
		}, nil
	})}
	previous := imageProviderGateway
	imageProviderGateway = imagegen.NewRegistry(
		imagegen.ProviderKeys{XAI: "managed-xai"}, providerClient,
	)
	defer func() { imageProviderGateway = previous }()

	body := `{"model":"x-ai/grok-imagine-image-2.0","prompt":"private red panda","aspect_ratio":"1:1"}`
	request := fmt.Sprintf(
		"POST /v1/images HTTP/1.1\r\nHost: api.trustedrouter.com\r\nAuthorization: Bearer sk-secret\r\nIdempotency-Key: native-xai-one\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
		len(body), body,
	)
	conn := newScriptedConn(request, nil)
	serveOne(context.Background(), conn, auth.New(nil), &imageTestLLM{}, nil, nil, gateway, nil)

	head, responseBody := splitHTTPResponse(t, conn.writes.String())
	if !strings.Contains(head, "HTTP/1.1 200 OK") {
		t.Fatalf("response head = %s\n%s", head, responseBody)
	}
	var response struct {
		Data  []map[string]any `json:"data"`
		Usage map[string]any   `json:"usage"`
	}
	if err := json.Unmarshal([]byte(responseBody), &response); err != nil {
		t.Fatalf("decode response: %v\n%s", err, responseBody)
	}
	if len(response.Data) != 1 || response.Data[0]["media_type"] != "image/jpeg" ||
		response.Usage["cost"] != 0.0633 {
		t.Fatalf("response = %#v", response)
	}
	mu.Lock()
	defer mu.Unlock()
	if authorize["additional_cost_reservation_microdollars"] != float64(63_300) ||
		authorize["route_type"] != "images" {
		t.Fatalf("authorize = %#v", authorize)
	}
	authorizeJSON, _ := json.Marshal(authorize)
	if bytes.Contains(authorizeJSON, []byte("private red panda")) {
		t.Fatalf("prompt leaked to authorization: %s", authorizeJSON)
	}
	if settle["additional_cost_microdollars"] != float64(63_300) ||
		settle["actual_output_tokens"] != float64(0) || settle["route_type"] != "images" {
		t.Fatalf("settle = %#v", settle)
	}
	if providerBody["quality"] != "medium" || providerBody["resolution"] != "1k" {
		t.Fatalf("provider body = %#v", providerBody)
	}
}

func TestServeNativeOpenAIImageSettlesTokenUsageBeforeCompletionStream(t *testing.T) {
	var mu sync.Mutex
	var authorize, settle map[string]any
	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
			t.Errorf("decode %s: %v", req.URL.Path, err)
			http.Error(w, "bad request", 400)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch req.URL.Path {
		case "/internal/gateway/authorize":
			authorize = body
			_, _ = io.WriteString(w, `{"data":{"authorization_id":"auth_openai_image","workspace_id":"ws_image","api_key_hash":"hash_image","model":"openai/gpt-image-2","upstream_model":"gpt-image-2","endpoint_id":"openai/gpt-image-2@openai/prepaid","provider":"openai","usage_type":"Credits","route_candidates":[{"endpoint_id":"openai/gpt-image-2@openai/prepaid","model":"openai/gpt-image-2","upstream_model":"gpt-image-2","provider":"openai","usage_type":"Credits"}]}}`)
		case "/internal/gateway/settle":
			settle = body
			_, _ = io.WriteString(w, `{"data":{"generation_id":"gen_openai_image","cost_microdollars":2655,"cost":0.002655,"input_tokens":21,"output_tokens":85,"usage_type":"Credits","model":"openai/gpt-image-2","provider":"openai","region":"us-central1","settled":true}}`)
		case "/internal/gateway/refund":
			_, _ = io.WriteString(w, `{"data":{"settled":true,"finalization_outcome":"refunded"}}`)
		default:
			http.Error(w, "unexpected path", 404)
		}
	}))
	defer control.Close()
	gateway := trustedrouter.New(control.URL, "internal", control.Client())

	var providerBody map[string]any
	providerClient := &http.Client{Transport: imageRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.String() != "https://api.openai.com/v1/images/generations" {
			t.Fatalf("provider URL = %s", req.URL)
		}
		if req.Header.Get("Authorization") != "Bearer managed-openai" ||
			req.Header.Get("Idempotency-Key") != "native-openai-one" {
			t.Fatalf("provider headers = %#v", req.Header)
		}
		if err := json.NewDecoder(req.Body).Decode(&providerBody); err != nil {
			t.Fatal(err)
		}
		payload, _ := json.Marshal(map[string]any{
			"created": 456,
			"data":    []map[string]any{{"b64_json": jpegBase64(t, 1536, 864)}},
			"usage": map[string]any{
				"input_tokens": 21, "output_tokens": 85, "total_tokens": 106,
			},
		})
		return &http.Response{
			StatusCode: 200, Header: make(http.Header),
			Body: io.NopCloser(bytes.NewReader(payload)),
		}, nil
	})}
	previous := imageProviderGateway
	imageProviderGateway = imagegen.NewRegistry(
		imagegen.ProviderKeys{OpenAI: "managed-openai"}, providerClient,
	)
	defer func() { imageProviderGateway = previous }()

	body := `{"model":"openai/gpt-image-2","prompt":"private red panda","aspect_ratio":"16:9","quality":"low","output_format":"jpeg","output_compression":70,"stream":true}`
	request := fmt.Sprintf(
		"POST /v1/images HTTP/1.1\r\nHost: api.trustedrouter.com\r\nAuthorization: Bearer sk-secret\r\nIdempotency-Key: native-openai-one\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
		len(body), body,
	)
	conn := newScriptedConn(request, nil)
	serveOne(context.Background(), conn, auth.New(nil), &imageTestLLM{}, nil, nil, gateway, nil)

	head, responseBody := splitHTTPResponse(t, conn.writes.String())
	if !strings.Contains(head, "HTTP/1.1 200 OK") ||
		!strings.Contains(head, "Content-Type: text/event-stream") {
		t.Fatalf("response head = %s\n%s", head, responseBody)
	}
	if !strings.Contains(responseBody, `"type":"image_generation.completed"`) ||
		!strings.Contains(responseBody, "data: [DONE]") ||
		!strings.Contains(responseBody, `"cost":0.002655`) {
		t.Fatalf("stream body = %s", responseBody)
	}
	mu.Lock()
	defer mu.Unlock()
	if authorize["additional_cost_reservation_microdollars"] != nil ||
		authorize["route_type"] != "images" || authorize["max_tokens"] != float64(8_000) {
		t.Fatalf("authorize = %#v", authorize)
	}
	if settle["actual_input_tokens"] != float64(21) ||
		settle["actual_output_tokens"] != float64(85) ||
		settle["additional_cost_microdollars"] != nil || settle["streamed"] != true {
		t.Fatalf("settle = %#v", settle)
	}
	if providerBody["size"] != "1536x864" || providerBody["quality"] != "low" ||
		providerBody["output_format"] != "jpeg" || providerBody["output_compression"] != float64(70) {
		t.Fatalf("provider body = %#v", providerBody)
	}
}
