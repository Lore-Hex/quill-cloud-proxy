package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image"
	"image/jpeg"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/imagegen"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

// The float deliberately disagrees with the integer: only the settled integer
// is authoritative, and a legacy float alone must not imply a known cost.
func mediaCostGateway(t *testing.T, out *bytes.Buffer, model, provider, route, scenario string) *trustedrouter.Client {
	t.Helper()
	settles := 0
	t.Cleanup(func() {
		if settles != 1 {
			t.Errorf("settlements = %d, want 1", settles)
		}
	})
	return trustedrouter.New("http://127.0.0.1:18080", "test", &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		var data any
		switch r.URL.Path {
		case "/internal/gateway/authorize":
			data = &trustedrouter.Authorization{
				AuthorizationID: "media-cost", Model: model, Provider: provider,
				EndpointID: "served", UsageType: "Credits",
			}
		case "/internal/gateway/settle":
			settles++
			if out.Len() != 0 {
				t.Fatal("response written before settlement")
			}
			var billed map[string]any
			if err := json.NewDecoder(r.Body).Decode(&billed); err != nil {
				t.Fatal(err)
			}
			if billed["route_type"] != route || billed["selected_endpoint"] != "served" {
				t.Fatalf("unexpected settlement: %#v", billed)
			}
			settlement := map[string]any{
				"settled": true, "cost": 0.25, "usage_type": "Credits",
				"model": model, "provider": provider, "region": "test-region",
			}
			switch scenario {
			case "known":
				settlement["cost_microdollars"] = 19
			case "zero":
				settlement["cost_microdollars"] = 0
			}
			data = settlement
		default:
			t.Fatalf("unexpected control-plane request: %s", r.URL)
		}
		body, err := json.Marshal(map[string]any{"data": data})
		if err != nil {
			t.Fatal(err)
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(body))}, nil
	})})
}

func mediaResponseBody(t *testing.T, out *bytes.Buffer) []byte {
	t.Helper()
	resp, err := http.ReadResponse(bufio.NewReader(out), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d: %s", resp.StatusCode, body)
	}
	return body
}

func assertMediaUsageCost(t *testing.T, usage, unchanged map[string]any, scenario string) {
	t.Helper()
	for _, key := range []string{"cost_microdollars", "total_cost_microdollars"} {
		value, present := usage[key]
		if scenario == "unknown" {
			if present {
				t.Errorf("unknown %s must be omitted, got %v", key, value)
			}
		} else {
			want := float64(19)
			if scenario == "zero" {
				want = 0
			}
			if !present || value != want {
				t.Errorf("%s = %v (present %t), want %v", key, value, present, want)
			}
		}
		delete(usage, key)
	}
	if !reflect.DeepEqual(usage, unchanged) {
		t.Errorf("existing usage changed: got %#v, want %#v", usage, unchanged)
	}
}

type mediaCostEmbeddingLLM struct {
	fakeStreamingLLM
	vector json.RawMessage
}

func (f *mediaCostEmbeddingLLM) InvokeEmbedding(_ context.Context, req *types.EmbeddingRequest, _ ...llm.InvokeOptions) (*types.EmbeddingResponse, error) {
	return &types.EmbeddingResponse{
		Object: "list", Model: req.Model,
		Data:  []types.EmbeddingData{{Object: "embedding", Index: 0, Embedding: f.vector}},
		Usage: types.EmbeddingUsage{PromptTokens: 7, TotalTokens: 7},
	}, nil
}

func TestEmbeddingsReportOnlyKnownSettledCostAndPreserveResponse(t *testing.T) {
	for _, batch := range []bool{false, true} {
		for _, vector := range []string{`[0.12345678901234567890123456789,1e-30]`, `"AACAPwAAAEA="`} {
			for _, scenario := range []string{"known", "unknown", "zero"} {
				t.Run(fmt.Sprintf("batch=%t/vector=%s/%s", batch, vector, scenario), func(t *testing.T) {
					var out bytes.Buffer
					const model = "openai/text-embedding-3-small"
					gateway := mediaCostGateway(t, &out, model, "openai", "embeddings", scenario)
					ctx := context.Background()
					if batch {
						ctx = context.WithValue(ctx, batchExecutionContextKey{}, true)
					}
					backend := &mediaCostEmbeddingLLM{vector: json.RawMessage(vector)}
					serveEmbeddings(ctx, &out, backend, []byte(`{"model":"`+model+`","input":"hello"}`), gateway, true, "test", nil, "media-cost", requestAttributionHeaders{}, "media-cost")
					body := mediaResponseBody(t, &out)
					var payload map[string]any
					if err := json.Unmarshal(body, &payload); err != nil {
						t.Fatal(err)
					}
					usage, ok := payload["usage"].(map[string]any)
					if !ok {
						t.Fatal("response has no usage object")
					}
					wantUsage := map[string]any{"prompt_tokens": float64(7), "total_tokens": float64(7)}
					if batch {
						wantUsage["provider_usage"] = map[string]any{
							"usage_type": "Credits", "selected_model": model, "selected_provider": "openai",
							"region": "test-region", "contains_prompt_or_completion": false,
						}
					} else if !bytes.Contains(body, []byte(`"embedding":`+vector)) {
						t.Error("interactive embedding encoding or precision changed")
					}
					assertMediaUsageCost(t, usage, wantUsage, scenario)
					delete(payload, "usage")
					var decodedVector any
					if err := json.Unmarshal([]byte(vector), &decodedVector); err != nil {
						t.Fatal(err)
					}
					want := map[string]any{"object": "list", "model": model, "data": []any{map[string]any{
						"object": "embedding", "index": float64(0), "embedding": decodedVector,
					}}}
					if !reflect.DeepEqual(payload, want) {
						t.Errorf("embedding response changed: %#v", payload)
					}
				})
			}
		}
	}
}

type mediaCostImageLLM struct{ stream string }

func (f *mediaCostImageLLM) InvokeStreaming(_ context.Context, _ *types.OpenAIChatRequest, _ *types.AnthropicMessagesRequest, out io.Writer, _ ...llm.InvokeOptions) error {
	_, err := io.WriteString(out, f.stream)
	return err
}

func TestGeminiImagesReportOnlyKnownSettledCostAndPreserveResponse(t *testing.T) {
	testImagesReportOnlyKnownSettledCost(t, false)
}

func TestNativeImagesReportOnlyKnownSettledCostAndPreserveResponse(t *testing.T) {
	testImagesReportOnlyKnownSettledCost(t, true)
}

func testImagesReportOnlyKnownSettledCost(t *testing.T, native bool) {
	t.Helper()
	var jpegBytes bytes.Buffer
	if err := jpeg.Encode(&jpegBytes, image.NewRGBA(image.Rect(0, 0, 1024, 1024)), nil); err != nil {
		t.Fatal(err)
	}
	b64 := base64.StdEncoding.EncodeToString(jpegBytes.Bytes())
	model, provider := "google/gemini-3.1-flash-image", "google-ai-studio"
	if native {
		model, provider = "openai/gpt-image-2", "openai"
		previous := imageProviderGateway
		t.Cleanup(func() { imageProviderGateway = previous })
		imageProviderGateway = imagegen.NewRegistry(imagegen.ProviderKeys{OpenAI: "test"}, &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.URL.String() != "https://api.openai.com/v1/images/generations" {
				t.Fatalf("unexpected provider request: %s", r.URL)
			}
			body := `{"created":123,"data":[{"b64_json":"` + b64 + `"},{"b64_json":"` + b64 + `"}],"usage":{"input_tokens":21,"output_tokens":85,"total_tokens":106,"input_tokens_details":{"text_tokens":21,"image_tokens":0,"cached_tokens":10}}}`
			return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
		})})
	}
	for _, stream := range []bool{false, true} {
		for _, scenario := range []string{"known", "unknown", "zero"} {
			t.Run(fmt.Sprintf("stream=%t/%s", stream, scenario), func(t *testing.T) {
				var out bytes.Buffer
				gateway := mediaCostGateway(t, &out, model, provider, "images", scenario)
				extra := ""
				if native {
					extra = `,"n":2,"output_format":"jpeg"`
				}
				body := fmt.Sprintf(`{"model":%q,"prompt":"cat","stream":%t%s}`, model, stream, extra)
				backend := &mediaCostImageLLM{stream: "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":5,\"output_tokens\":0}}}\n\n" +
					"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"data:image/jpeg;base64," + b64 + "\"}}\n\n" +
					"event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":1120}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"}
				serveImages(context.Background(), &out, backend, []byte(body), gateway, "test", nil, "media-cost", requestAttributionHeaders{}, "media-cost")
				responseBody := mediaResponseBody(t, &out)
				payloads := [][]byte{responseBody}
				imageCount := 1
				if native {
					imageCount = 2
				}
				if stream {
					payloads = nil
					if !bytes.HasSuffix(responseBody, []byte("data: [DONE]\n\n")) {
						t.Fatal("missing terminal DONE event")
					}
					for _, line := range strings.Split(string(responseBody), "\n") {
						if strings.HasPrefix(line, "data: {") {
							payloads = append(payloads, []byte(strings.TrimPrefix(line, "data: ")))
						}
					}
					if len(payloads) != imageCount {
						t.Fatalf("completed events = %d, want %d", len(payloads), imageCount)
					}
				}
				for _, raw := range payloads {
					var payload map[string]any
					if err := json.Unmarshal(raw, &payload); err != nil {
						t.Fatal(err)
					}
					usage, ok := payload["usage"].(map[string]any)
					if !ok {
						t.Fatal("image response has no usage object")
					}
					wantUsage := map[string]any{"prompt_tokens": float64(5), "completion_tokens": float64(1120), "total_tokens": float64(1125), "cost": 0.25}
					if native {
						wantUsage = map[string]any{"prompt_tokens": float64(21), "completion_tokens": float64(85), "total_tokens": float64(106), "cost": 0.25,
							"prompt_tokens_details": map[string]any{"cached_tokens": float64(10)}}
					}
					assertMediaUsageCost(t, usage, wantUsage, scenario)
					delete(payload, "usage")
					created, ok := payload["created"].(float64)
					if !ok || created <= 0 || (native && created != 123) {
						t.Errorf("created changed: %v", payload["created"])
					}
					delete(payload, "created")
					want := map[string]any{"type": "image_generation.completed", "b64_json": b64, "media_type": "image/jpeg"}
					if !stream {
						data := make([]any, imageCount)
						for i := range data {
							data[i] = map[string]any{"b64_json": b64, "media_type": "image/jpeg"}
						}
						want = map[string]any{"data": data}
					}
					if !reflect.DeepEqual(payload, want) {
						t.Error("image response fields or data changed")
					}
				}
			})
		}
	}
}
