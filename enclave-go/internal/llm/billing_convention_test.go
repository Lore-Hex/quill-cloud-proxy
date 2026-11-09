//go:build llm_multi

package llm

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/billingv1"
	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
	"github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream"
)

// The billing snapshot's prompt convention (billingv1.PromptConvention) says
// whose input count leaves out its cached tokens. In the enclave that is a fact
// about dispatch: InvokeStreaming relays the provider's own Anthropic-format
// stream for amazon-bedrock with an upstream id under us.anthropic. and for
// google-vertex with a direct model id under claude-, and the adapter marks
// such a stream InputExcludesCache when its message_start carries usage
// (internal/adapter/usage_cache_stream_test.go: TestRelayAnthropicStreamRecordsCacheConvention
// and TestUsageChunkFoldsAnthropicCacheEndToEnd). Anthropic's own endpoints are
// native too. Further native relays are outside the rule: azure sends a claude-
// model through its Anthropic wire client (azure.go, azureUsesAnthropicWire),
// zero-g does the same for a claude- upstream id or an anthropic/ model
// (zero_g.go, zeroGUsesAnthropicFormat), and the legacy vertex slug reaches the
// native gcpClient; the catalog has no such Credits endpoint, and the router's
// tests/test_resold_claude_cache_accounting.py fails if one appears, which is
// when the rule must grow on both sides. Every other route reaches the adapter
// with an input count that already includes the cache.
//
// This test drives the real dispatch for every approved Bedrock Claude pair,
// the catalog's Vertex Claude id and two more, anthropic itself, and one
// cache-inclusive model on each of amazon-bedrock, google-vertex and openai. It
// feeds what was relayed to the adapter as the request path does, and requires
// the adapter's flag, the upstream the request reached and the billing rule to
// agree, which is the agreement buildAsyncSettlement insists on before it
// settles asynchronously.
func TestBillingConventionFollowsNativeAnthropicRelays(t *testing.T) {
	type route struct {
		provider, model, upstream, hit string
		native                         bool
	}
	var routes []route
	for model, profile := range bedrockRuntimeModels {
		routes = append(routes, route{"amazon-bedrock", model, profile, "bedrock-runtime.us-east-1.amazonaws.com/model/" + profile + "/invoke-with-response-stream", true})
	}
	sort.Slice(routes, func(i, j int) bool { return routes[i].model < routes[j].model })
	if len(routes) < 3 {
		t.Fatalf("only %d approved Bedrock Claude pairs", len(routes))
	}
	const vertexClaude = "aiplatform.googleapis.com/v1/projects/test-project/locations/global/publishers/anthropic/models/"
	routes = append(routes,
		route{"amazon-bedrock", "qwen/qwen3-32b", "qwen.qwen3-32b", "bedrock-mantle.us-east-1.api.aws/v1/chat/completions", false},
		route{"google-vertex", "anthropic/claude-sonnet-4.6", "claude-sonnet-4-6", vertexClaude + "claude-sonnet-4-6:streamRawPredict", true},
		route{"google-vertex", "anthropic/claude-opus-5.5", "claude-opus-5-5", vertexClaude + "claude-opus-5-5:streamRawPredict", true},
		route{"google-vertex", "anthropic/claude-haiku-4.5", "claude-haiku-4-5@20251001", vertexClaude + "claude-haiku-4-5@20251001:streamRawPredict", true},
		route{"google-vertex", "google/gemini-2.5-flash", "google/gemini-2.5-flash", "aiplatform.googleapis.com/v1/projects/test-project/locations/global/publishers/google/models/gemini-2.5-flash:streamGenerateContent", false},
		route{"anthropic", "anthropic/claude-opus-5.5", "claude-opus-5-5", "api.anthropic.com/v1/messages", true},
		route{"openai", "openai/gpt-4.1", "gpt-4.1", "api.openai.com/v1/chat/completions", false},
	)

	var hits []string
	record := func(r *http.Request) { hits = append(hits, r.URL.Host+r.URL.Path) }
	// Anthropic's own usage shape: the input count leaves out the 8 + 2 cached tokens.
	const nativeUsage = `"usage":{"input_tokens":4,"output_tokens":0,"cache_read_input_tokens":8,"cache_creation_input_tokens":2}`
	// The same stream in Anthropic's SSE framing, and the OpenAI-compatible
	// shape, whose prompt_tokens already includes the 8 cached tokens.
	nativeSSE := "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"test\",\"role\":\"assistant\",\"content\":[]," + nativeUsage + "}}\n\n" +
		"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"PONG\"}}\n\n" +
		"event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":2}}\n\n" +
		"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"
	openAIStream := "data: {\"choices\":[{\"delta\":{\"content\":\"PONG\"},\"finish_reason\":\"stop\"}]}\n\n" +
		"data: {\"choices\":[],\"usage\":{\"prompt_tokens\":16,\"completion_tokens\":3,\"total_tokens\":19,\"prompt_tokens_details\":{\"cached_tokens\":8}}}\n\n"
	bedrockRuntime := newBedrockRuntimeWithHTTP("test-key", &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method == http.MethodGet {
			return runtimeReply(200, `{"mode":"none"}`), nil
		}
		record(r)
		var stream bytes.Buffer
		encoder := eventstream.NewEncoder()
		for _, event := range []string{
			`{"type":"message_start","message":{"id":"test","type":"message","role":"assistant","content":[],` + nativeUsage + `}}`,
			`{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"PONG"}}`,
			`{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":2}}`,
			`{"type":"message_stop"}`,
		} {
			var headers eventstream.Headers
			headers.Set(":message-type", eventstream.StringValue("event"))
			headers.Set(":event-type", eventstream.StringValue("chunk"))
			headers.Set(":content-type", eventstream.StringValue("application/json"))
			wire, _ := json.Marshal(map[string][]byte{"bytes": []byte(event)})
			if err := encoder.Encode(&stream, eventstream.Message{Headers: headers, Payload: wire}); err != nil {
				t.Fatal(err)
			}
		}
		response := runtimeReply(200, stream.String())
		response.Header.Set("Content-Type", "application/vnd.amazon.eventstream")
		return response, nil
	})})
	direct := newBootstrapDirectClients(map[string]string{"amazon-bedrock": "test-key"})
	if direct["amazon-bedrock"] == nil {
		t.Fatal("Bedrock prepaid client missing")
	}
	direct["amazon-bedrock"].httpc = &http.Client{Transport: byokRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		record(r)
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/event-stream"}}, Body: io.NopCloser(strings.NewReader(openAIStream))}, nil
	})}
	anthropic := &anthropicClient{provider: "anthropic", url: anthropicURL, apiKey: "test-key", httpc: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		record(r)
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(nativeSSE))}, nil
	})}}
	openai := newOpenAICompatible("openai", "test-key")
	openai.httpc = &http.Client{Transport: byokRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		record(r)
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/event-stream"}}, Body: io.NopCloser(strings.NewReader(openAIStream))}, nil
	})}
	vertex := &vertexGeminiClient{auth: &gcpClient{
		projectID: "test-project", region: "global", token: "vertex-token", tokenExp: time.Now().Add(time.Hour),
		httpc: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			record(r)
			var sse string
			if strings.Contains(r.URL.Path, "/publishers/anthropic/") {
				sse = nativeSSE
			} else {
				// Gemini's shape: promptTokenCount already includes the 8 cached tokens.
				sse = "data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"PONG\"}],\"role\":\"model\"},\"finishReason\":\"STOP\"}]," +
					"\"usageMetadata\":{\"promptTokenCount\":16,\"candidatesTokenCount\":3,\"totalTokenCount\":19,\"cachedContentTokenCount\":8}}\n\n"
			}
			return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(sse))}, nil
		})},
	}}
	multi := &multiClient{bedrockRuntime: bedrockRuntime, direct: direct, googleVertex: vertex, anthropic: anthropic, openai: openai}

	for _, r := range routes {
		t.Run(r.provider+"/"+r.model, func(t *testing.T) {
			hits = nil
			var out bytes.Buffer
			err := multi.InvokeStreaming(t.Context(),
				&qtypes.OpenAIChatRequest{Model: r.model, Messages: []qtypes.OpenAIChatMessage{{Role: "user", Content: "Reply PONG"}}},
				&qtypes.AnthropicMessagesRequest{MaxTokens: 32, Messages: []qtypes.AnthropicMessage{{Role: "user", Content: "Reply PONG"}}},
				&out, InvokeOptions{Provider: r.provider, UpstreamModel: r.upstream})
			if err != nil {
				t.Fatal(err)
			}
			if len(hits) != 1 || hits[0] != r.hit {
				t.Fatalf("reached %v, want %s", hits, r.hit)
			}
			result, err := adapter.TransformStreamCaptureWithOptions(strings.NewReader(out.String()), io.Discard, "req", r.model, true)
			if err != nil || result.Usage == nil || result.Usage.CacheReadInputTokens != 8 {
				t.Fatalf("relayed usage lost: %+v (%v)", result.Usage, err)
			}
			if result.Usage.InputExcludesCache != r.native {
				t.Fatalf("adapter InputExcludesCache=%v, want %v", result.Usage.InputExcludesCache, r.native)
			}
			if input := result.Usage.InputTokens; (r.native && input != 4) || (!r.native && input != 16) {
				t.Fatalf("input count %d does not match the relayed shape", input)
			}
			if excludes := billingv1.PromptConvention(r.provider, r.model) == "excludes_cache"; excludes != r.native {
				t.Fatalf("billing rule says excludes_cache=%v, dispatch relays natively=%v", excludes, r.native)
			}
		})
	}
}
