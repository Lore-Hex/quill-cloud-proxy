//go:build llm_multi

package llm

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

const tencentTestStream = "data: {\"choices\":[{\"delta\":{\"reasoning_content\":\"think\"}}]}\n\n" +
	"data: {\"choices\":[{\"delta\":{\"content\":\"PONG\"},\"finish_reason\":\"stop\"}]}\n\n" +
	"data: {\"choices\":[],\"usage\":{\"prompt_tokens\":12,\"completion_tokens\":8,\"total_tokens\":20,\"prompt_tokens_details\":{\"cached_tokens\":4},\"completion_tokens_details\":{\"reasoning_tokens\":6}}}\n\n" +
	"data: [DONE]\n\n"

func TestTencentPrepaidAndBYOKWire(t *testing.T) {
	for _, nativeModel := range []string{"hy4-preview", "mimo-v2.6-flash", "glm-5.3", "kimi-k2.7-code", "kimi-k2.7-code-highspeed", "kimi-k2.8-preview", "kimi-k3", "deepseek/deepseek-flash", "Vendor/Model:free", "ep-test"} {
		for _, byok := range []bool{false, true} {
			mode := "prepaid"
			key := "operator-test-key"
			if byok {
				mode, key = "byok", "workspace-test-key"
			}
			t.Run(mode+"/"+nativeModel, func(t *testing.T) {
				calls := 0
				httpc := &http.Client{Transport: byokRoundTripFunc(func(r *http.Request) (*http.Response, error) {
					calls++
					if r.Method != http.MethodPost || r.URL.String() != "https://tokenhub-intl.tencentcloudmaas.com/v1/chat/completions" {
						t.Fatalf("unexpected endpoint: %s %s", r.Method, r.URL)
					}
					if r.Header.Get("Authorization") != "Bearer "+key {
						t.Fatal("wrong prepaid/BYOK credential selected")
					}
					var wire openAICompatibleRequest
					if err := json.NewDecoder(r.Body).Decode(&wire); err != nil {
						t.Fatal(err)
					}
					capOK := wire.MaxTokens == 32 && wire.MaxCompletionTokens == 0
					if nativeModel == "kimi-k3" {
						capOK = wire.MaxCompletionTokens == 32 && wire.MaxTokens == 0
					}
					if wire.Model != nativeModel || !wire.Stream || !capOK || wire.StreamOptions == nil || !wire.StreamOptions.IncludeUsage {
						t.Fatalf("model or streaming contract changed: %#v", wire)
					}
					if wire.Thinking != nil || wire.Reasoning != nil || wire.ReasoningEffort != "" {
						t.Fatalf("changed native default thinking: %#v", wire)
					}
					return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"text/event-stream"}}, Body: io.NopCloser(strings.NewReader(tencentTestStream))}, nil
				})}
				req := &qtypes.OpenAIChatRequest{Model: "author/public-alias"}
				body := &qtypes.AnthropicMessagesRequest{
					Messages:  []qtypes.AnthropicMessage{{Role: "user", Content: "PONG"}},
					MaxTokens: 32, MaxTokensExplicit: true,
				}
				option := InvokeOptions{Provider: "tencent", UpstreamModel: nativeModel}
				var out bytes.Buffer
				var err error
				if byok {
					option.ProviderAPIKey = key
					err = invokeOpenAICompatibleBYOKStreamingWithClient(t.Context(), httpc, "tencent", req, body, &out, option)
				} else {
					clients := newBootstrapDirectClients(map[string]string{"tencent": " " + key + " "})
					if clients["tencent"] == nil {
						t.Fatal("missing prepaid Tencent client")
					}
					clients["tencent"].httpc = httpc
					multi := &multiClient{direct: clients}
					err = multi.InvokeStreaming(t.Context(), req, body, &out, option)
				}
				if err != nil || calls != 1 {
					t.Fatalf("calls=%d error=%v", calls, err)
				}
				for _, want := range []string{"PONG", "thinking_delta", `"input_tokens":12`, `"output_tokens":8`, `"reasoning_tokens":6`, "message_stop"} {
					if !strings.Contains(out.String(), want) {
						t.Fatalf("stream missing %s: %s", want, out.String())
					}
				}
			})
		}
	}
}

func TestTencentBYOKDispatchWithoutOperatorKey(t *testing.T) {
	if !isOpenAICompatibleBYOKProvider("tencent") {
		t.Fatal("Tencent BYOK is not enabled")
	}
	// Missing model fails before I/O, but only after the BYOK dispatcher accepts
	// the provider. No operator client or secret may be required on this path.
	multi := &multiClient{}
	err := multi.InvokeStreaming(t.Context(), &qtypes.OpenAIChatRequest{Model: "author/public-alias"}, &qtypes.AnthropicMessagesRequest{}, io.Discard,
		InvokeOptions{Provider: "tencent", ProviderAPIKey: "workspace-test-key"})
	if err == nil || !strings.Contains(err.Error(), "missing authorized upstream model") {
		t.Fatalf("BYOK dispatch = %v", err)
	}
	err = multi.InvokeStreaming(t.Context(), &qtypes.OpenAIChatRequest{}, &qtypes.AnthropicMessagesRequest{}, io.Discard, InvokeOptions{Provider: "tencent"})
	if err == nil || !strings.Contains(err.Error(), "prepaid credential is unavailable") {
		t.Fatalf("unconfigured prepaid Tencent must fail closed: %v", err)
	}
	if got := directModelID("tencent", "author/public-alias", ""); got != "" {
		t.Fatalf("guessed a Tencent model: %q", got)
	}
}

func TestTencentStreamFailsClosed(t *testing.T) {
	for name, stream := range map[string]string{
		"error":         "data: {\"error\":{\"type\":\"gateway_error\",\"message\":\"PRIVATE\",\"code\":429001}}\n\ndata: [DONE]\n\n",
		"partial_error": "data: {\"choices\":[{\"delta\":{\"content\":\"partial\"}}]}\n\ndata: {\"error\":{\"message\":\"PRIVATE\"}}\n\ndata: [DONE]\n\n",
		"delta_error":   "data: {\"choices\":[{\"delta\":{\"error\":{\"message\":\"PRIVATE\"}}}]}\n\ndata: [DONE]\n\n",
		"malformed":     "data: {PRIVATE}\n\n" + tencentTestStream,
		"truncated":     strings.ReplaceAll(tencentTestStream, "data: [DONE]\n\n", ""),
		"no_finish":     strings.ReplaceAll(tencentTestStream, `,"finish_reason":"stop"`, ""),
		"no_usage":      "data: {\"choices\":[{\"delta\":{\"content\":\"PONG\"},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n",
		"empty":         "",
	} {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			err := translateOpenAIStreamToAnthropicForProvider(strings.NewReader(stream), &out, "tencent")
			if err == nil || strings.Contains(err.Error(), "PRIVATE") || strings.Contains(out.String(), "message_stop") {
				t.Fatalf("failed stream became success or leaked an error body: err=%v output=%s", err, out.String())
			}
		})
	}
}

func TestTencentReasoningControls(t *testing.T) {
	for _, model := range []string{"hy3", "hy4-preview", "mimo-v2.6-flash", "glm-5.2", "minimax-m3"} {
		for _, enabled := range []bool{false, true} {
			req := &qtypes.OpenAIChatRequest{Reasoning: map[string]any{"enabled": enabled}, ReasoningEffort: "high"}
			wire := buildOpenAICompatibleRequest("tencent", model, req, &qtypes.AnthropicMessagesRequest{}, nil)
			mode := "disabled"
			if enabled {
				mode = "enabled"
				if model == "minimax-m3" {
					mode = "adaptive"
				}
			}
			thinking, _ := wire.Thinking.(map[string]string)
			if thinking["type"] != mode || wire.Reasoning != nil || (!enabled && wire.ReasoningEffort != "") {
				t.Fatalf("incorrect native reasoning control: %#v", wire)
			}
			if err := validateTencentThinking(wire); err != nil {
				t.Fatal(err)
			}
		}
	}
	wire := buildOpenAICompatibleRequest("tencent", "hy4-preview",
		&qtypes.OpenAIChatRequest{Reasoning: map[string]any{"effort": "high"}},
		&qtypes.AnthropicMessagesRequest{Thinking: map[string]any{"type": "enabled", "budget_tokens": 4096}}, nil)
	if wire.ReasoningEffort != "high" || wire.Reasoning != nil || wire.Thinking != nil {
		t.Fatalf("nested effort was not normalized: %#v", wire)
	}
	for model, defaultEffort := range map[string]string{"kimi-k3": "high", "kimi-k2.8-preview": "max"} {
		for _, effort := range []string{"", "low", "max"} {
			wire := buildOpenAICompatibleRequest("tencent", model,
				&qtypes.OpenAIChatRequest{Reasoning: map[string]any{"enabled": true}, ReasoningEffort: effort},
				&qtypes.AnthropicMessagesRequest{}, nil)
			want := effort
			if want == "" {
				want = defaultEffort
			}
			if wire.Thinking != nil || wire.Reasoning != nil || wire.ReasoningEffort != want {
				t.Fatalf("%s effort control = %#v", model, wire)
			}
		}
	}
}

func TestTencentUnsupportedThinkingFailsBeforeUpstream(t *testing.T) {
	httpc := &http.Client{Transport: byokRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		t.Fatal("unsupported thinking reached upstream")
		return nil, nil
	})}
	for _, model := range []string{"glm-5.3", "glm-5.3-flash", "glm-5.3-flashx", "kimi-k2.7-code", "kimi-k2.7-code-highspeed", "kimi-k3", "kimi-k2.8-preview"} {
		for _, native := range []bool{false, true} {
			req := &qtypes.OpenAIChatRequest{Reasoning: map[string]any{"enabled": false}}
			body := &qtypes.AnthropicMessagesRequest{}
			if native {
				req.Reasoning = nil
				body.NativeContent = true
				body.Thinking = map[string]any{"type": "disabled"}
			}
			err := invokeOpenAICompatibleBYOKStreamingWithClient(t.Context(), httpc, "tencent", req, body, io.Discard,
				InvokeOptions{ProviderAPIKey: "test-key", UpstreamModel: model})
			if status, ok := HTTPStatusFromError(err); !ok || status != http.StatusBadRequest {
				t.Fatalf("%s native=%t: wanted explicit 400, got %v", model, native, err)
			}
		}
	}
}

func TestTencentKimiSamplingAndUserPrivacy(t *testing.T) {
	zero := 0.0
	for _, model := range []string{"kimi-k3", "kimi-k2.8-preview", "kimi-k2.7-code", "kimi-k2.7-code-highspeed"} {
		wire := buildOpenAICompatibleRequest("tencent", model,
			&qtypes.OpenAIChatRequest{User: "private-user", FrequencyPenalty: &zero, PresencePenalty: &zero},
			&qtypes.AnthropicMessagesRequest{Temperature: &zero, TopP: &zero}, nil)
		encoded, err := json.Marshal(wire)
		if err != nil {
			t.Fatal(err)
		}
		if wire.Temperature != nil || wire.TopP != nil || wire.FrequencyPenalty != nil || wire.PresencePenalty != nil || strings.Contains(string(encoded), "private-user") {
			t.Fatalf("%s sampling or user contract: %s", model, encoded)
		}
	}
}
