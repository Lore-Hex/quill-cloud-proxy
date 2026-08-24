//go:build llm_multi

package llm

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestMultiClientDispatchesPrepaidOpenAICompatibleProviders(t *testing.T) {
	tests := []struct {
		provider      string
		publicModel   string
		upstreamModel string
		wantModel     string
		wantWaferZDR  bool
	}{
		{"openai", "openai/gpt-4o-mini", "openai/gpt-4o-mini", "gpt-4o-mini", false},
		{"google-ai-studio", "google/gemini-2.5-flash", "google/gemini-2.5-flash", "gemini-2.5-flash", false},
		{"cerebras", "meta-llama/llama-3.1-8b-instruct", "meta-llama/llama-3.1-8b-instruct", "llama3.1-8b", false},
		{"deepseek", "deepseek/deepseek-v4-flash", "deepseek/deepseek-v4-flash", "deepseek-v4-flash", false},
		{"mistral", "mistralai/mistral-small-2603", "mistralai/mistral-small-2603", "mistral-small-2603", false},
		{"fireworks", "openai/gpt-oss-120b", "accounts/fireworks/models/gpt-oss-120b", "accounts/fireworks/models/gpt-oss-120b", false},
		{"friendli", "z-ai/glm-5.2", "zai-org/GLM-5.2", "zai-org/GLM-5.2", false},
		{"baseten", "z-ai/glm-5.2", "zai-org/GLM-5.2", "zai-org/GLM-5.2", false},
		{"baseten", "nvidia/nemotron-3-ultra-550b-a55b", "nvidia/NVIDIA-Nemotron-3-Ultra-550B-A55B", "nvidia/NVIDIA-Nemotron-3-Ultra-550B-A55B", false},
		{"telnyx", "moonshotai/kimi-k3", "moonshotai/Kimi-K3", "moonshotai/Kimi-K3", false},
		{"thinkingmachines", "thinkingmachines/inkling", "thinkingmachines/Inkling:peft:262144", "thinkingmachines/Inkling:peft:262144", false},
		{"wafer", "z-ai/glm-5.2", "GLM-5.2", "GLM-5.2", true},
		{"wafer", "moonshotai/kimi-k2.7-code", "Kimi-K2.7-Code", "Kimi-K2.7-Code", false},
		{"wafer", "qwen/qwen3.6-35b-a3b", "Qwen3.6-35B-A3B", "Qwen3.6-35B-A3B", false},
		{"crusoe", "z-ai/glm-5.2", "zai/GLM-5.2", "zai/GLM-5.2", false},
		{"makora", "z-ai/glm-5.2", "zai-org/GLM-5.2-FP8", "zai-org/GLM-5.2-FP8", false},
		{"nebius", "Qwen/Qwen3.5-397B-A17B", "Qwen/Qwen3.5-397B-A17B", "Qwen/Qwen3.5-397B-A17B", false},
		{"minimax", "minimax/minimax-m2.7", "MiniMax-M2.7", "MiniMax-M2.7", false},
		{"inceptron", "moonshotai/kimi-k2.7-code", "moonshotai/Kimi-K2.7-Code", "moonshotai/Kimi-K2.7-Code", false},
		{"morph", "z-ai/glm-5.2", "morph-glm52-744b", "morph-glm52-744b", false},
		{"atlas-cloud", "z-ai/glm-5.2", "zai-org/glm-5.2", "zai-org/glm-5.2", false},
		{"streamlake", "kwaipilot/kat-coder-pro-v2.5", "kat-coder-pro-v2.5", "kat-coder-pro-v2.5", false},
		{"neurometric", "ibm-granite/granite-4.1-8b", "ibm-granite/granite-4.1-8b", "ibm-granite/granite-4.1-8b", false},
		{"pearl", "deepseek/deepseek-v4-pro", "deepseek-ai/DeepSeek-V4-Pro", "deepseek-ai/DeepSeek-V4-Pro", false},
		{"engy", "z-ai/glm-5.2", "glm-5.2", "glm-5.2", false},
		{"stepfun", "stepfun/step-3.7-flash", "step-3.7-flash", "step-3.7-flash", false},
		{"relace", "moonshotai/kimi-k3", "moonshotai/kimi-k3", "moonshotai/kimi-k3", false},
		{"relace", "moonshotai/kimi-k3", "", "moonshotai/kimi-k3", false},
		{"zero-g", "z-ai/glm-5.2", "glm-5.2", "glm-5.2", false},
		{"alibaba", "qwen/qwen3.7-flash", "qwen3.7-flash", "qwen3.7-flash", false},
		{"nextbit", "deepseek/deepseek-v4-flash-0731", "deepseek:v4-flash-0731", "deepseek:v4-flash-0731", false},
		{"aion-labs", "aion-labs/aion-3.0", "aion-labs/aion-3.0", "aion-labs/aion-3.0", false},
		{"sambanova", "openai/gpt-oss-120b", "gpt-oss-120b", "gpt-oss-120b", false},
		{"inception", "inception/mercury-2", "mercury-2", "mercury-2", false},
		{"akashml", "qwen/qwen3.8-27b", "Qwen/Qwen3.8-27B", "Qwen/Qwen3.8-27B", false},
		{"arcee", "moonshotai/kimi-k3", "moonshotai/kimi-k3", "moonshotai/kimi-k3", false},
		{"upstage", "upstage/solar-pro4", "solar-pro4", "solar-pro4", false},
		{"reka", "reka/reka-edge-2603", "reka-edge-2603", "reka-edge-2603", false},
		{"sail-research", "z-ai/glm-5.2", "zai-org/GLM-5.2-FP8", "zai-org/GLM-5.2-FP8", false},
		{"mancer", "z-ai/glm-4.7", "glm-4.7", "glm-4.7", false},
		{"wandb", "z-ai/glm-5.2", "zai-org/GLM-5.2", "zai-org/GLM-5.2", false},
	}

	for _, tt := range tests {
		t.Run(tt.provider, func(t *testing.T) {
			var captured map[string]any
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/chat/completions" {
					t.Fatalf("path = %s, want /chat/completions", r.URL.Path)
				}
				if r.Header.Get("Authorization") != "Bearer operator-key" {
					t.Fatalf("authorization header = %q", r.Header.Get("Authorization"))
				}
				if r.Header.Get("User-Agent") != "TrustedRouter/1.0" {
					t.Fatalf("user-agent = %q", r.Header.Get("User-Agent"))
				}
				if got := r.Header.Get("OpenAI-Project"); got != "" {
					t.Fatalf("OpenAI-Project must be omitted for %s, got %q", tt.provider, got)
				}
				if tt.provider == "wafer" {
					got := r.Header.Get("Wafer-ZDR")
					if tt.wantWaferZDR && got != "required" {
						t.Fatalf("Wafer-ZDR header = %q, want required", got)
					}
					if !tt.wantWaferZDR && got != "" {
						t.Fatalf("Wafer-ZDR header = %q, want omitted", got)
					}
				}
				if got := r.Header.Get("X-0G-Provider-Trust-Mode"); got != "" {
					t.Fatalf("0G trust mode header leaked to %s: %q", tt.provider, got)
				}
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Fatalf("read body: %v", err)
				}
				if err := json.Unmarshal(body, &captured); err != nil {
					t.Fatalf("decode request: %v", err)
				}
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = w.Write([]byte(strings.Join([]string{
					`data: {"id":"x","choices":[{"delta":{"content":"ok"},"finish_reason":null}]}`,
					``,
					`data: {"id":"x","choices":[{"delta":{},"finish_reason":"stop"}]}`,
					``,
					`data: [DONE]`,
					``,
				}, "\n")))
			}))
			defer server.Close()

			client := &openAICompatibleClient{
				provider: tt.provider,
				baseURL:  server.URL,
				apiKey:   "operator-key",
				httpc:    server.Client(),
			}
			direct := map[string]*openAICompatibleClient{}
			if bootstrapDirectProviderAllowed(tt.provider) {
				direct[tt.provider] = client
			}
			multi := &multiClient{
				direct:           direct,
				openai:           client,
				googleAIStudio:   client,
				cerebras:         client,
				deepseek:         client,
				mistral:          client,
				fireworks:        client,
				friendli:         client,
				baseten:          client,
				telnyx:           client,
				thinkingmachines: client,
				wafer:            client,
				crusoe:           client,
				makora:           client,
				nebius:           client,
				minimax:          client,
				inceptron:        client,
				morph:            client,
				atlasCloud:       client,
				streamLake:       client,
				neurometric:      client,
				pearl:            client,
				engy:             client,
				stepfun:          client,
				relace:           client,
				zeroG:            newZeroGAt(server.URL, "operator-key", server.Client()),
				alibaba:          client,
			}
			req := &qtypes.OpenAIChatRequest{Model: tt.publicModel}
			body := &qtypes.AnthropicMessagesRequest{
				Messages:  []qtypes.AnthropicMessage{{Role: "user", Content: "hello"}},
				MaxTokens: 8,
			}
			var out bytes.Buffer

			err := multi.InvokeStreaming(
				t.Context(),
				req,
				body,
				&out,
				InvokeOptions{
					Model:         tt.publicModel,
					UpstreamModel: tt.upstreamModel,
					Provider:      tt.provider,
					UsageType:     "Credits",
				},
			)
			if err != nil {
				t.Fatalf("InvokeStreaming: %v", err)
			}
			if captured["model"] != tt.wantModel {
				t.Fatalf("upstream model = %#v, want %q; payload=%#v", captured["model"], tt.wantModel, captured)
			}
			if _, ok := captured["response_format"]; ok {
				t.Fatalf("nil response_format leaked into upstream payload: %#v", captured)
			}
			if !strings.Contains(out.String(), "content_block_delta") {
				t.Fatalf("stream was not translated to Anthropic SSE: %s", out.String())
			}
		})
	}
}

func TestMultiClientGoogleAIStudioImageGenerationUsesNativeAPI(t *testing.T) {
	var capturedPath string
	var capturedBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		if r.URL.Path == "/chat/completions" {
			http.Error(w, `{"error":{"message":"Unhandled generated data mime type: image/jpeg"}}`, http.StatusBadRequest)
			return
		}
		if got := r.Header.Get("x-goog-api-key"); got != "operator-key" {
			t.Fatalf("x-goog-api-key = %q", got)
		}
		if got := r.Header.Get("Authorization"); got != "" {
			t.Fatalf("native Gemini request sent Authorization header %q", got)
		}
		if err := json.NewDecoder(r.Body).Decode(&capturedBody); err != nil {
			t.Fatalf("decode native request: %v", err)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w,
			"data: {\"candidates\":[{\"content\":{\"parts\":[{\"inlineData\":{\"mimeType\":\"image/jpeg\",\"data\":\"SlBFRw==\"}}]},\"finishReason\":\"STOP\"}]}\n\n",
		)
	}))
	defer server.Close()

	client := &openAICompatibleClient{
		provider: "google-ai-studio",
		baseURL:  server.URL,
		apiKey:   "operator-key",
		httpc:    server.Client(),
	}
	native := &aiStudioGeminiClient{
		apiKey:  "operator-key",
		baseURL: server.URL,
		httpc:   server.Client(),
	}
	multi := &multiClient{googleAIStudio: client, aiStudioNative: native}
	req := &qtypes.OpenAIChatRequest{
		Model:    "google/gemini-3.1-flash-image-preview",
		Messages: []qtypes.OpenAIChatMessage{{Role: "user", Content: "Generate a small red square."}},
	}
	body := &qtypes.AnthropicMessagesRequest{MaxTokens: 128}
	var out bytes.Buffer

	err := multi.InvokeStreaming(
		t.Context(),
		req,
		body,
		&out,
		InvokeOptions{
			Provider:      "google-ai-studio",
			UpstreamModel: "gemini-3.1-flash-image-preview",
			UsageType:     "Credits",
		},
	)
	if err != nil {
		t.Fatalf("InvokeStreaming: %v", err)
	}
	if strings.Contains(capturedPath, "chat/completions") {
		t.Fatalf("image generation used Google OpenAI compatibility path %q", capturedPath)
	}
	if capturedPath != "/models/gemini-3.1-flash-image-preview:streamGenerateContent" {
		t.Fatalf("native Gemini path = %q", capturedPath)
	}
	config := capturedBody["generationConfig"].(map[string]any)
	modalities := config["responseModalities"].([]any)
	if len(modalities) != 2 || modalities[0] != "TEXT" || modalities[1] != "IMAGE" {
		t.Fatalf("responseModalities = %#v", modalities)
	}
	if _, ok := config["maxOutputTokens"]; ok {
		t.Fatalf("image generation forwarded maxOutputTokens: %#v", config)
	}
	if !strings.Contains(out.String(), "data:image/jpeg;base64,SlBFRw==") {
		t.Fatalf("native Gemini image missing from translated stream: %s", out.String())
	}
}

func TestMultiClientGoogleAIStudioImageGenerationUsesBYOKKey(t *testing.T) {
	var gotKey string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("x-goog-api-key")
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w,
			"data: {\"candidates\":[{\"content\":{\"parts\":[{\"inlineData\":{\"mimeType\":\"image/png\",\"data\":\"UE5H\"}}]},\"finishReason\":\"STOP\"}]}\n\n",
		)
	}))
	defer server.Close()

	native := &aiStudioGeminiClient{
		apiKey:  "operator-key",
		baseURL: server.URL,
		httpc:   server.Client(),
	}
	multi := &multiClient{aiStudioNative: native}
	req := &qtypes.OpenAIChatRequest{
		Model:    "google/gemini-3.1-flash-image",
		Messages: []qtypes.OpenAIChatMessage{{Role: "user", Content: "Generate an icon."}},
	}
	var out bytes.Buffer
	err := multi.InvokeStreaming(
		t.Context(),
		req,
		&qtypes.AnthropicMessagesRequest{MaxTokens: 128},
		&out,
		InvokeOptions{
			Provider:       "google-ai-studio",
			ProviderAPIKey: "workspace-byok-key",
			UpstreamModel:  "gemini-3.1-flash-image",
			UsageType:      "BYOK",
		},
	)
	if err != nil {
		t.Fatalf("InvokeStreaming: %v", err)
	}
	if gotKey != "workspace-byok-key" {
		t.Fatalf("x-goog-api-key = %q, want BYOK key", gotKey)
	}
	if !strings.Contains(out.String(), "data:image/png;base64,UE5H") {
		t.Fatalf("native Gemini image missing from BYOK stream: %s", out.String())
	}
}

func TestGoogleProviderNormalizationKeepsProductsDistinct(t *testing.T) {
	tests := map[string]string{
		"gemini":           "gemini",
		"google":           "gemini",
		"google-ai-studio": "google-ai-studio",
		"ai-studio":        "google-ai-studio",
		"google-vertex":    "google-vertex",
		"google-vertex-ai": "google-vertex",
		"vertex-ai":        "google-vertex",
	}
	for input, want := range tests {
		if got := normalizeDirectProvider(input); got != want {
			t.Errorf("normalizeDirectProvider(%q) = %q, want %q", input, got, want)
		}
	}
	if got := directBaseURL("google-ai-studio"); got != "https://generativelanguage.googleapis.com/v1beta/openai" {
		t.Fatalf("AI Studio base URL = %q", got)
	}
	if got := directBaseURL("google-vertex"); got != "" {
		t.Fatalf("Vertex must not use API-key compatible base URL, got %q", got)
	}
}

func TestBootstrapDirectProviderClientsAreBoundedToCompiledHosts(t *testing.T) {
	wantBaseURLs := map[string]string{
		"nextbit":       "https://api.nextbit256.com/v1",
		"aion-labs":     "https://api.aionlabs.ai/v1",
		"sambanova":     "https://api.sambanova.ai/v1",
		"inception":     "https://api.inceptionlabs.ai/v1",
		"akashml":       "https://api.akashml.com/v1",
		"arcee":         "https://api.arcee.ai/api/v1",
		"upstage":       "https://api.upstage.ai/v1",
		"reka":          "https://api.reka.ai/v1",
		"sail-research": "https://api.sailresearch.com/v1",
		"mancer":        "https://mancer.tech/oai/v1",
		"wandb":         "https://api.inference.wandb.ai/v1",
	}
	keys := map[string]string{
		"nextbit":       " key-nextbit ",
		"aion-labs":     "key-aion",
		"sambanova":     "key-sambanova",
		"inception":     "key-inception",
		"akashml":       "key-akashml",
		"arcee":         "key-arcee",
		"upstage":       "key-upstage",
		"reka":          "key-reka",
		"sail-research": "key-sail",
		"mancer":        "key-mancer",
		"wandb":         "key-wandb",
		"evil":          "must-not-route",
		"aion_labs":     "must-not-route",
		"":              "must-not-route",
	}
	clients := newBootstrapDirectClients(keys)
	if len(clients) != len(wantBaseURLs) {
		t.Fatalf("clients = %v, want exactly %d compiled providers", clients, len(wantBaseURLs))
	}
	for provider, wantBaseURL := range wantBaseURLs {
		client := clients[provider]
		if client == nil {
			t.Fatalf("missing %s client", provider)
		}
		if client.baseURL != wantBaseURL {
			t.Errorf("%s base URL = %q, want %q", provider, client.baseURL, wantBaseURL)
		}
		if !providerUsesAuthorizedUpstreamModel(provider) {
			t.Errorf("%s must preserve the catalog-discovered upstream model", provider)
		}
		if got := directModelID(provider, "author/canonical-model", ""); got != "" {
			t.Errorf("%s guessed an upstream model without authorization: %q", provider, got)
		}
	}
	if clients["nextbit"].apiKey != "key-nextbit" {
		t.Errorf("bootstrap key was not trimmed")
	}
	if clients["evil"] != nil || directBaseURL("evil") != "" {
		t.Fatal("unknown bootstrap provider acquired a routable client")
	}
}

func TestZeroGProviderContract(t *testing.T) {
	for _, input := range []string{"0g", "0G Private Computer", "zero_g"} {
		if got := normalizeDirectProvider(input); got != "zero-g" {
			t.Errorf("normalizeDirectProvider(%q) = %q, want zero-g", input, got)
		}
	}
	if got := directBaseURL("zero-g"); got != "https://router-api.0g.ai/v1" {
		t.Fatalf("0G base URL = %q", got)
	}
	if got := directModelID("zero-g", "z-ai/glm-5.2", "glm-5.2"); got != "glm-5.2" {
		t.Fatalf("0G upstream model = %q", got)
	}
	if isOpenAICompatibleBYOKProvider("zero-g") {
		t.Fatal("0G onboarding is prepaid-only and must not accept BYOK")
	}
}

func TestZeroGClaudeUsesAnthropicMessagesFormat(t *testing.T) {
	var captured map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/messages" {
			t.Fatalf("path = %s, want /messages", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer operator-key" {
			t.Fatalf("authorization = %q", got)
		}
		if got := r.Header.Get("x-api-key"); got != "" {
			t.Fatalf("x-api-key must be omitted, got %q", got)
		}
		if got := r.Header.Get("anthropic-version"); got != "2023-06-01" {
			t.Fatalf("anthropic-version = %q", got)
		}
		if got := r.Header.Get("X-0G-Provider-Trust-Mode"); got != "" {
			t.Fatalf("0G trust mode must be omitted, got %q", got)
		}
		if err := json.NewDecoder(r.Body).Decode(&captured); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte(strings.Join([]string{
			`event: message_start`,
			`data: {"type":"message_start","message":{"id":"msg_0g","type":"message","role":"assistant","content":[],"model":"claude-opus-5","stop_reason":null,"usage":{"input_tokens":4,"output_tokens":0}}}`,
			``,
			`event: message_stop`,
			`data: {"type":"message_stop"}`,
			``,
		}, "\n")))
	}))
	defer server.Close()

	multi := &multiClient{zeroG: newZeroGAt(server.URL, "operator-key", server.Client())}
	req := &qtypes.OpenAIChatRequest{Model: "anthropic/claude-opus-5"}
	body := &qtypes.AnthropicMessagesRequest{
		Messages:  []qtypes.AnthropicMessage{{Role: "user", Content: "PONG"}},
		MaxTokens: 16,
	}
	var out bytes.Buffer
	err := multi.InvokeStreaming(
		t.Context(),
		req,
		body,
		&out,
		InvokeOptions{
			Model:         "anthropic/claude-opus-5",
			UpstreamModel: "claude-opus-5",
			Provider:      "zero-g",
			UsageType:     "Credits",
		},
	)
	if err != nil {
		t.Fatalf("InvokeStreaming: %v", err)
	}
	if got := captured["model"]; got != "claude-opus-5" {
		t.Fatalf("upstream model = %#v", got)
	}
	if got := captured["stream"]; got != true {
		t.Fatalf("stream = %#v", got)
	}
	if !strings.Contains(out.String(), "message_start") {
		t.Fatalf("missing Anthropic stream: %q", out.String())
	}
}

func TestDirectModelIDStripsOpenRouterVariants(t *testing.T) {
	tests := map[string]string{
		"google/gemma-3-27b-it:free":    "gemma-3-27b-it",
		"z-ai/glm-4.5-air:free":         "glm-4.5-air",
		"openai/gpt-4o-mini:nitro":      "gpt-4o-mini",
		"mistralai/mistral-small:floor": "mistral-small",
	}

	for public, want := range tests {
		got := directModelID("gemini", public, public)
		if got != want {
			t.Fatalf("directModelID(%q) = %q, want %q", public, got, want)
		}
	}
}

func TestAnthropicCatalogModelsNormalizeToProviderIDs(t *testing.T) {
	tests := map[string]string{
		// 4.0 GA models map to their dated snapshot ids (the undated
		// "claude-opus-4"/"claude-sonnet-4" 404 on Anthropic's API).
		"anthropic/claude-opus-4":     "claude-opus-4-20250514",
		"anthropic/claude-opus-4.1":   "claude-opus-4-1",
		"anthropic/claude-opus-4.5":   "claude-opus-4-5",
		"anthropic/claude-opus-4.6":   "claude-opus-4-6",
		"anthropic/claude-opus-4.7":   "claude-opus-4-7",
		"anthropic/claude-sonnet-4":   "claude-sonnet-4-20250514",
		"anthropic/claude-sonnet-4.5": "claude-sonnet-4-5",
		"anthropic/claude-sonnet-4.6": "claude-sonnet-4-6",
		"anthropic/claude-haiku-4.5":  "claude-haiku-4-5",
		"claude-3-5-sonnet-20241022":  "claude-3-5-sonnet-20241022",
	}

	for public, want := range tests {
		if got := mapModelID(public); got != want {
			t.Fatalf("mapModelID(%q) = %q, want %q", public, got, want)
		}
	}
}
