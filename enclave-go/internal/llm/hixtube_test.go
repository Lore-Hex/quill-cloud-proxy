//go:build llm_multi

package llm

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestHixtubeCacheModelAllowlist(t *testing.T) {
	for _, tc := range []struct {
		provider string
		model    string
		want     bool
	}{
		{"hixtube", "dealignai/deepseek-v4.1-flash-1017-uncensored-fp8", true},
		{"hixtube", "deepseek/deepseek-v4.1-flash-1017", true},
		{" Hixtube ", "deepseek/deepseek-v4.1-flash-1017", true},
		{"hixtube", "deepseek/deepseek-v4.1-flash", false},
		{"hixtube", "deepseek-ai/DeepSeek-V4.1-Flash-1017", false},
		{"hixtube", "deepseek/deepseek-v4.1-flash-1017-other", false},
		{"hixtube", "qwen/qwen3-0.6b", false},
		{"hixtube", "", false},
		{"other", "deepseek/deepseek-v4.1-flash-1017", false},
		{"", "deepseek/deepseek-v4.1-flash-1017", false},
	} {
		t.Run(tc.provider+"/"+tc.model, func(t *testing.T) {
			if got := hixtubeCacheEnabled(tc.provider, tc.model); got != tc.want {
				t.Fatalf("cache support = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestHixtubePreparationRequiresResolvedCacheSalt(t *testing.T) {
	for _, tc := range []struct {
		model string
		cache bool
	}{
		{"dealignai/deepseek-v4.1-flash-1017-uncensored-fp8", true},
		{"deepseek/deepseek-v4.1-flash-1017", true},
		{"qwen/qwen3-0.6b", false},
	} {
		t.Run(tc.model, func(t *testing.T) {
			model := tc.model
			req := &qtypes.OpenAIChatRequest{Model: model, Messages: []qtypes.OpenAIChatMessage{{Role: "user", Content: "hello"}}}
			body, err := adapter.ToAnthropic(req, model)
			if err != nil {
				t.Fatal(err)
			}
			msgs, err := openAICompatibleMessagesWithFetchedImages(t.Context(), body)
			if err != nil {
				t.Fatal(err)
			}
			for _, unresolved := range []ChatPreparationOptions{{}, {privateWire: &openAICompatibleRequest{}}} {
				_, err = PrepareChatRequest("hixtube", model, req, body, msgs, unresolved)
				if (err != nil) != tc.cache {
					t.Fatalf("unresolved isolation: %v", err)
				}
			}
			opts := ChatPreparationOptions{privateWire: &openAICompatibleRequest{CacheSalt: strings.Repeat("a", 64)}}
			first, err := PrepareChatRequest("hixtube", model, req, body, msgs, opts)
			if err != nil {
				t.Fatal(err)
			}
			again, err := PrepareChatRequest("hixtube", model, req, body, msgs, opts)
			if err != nil || !bytes.Equal(first.Bytes, again.Bytes) {
				t.Fatal("pure preparation changed identical resolved inputs")
			}
			var wire openAICompatibleRequest
			if err := json.Unmarshal(first.Bytes, &wire); err != nil {
				t.Fatal(err)
			}
			if tc.cache && wire.CacheSalt != opts.privateWire.CacheSalt || !tc.cache && wire.CacheSalt != "" {
				t.Fatal("cache salt leaked to an unsupported profile or was lost")
			}
			if wire.Model != model {
				t.Fatal("cache preparation changed model identity")
			}
		})
	}
}

func TestHixtubeCacheIsolation(t *testing.T) {
	first, same, other, absent, again, private := openAICompatibleRequest{}, openAICompatibleRequest{}, openAICompatibleRequest{}, openAICompatibleRequest{}, openAICompatibleRequest{}, openAICompatibleRequest{}
	for wire, scope := range map[*openAICompatibleRequest]string{&first: "workspace-one", &same: " workspace-one ", &other: "workspace-two", &absent: "", &again: ""} {
		if err := isolateProviderCache(wire, "hixtube", scope); err != nil {
			t.Fatal(err)
		}
	}
	if err := isolatePrivatemodeCache(&private, "workspace-one"); err != nil {
		t.Fatal(err)
	}
	if len(first.CacheSalt) != 64 || first.CacheSalt != same.CacheSalt || first.CacheSalt == other.CacheSalt || absent.CacheSalt == again.CacheSalt || first.CacheSalt == private.CacheSalt {
		t.Fatal("cache scope must be stable only within one provider/workspace")
	}
}

func TestHixtubePrepaidUsesPinnedHostAndPreservesUsage(t *testing.T) {
	for _, model := range []string{"dealignai/deepseek-v4.1-flash-1017-uncensored-fp8", "deepseek/deepseek-v4.1-flash-1017"} {
		t.Run(model, func(t *testing.T) { checkHixtubePrepaidCache(t, model) })
	}
}

func checkHixtubePrepaidCache(t *testing.T, model string) {
	t.Helper()
	clients := newBootstrapDirectClients(map[string]string{"hixtube": "operator-test-key"})
	if clients["hixtube"] == nil {
		t.Fatal("Hixtube prepaid client missing")
	}
	calls := 0
	var salts []string
	clients["hixtube"].httpc = &http.Client{Transport: byokRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.String() != "https://api.hixtube.com/v1/chat/completions" || r.Header.Get("Authorization") != "Bearer operator-test-key" {
			t.Fatal("wrong Hixtube destination or credential")
		}
		var wire openAICompatibleRequest
		if err := json.NewDecoder(r.Body).Decode(&wire); err != nil {
			t.Fatal(err)
		}
		if wire.Model != model || !wire.Stream || wire.StreamOptions == nil || !wire.StreamOptions.IncludeUsage {
			t.Fatal("model or streaming usage request changed")
		}
		if len(wire.CacheSalt) != 64 || strings.Contains(wire.CacheSalt, "workspace") {
			t.Fatal("trusted cache isolation missing from upstream wire")
		}
		salts = append(salts, wire.CacheSalt)
		stream := "data: {\"choices\":[{\"delta\":{\"content\":\"PONG\"},\"finish_reason\":\"stop\"}]}\n\n" +
			"data: {\"choices\":[],\"usage\":{\"prompt_tokens\":24,\"completion_tokens\":2,\"total_tokens\":26,\"prompt_tokens_details\":{\"cached_tokens\":12}}}\n\n" +
			"data: [DONE]\n\n"
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/event-stream"}}, Body: io.NopCloser(strings.NewReader(stream))}, nil
	})}
	multi := &multiClient{direct: clients}
	for index, scope := range []string{"synthetic-workspace", " synthetic-workspace ", "other-workspace", "", ""} {
		var req qtypes.OpenAIChatRequest
		// End-user JSON must not replace the trusted workspace-derived salt.
		if err := json.Unmarshal([]byte(`{"model":"`+model+`","cache_salt":"`+strings.Repeat("a", 64)+`"}`), &req); err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		err := multi.InvokeStreaming(t.Context(), &req,
			&qtypes.AnthropicMessagesRequest{MaxTokens: 64, Messages: []qtypes.AnthropicMessage{{Role: "user", Content: "PONG"}}},
			&out, InvokeOptions{Provider: "hixtube", UpstreamModel: model, ProviderCacheScope: scope})
		if err != nil || calls != index+1 {
			t.Fatalf("calls=%d error=%v", calls, err)
		}
		for _, want := range []string{"PONG", `"input_tokens":24`, `"output_tokens":2`, `"cache_read_input_tokens":12`, "message_stop"} {
			if !strings.Contains(out.String(), want) {
				t.Fatalf("missing %s", want)
			}
		}
	}
	if salts[0] != salts[1] || salts[0] == salts[2] || salts[3] == salts[4] {
		t.Fatal("dispatch did not preserve workspace isolation and same-workspace reuse")
	}
	for _, salt := range salts {
		if salt == strings.Repeat("a", 64) {
			t.Fatal("end-user cache salt reached the provider")
		}
	}
}
