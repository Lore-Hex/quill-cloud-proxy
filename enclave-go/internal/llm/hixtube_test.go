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
	clients := newBootstrapDirectClients(map[string]string{"hixtube": "operator-test-key"})
	if clients["hixtube"] == nil {
		t.Fatal("Hixtube prepaid client missing")
	}
	calls := 0
	clients["hixtube"].httpc = &http.Client{Transport: byokRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.String() != "https://api.hixtube.com/v1/chat/completions" || r.Header.Get("Authorization") != "Bearer operator-test-key" {
			t.Fatal("wrong Hixtube destination or credential")
		}
		var wire openAICompatibleRequest
		if err := json.NewDecoder(r.Body).Decode(&wire); err != nil {
			t.Fatal(err)
		}
		if wire.Model != "dealignai/deepseek-v4.1-flash-1017-uncensored-fp8" || !wire.Stream || wire.StreamOptions == nil || !wire.StreamOptions.IncludeUsage {
			t.Fatal("model or streaming usage request changed")
		}
		if len(wire.CacheSalt) != 64 || strings.Contains(wire.CacheSalt, "workspace") {
			t.Fatal("trusted cache isolation missing from upstream wire")
		}
		stream := "data: {\"choices\":[{\"delta\":{\"content\":\"PONG\"},\"finish_reason\":\"stop\"}]}\n\n" +
			"data: {\"choices\":[],\"usage\":{\"prompt_tokens\":24,\"completion_tokens\":2,\"total_tokens\":26}}\n\n" +
			"data: [DONE]\n\n"
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/event-stream"}}, Body: io.NopCloser(strings.NewReader(stream))}, nil
	})}
	var out bytes.Buffer
	multi := &multiClient{direct: clients}
	err := multi.InvokeStreaming(t.Context(), &qtypes.OpenAIChatRequest{Model: "dealignai/deepseek-v4.1-flash-1017-uncensored-fp8"},
		&qtypes.AnthropicMessagesRequest{MaxTokens: 64, Messages: []qtypes.AnthropicMessage{{Role: "user", Content: "PONG"}}},
		&out, InvokeOptions{Provider: "hixtube", UpstreamModel: "dealignai/deepseek-v4.1-flash-1017-uncensored-fp8", ProviderCacheScope: "synthetic-workspace"})
	if err != nil || calls != 1 {
		t.Fatalf("calls=%d error=%v", calls, err)
	}
	for _, want := range []string{"PONG", `"input_tokens":24`, `"output_tokens":2`, "message_stop"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("missing %s", want)
		}
	}
}
