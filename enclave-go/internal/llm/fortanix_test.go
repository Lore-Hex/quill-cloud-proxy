//go:build llm_multi

package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestFortanixOrdinaryClientRefusesConfidentialBeforeEgress(t *testing.T) {
	floor := &qtypes.ProviderRouting{MinPrivacy: "confidential"}
	for _, tc := range []struct {
		name string
		ctx  context.Context
		chat *qtypes.ProviderRouting
	}{
		{"hostname", trustedrouter.WithConfidentialOnly(t.Context()), nil},
		{"request", t.Context(), floor},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := &http.Client{Transport: byokRoundTripFunc(func(*http.Request) (*http.Response, error) {
				t.Fatal("ordinary Fortanix transport received a Confidential request")
				return nil, nil
			})}
			req := &qtypes.OpenAIChatRequest{Model: "fortanix/glm-5.3-flash", Provider: tc.chat}
			body := &qtypes.AnthropicMessagesRequest{MaxTokens: 16, Messages: []qtypes.AnthropicMessage{{Role: "user", Content: "test"}}}
			err := invokeOpenAICompatibleStreamingWithClient(tc.ctx, client, "fortanix", directBaseURL("fortanix"), "test-key", req, body, io.Discard, fortanixNativeModel)
			if err == nil || !strings.Contains(err.Error(), "Confidential") {
				t.Fatalf("expected a privacy refusal, got %v", err)
			}
		})
	}
}

func TestFortanixOrdinaryPrivacyAliases(t *testing.T) {
	for _, floor := range []string{"e2e", "e2ee", "max", "maximum", "trusted", " CONFIDENTIAL ", "unknown"} {
		if fortanixOrdinaryAllowed(t.Context(), &qtypes.OpenAIChatRequest{Provider: &qtypes.ProviderRouting{MinPrivacy: floor}}) {
			t.Errorf("accepted ineligible privacy floor %q", floor)
		}
	}
	for _, model := range []string{"nyte/confidential", "trustedrouter/e2e", "trustedrouter/trusted:fastest"} {
		if fortanixOrdinaryAllowed(t.Context(), &qtypes.OpenAIChatRequest{Model: model}) {
			t.Errorf("accepted restricted model alias %q", model)
		}
	}
}

func TestFortanixInternalStreamingNativeModelAndUsage(t *testing.T) {
	clients := newBootstrapDirectClients(map[string]string{"fortanix": "test-key"})
	client := clients["fortanix"]
	if client == nil {
		t.Fatal("missing Fortanix client")
	}
	client.httpc = &http.Client{Transport: byokRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.String() != "https://ctf.armet.ai/v1/chat/completions" || r.Header.Get("Authorization") != "Bearer test-key" {
			t.Fatal("wrong Fortanix endpoint or credential")
		}
		var wire openAICompatibleRequest
		if err := json.NewDecoder(r.Body).Decode(&wire); err != nil {
			t.Fatal(err)
		}
		if wire.Model != "GLM-5.3-Flash" || !wire.Stream || wire.StreamOptions == nil || !wire.StreamOptions.IncludeUsage {
			t.Fatalf("wrong request: %+v", wire)
		}
		stream := "data: {\"choices\":[{\"delta\":{\"reasoning\":\"Check instruction.\"}}]}\n\n" +
			"data: {\"choices\":[{\"delta\":{\"content\":\"PONG\"},\"finish_reason\":\"stop\"}]}\n\n" +
			"data: {\"choices\":[],\"usage\":{\"prompt_tokens\":18,\"completion_tokens\":171,\"total_tokens\":189,\"completion_tokens_details\":{\"reasoning_tokens\":167}}}\n\n" +
			"data: [DONE]\n\n"
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/event-stream"}}, Body: io.NopCloser(strings.NewReader(stream))}, nil
	})}
	var out bytes.Buffer
	multi := &multiClient{direct: clients}
	err := multi.InvokeStreaming(t.Context(), &qtypes.OpenAIChatRequest{Model: "fortanix/glm-5.3-flash", Provider: &qtypes.ProviderRouting{MinPrivacy: "zdr"}},
		&qtypes.AnthropicMessagesRequest{MaxTokens: 256, Messages: []qtypes.AnthropicMessage{{Role: "user", Content: "PONG"}}},
		&out, InvokeOptions{Provider: "fortanix", UpstreamModel: "GLM-5.3-Flash"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"PONG", "Check instruction.", `"input_tokens":18`, `"output_tokens":171`, "message_stop"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("missing %s: %s", want, out.String())
		}
	}
}
