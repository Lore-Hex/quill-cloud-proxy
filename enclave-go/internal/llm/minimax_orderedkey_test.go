package llm

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/orderedkey"
	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestMiniMaxManagedBillingErrorDoesNotRetryOtherKey(t *testing.T) {
	gen := orderedkey.Generation("minimax", "first", "second")
	for _, tc := range []struct{ generation, want string }{
		{"primary:" + gen, "first"}, {gen, "second"}, {"", ""}, {"mismatch", ""},
	} {
		client := newOpenAICompatibleAt("minimax", "https://provider.invalid/v1", "first")
		client.standbyKey = "second"
		calls := 0
		client.httpc = &http.Client{Transport: byokRoundTripFunc(func(req *http.Request) (*http.Response, error) {
			calls++
			if req.Header.Get("Authorization") != "Bearer "+tc.want {
				t.Fatal("wrong managed credential")
			}
			return &http.Response{StatusCode: 402, Body: io.NopCloser(strings.NewReader("{}")), Header: make(http.Header)}, nil
		})}
		err := client.InvokeStreaming(t.Context(), &qtypes.OpenAIChatRequest{Model: "minimax/minimax-m3"},
			&qtypes.AnthropicMessagesRequest{}, io.Discard,
			InvokeOptions{Provider: "minimax", UpstreamModel: "MiniMax-M3", UsageType: "Credits", ManagedKeyGeneration: tc.generation})
		if err == nil || (tc.want != "" && calls != 1) || (tc.want == "" && calls != 0) {
			t.Fatalf("unexpected attempt count: %d", calls)
		}
	}
}
