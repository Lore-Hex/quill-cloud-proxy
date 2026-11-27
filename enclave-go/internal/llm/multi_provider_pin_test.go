//go:build llm_multi

package llm

import (
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestProviderPinStopsMultiDispatchBeforeAnyClient(t *testing.T) {
	m := &multiClient{}
	p := &qtypes.ProviderRouting{Only: []string{"tinfoil"}}
	opt := InvokeOptions{Provider: "openai", UsageType: "Credits"}
	// Exercise both a request-local pin and a subcall with only the inherited pin.
	for _, inherited := range []bool{false, true} {
		ctx, routing := t.Context(), p
		if inherited {
			ctx = trustedrouter.WithRequestPrivacy(ctx, "", nil, p)
			routing = nil
		}
		chat := &qtypes.OpenAIChatRequest{Provider: routing}
		embed := &qtypes.EmbeddingRequest{Provider: routing}
		if err := m.InvokeStreaming(ctx, chat, nil, io.Discard, opt); err == nil || !strings.Contains(err.Error(), "dispatch not approved") {
			t.Fatalf("chat (inherited %v): %v", inherited, err)
		}
		if _, err := m.InvokeEmbedding(ctx, embed, opt); err == nil || !strings.Contains(err.Error(), "dispatch not approved") {
			t.Fatalf("embedding (inherited %v): %v", inherited, err)
		}
		rerank := &qtypes.RerankRequest{EmbeddingRequest: *embed}
		if _, err := m.InvokeRerank(ctx, rerank, InvokeOptions{Provider: "cohere"}); !errors.Is(err, ErrRerankUnsupported) {
			t.Fatalf("rerank (inherited %v): %v", inherited, err)
		}
	}
}
