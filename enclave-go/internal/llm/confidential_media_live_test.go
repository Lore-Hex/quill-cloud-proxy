//go:build live_provider_wave && llm_multi

package llm

import (
	"context"
	"encoding/json"
	"math"
	"os"
	"testing"
	"time"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestTinfoilNomicLive(t *testing.T) {
	if os.Getenv("TR_CONFIDENTIAL_MEDIA_LIVE") != "1" || os.Getenv("TINFOIL_API_KEY") == "" {
		t.Skip("paid synthetic embeddings opt-in")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	out, err := newTinfoilAttested(os.Getenv("TINFOIL_API_KEY")).InvokeEmbedding(ctx,
		&qtypes.EmbeddingRequest{Model: "nomic-ai/nomic-embed-text", Input: "search_document: This is a synthetic public test."}, InvokeOptions{UpstreamModel: "nomic-embed-text"})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Data) != 1 || out.Usage.PromptTokens <= 0 {
		t.Fatal("embedding shape or billable usage invalid")
	}
	var vector []float64
	if json.Unmarshal(out.Data[0].Embedding, &vector) != nil || len(vector) != 768 {
		t.Fatal("embedding dimensions invalid")
	}
	for _, v := range vector {
		if math.IsNaN(v) || math.IsInf(v, 0) {
			t.Fatal("non-finite embedding")
		}
	}
	t.Logf("verified embedding dimensions=%d input_tokens=%d", len(vector), out.Usage.PromptTokens)
}
