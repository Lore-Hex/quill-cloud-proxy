//go:build llm_multi

package llm

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestConfidentialEmbeddingsDispatchUsesVerifiedTransport(t *testing.T) {
	defer ConfigurePrivatemode(nil)
	for _, provider := range []string{"tinfoil", "privatemode"} {
		t.Run(provider, func(t *testing.T) {
			model, native, url := "nomic-ai/nomic-embed-text", "nomic-embed-text", "https://inference.tinfoil.sh/v1/embeddings"
			if provider == "privatemode" {
				model, native, url = "qwen/qwen3-embedding-4b", "qwen3-embedding-4b", "https://privatemode.internal:18489/v1/embeddings"
			}
			calls := 0
			verified := &http.Client{Transport: byokRoundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.URL.String() != url || r.Header.Get("Authorization") != "Bearer synthetic-key" {
					t.Fatal("embedding request escaped verified authority")
				}
				var wire map[string]any
				if err := json.NewDecoder(r.Body).Decode(&wire); err != nil || wire["model"] != native {
					t.Fatal("incorrect native model")
				}
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"data":[{"embedding":[0.1,0.2],"index":0}],"usage":{"prompt_tokens":3}}`))}, nil
			})}
			client := newTinfoilAttested("synthetic-key")
			client.httpcGetter = func() (*http.Client, error) { return verified, nil }
			multi := &multiClient{tinfoil: client}
			if provider == "privatemode" {
				ConfigurePrivatemode(verified)
				multi.direct = map[string]*openAICompatibleClient{"privatemode": newOpenAICompatible("privatemode", "synthetic-key")}
			}
			out, err := multi.InvokeEmbedding(t.Context(), &qtypes.EmbeddingRequest{Model: model, Input: "synthetic"}, InvokeOptions{Provider: provider, UpstreamModel: native})
			if err != nil || out == nil || out.Usage.PromptTokens != 3 || out.Model != model || calls != 1 {
				t.Fatalf("dispatch/usage failure: %v, calls=%d", err, calls)
			}
		})
	}
}

func TestTinfoilEmbeddingsNeverFallBackToPlainClient(t *testing.T) {
	for _, failure := range []error{errors.New("attestation unavailable"), nil} {
		client := newTinfoilAttested("synthetic-key")
		client.httpcGetter = func() (*http.Client, error) { return nil, failure }
		client.httpc = &http.Client{Transport: byokRoundTripFunc(func(*http.Request) (*http.Response, error) {
			t.Fatal("plaintext transport used")
			return nil, errors.New("must not run")
		})}
		_, err := client.InvokeEmbedding(t.Context(), &qtypes.EmbeddingRequest{Model: "nomic-ai/nomic-embed-text", Input: "synthetic"})
		if err == nil {
			t.Fatal("missing verified client did not fail closed")
		}
	}
}

func TestPrivatemodeEmbeddingPreflight(t *testing.T) {
	defer ConfigurePrivatemode(nil)
	calls := 0
	ConfigurePrivatemode(&http.Client{Transport: byokRoundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return nil, errors.New("must not run")
	})})
	for _, option := range []InvokeOptions{
		{UpstreamModel: "qwen3-embedding-4b", ProviderAPIKey: "byok"},
		{UpstreamModel: "qwen-latest"},
		{UpstreamModel: "gpt-oss-120b"},
	} {
		_, err := newOpenAICompatible("privatemode", "synthetic-key").InvokeEmbedding(t.Context(), &qtypes.EmbeddingRequest{Model: "qwen/qwen3-embedding-4b", Input: "synthetic"}, option)
		if err == nil {
			t.Fatal("unsupported encrypted embedding accepted")
		}
	}
	if calls != 0 {
		t.Fatal("preflight sent input")
	}
	dim := 512
	_, err := newOpenAICompatible("privatemode", "synthetic-key").InvokeEmbedding(t.Context(), &qtypes.EmbeddingRequest{Model: "qwen/qwen3-embedding-4b", Input: "synthetic", Dimensions: &dim}, InvokeOptions{UpstreamModel: "qwen3-embedding-4b"})
	if err == nil || calls != 0 {
		t.Fatal("unsupported dimensions sent input")
	}
}

func TestPrivatemodeEmbeddingScrubsAttestationErrors(t *testing.T) {
	defer ConfigurePrivatemode(nil)
	ConfigurePrivatemode(&http.Client{Transport: byokRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 401, Body: io.NopCloser(strings.NewReader(`{"error":{"message":"active manifest does not match expected manifest sensitive-input"}}`))}, nil
	})})
	_, err := newOpenAICompatible("privatemode", "synthetic-key").InvokeEmbedding(t.Context(), &qtypes.EmbeddingRequest{Model: "qwen/qwen3-embedding-4b", Input: "synthetic"}, InvokeOptions{UpstreamModel: "qwen3-embedding-4b"})
	var typed *privatemodeHTTPError
	if !errors.As(err, &typed) || typed.reason != "attestation_manifest_mismatch" || strings.Contains(err.Error(), "sensitive-input") {
		t.Fatalf("attestation error lost or content leaked: %v", err)
	}
}

func TestPrivatemodeOCRDoesNotInjectReasoning(t *testing.T) {
	for _, reasoning := range []any{nil, map[string]any{"enabled": false}, map[string]any{"effort": "none"}} {
		wire := &openAICompatibleRequest{Model: "deepseek-ocr-2"}
		if err := preparePrivatemodeWire(&qtypes.OpenAIChatRequest{Reasoning: reasoning}, nil, wire, "workspace"); err != nil {
			t.Fatal(err)
		}
		if wire.Thinking != nil || wire.Reasoning != nil || wire.ReasoningEffort != "" || len(wire.CacheSalt) != 64 {
			t.Fatal("OCR reasoning or cache isolation incorrect")
		}
	}
	for _, reasoning := range []any{map[string]any{"enabled": true}, map[string]any{"effort": "high"}, map[string]any{"max_tokens": 10}} {
		if err := preparePrivatemodeWire(&qtypes.OpenAIChatRequest{Reasoning: reasoning}, nil, &openAICompatibleRequest{Model: "deepseek-ocr-2"}, "workspace"); err == nil {
			t.Fatal("OCR silently accepted unsupported reasoning")
		}
	}
}
