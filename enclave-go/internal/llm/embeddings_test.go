//go:build llm_multi

package llm

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestOpenAICompatibleEmbeddings(t *testing.T) {
	var gotModel string
	var gotInput []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/embeddings") {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer sk-test" {
			t.Errorf("auth header = %q", got)
		}
		var body struct {
			Model string   `json:"model"`
			Input []string `json:"input"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		gotModel = body.Model
		gotInput = body.Input
		_, _ = io.WriteString(w, `{"object":"list","data":[{"object":"embedding","embedding":[0.1,0.2],"index":0}],"usage":{"prompt_tokens":3,"total_tokens":3}}`)
	}))
	defer srv.Close()

	c := &openAICompatibleClient{provider: "openai", baseURL: srv.URL, apiKey: "sk-test", httpc: srv.Client()}
	req := &qtypes.EmbeddingRequest{Model: "openai/text-embedding-3-small", Input: "hello"}
	resp, err := c.InvokeEmbedding(context.Background(), req, InvokeOptions{Provider: "openai", UpstreamModel: "text-embedding-3-small"})
	if err != nil {
		t.Fatalf("InvokeEmbedding: %v", err)
	}
	// The author-prefixed public id must NOT leak upstream; the native id does.
	if gotModel != "text-embedding-3-small" {
		t.Errorf("upstream model = %q, want text-embedding-3-small", gotModel)
	}
	if len(gotInput) != 1 || gotInput[0] != "hello" {
		t.Errorf("upstream input = %v", gotInput)
	}
	if resp.Object != "list" || resp.Model != "openai/text-embedding-3-small" {
		t.Errorf("resp envelope = %+v", resp)
	}
	if len(resp.Data) != 1 || string(resp.Data[0].Embedding) != "[0.1,0.2]" {
		t.Errorf("resp data = %+v", resp.Data)
	}
	if resp.Usage.PromptTokens != 3 || resp.Usage.TotalTokens != 3 {
		t.Errorf("usage = %+v", resp.Usage)
	}
}

func TestOpenAICompatibleEmbeddingsPreservesAuthorPrefix(t *testing.T) {
	// Together serves author-prefixed ids verbatim (e.g.
	// togethercomputer/m2-bert-80M-8k-retrieval). The upstream id must NOT be
	// author-stripped — that was the directModelID pitfall.
	var gotModel string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Model string `json:"model"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		gotModel = body.Model
		_, _ = io.WriteString(w, `{"object":"list","data":[{"object":"embedding","embedding":[0.5],"index":0}],"usage":{"prompt_tokens":1}}`)
	}))
	defer srv.Close()

	c := &openAICompatibleClient{provider: "together", baseURL: srv.URL, apiKey: "sk-test", httpc: srv.Client()}
	req := &qtypes.EmbeddingRequest{Model: "togethercomputer/m2-bert-80M-8k-retrieval", Input: []string{"a"}}
	_, err := c.InvokeEmbedding(context.Background(), req, InvokeOptions{Provider: "together", UpstreamModel: "togethercomputer/m2-bert-80M-8k-retrieval"})
	if err != nil {
		t.Fatalf("InvokeEmbedding: %v", err)
	}
	if gotModel != "togethercomputer/m2-bert-80M-8k-retrieval" {
		t.Errorf("upstream model = %q (author prefix was stripped!)", gotModel)
	}
}

func TestCohereEmbeddings(t *testing.T) {
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/embed") {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_, _ = io.WriteString(w, `{"embeddings":{"float":[[0.1,0.2]]},"meta":{"billed_units":{"input_tokens":3}}}`)
	}))
	defer srv.Close()

	c := &cohereClient{apiKey: "co-test", baseURL: srv.URL, httpc: srv.Client()}
	req := &qtypes.EmbeddingRequest{Model: "cohere/embed-v4.0", Input: "hello"}
	resp, err := c.InvokeEmbedding(context.Background(), req, InvokeOptions{Provider: "cohere", UpstreamModel: "embed-v4.0"})
	if err != nil {
		t.Fatalf("InvokeEmbedding: %v", err)
	}
	if gotBody["model"] != "embed-v4.0" {
		t.Errorf("upstream model = %v", gotBody["model"])
	}
	if gotBody["input_type"] != "search_document" {
		t.Errorf("input_type = %v, want search_document default", gotBody["input_type"])
	}
	if resp.Model != "cohere/embed-v4.0" || len(resp.Data) != 1 || string(resp.Data[0].Embedding) != "[0.1,0.2]" {
		t.Errorf("resp = %+v", resp)
	}
	if resp.Usage.PromptTokens != 3 {
		t.Errorf("usage = %+v", resp.Usage)
	}
}

func TestCohereChatNotSupported(t *testing.T) {
	c := newCohere("co-test")
	err := c.InvokeStreaming(context.Background(), &qtypes.OpenAIChatRequest{Model: "cohere/command-r"}, nil, io.Discard)
	if err == nil {
		t.Fatal("expected cohere chat to be unsupported")
	}
}

func TestMultiInvokeEmbeddingDispatch(t *testing.T) {
	// Error cases hit the default switch arm without dereferencing a (nil)
	// client, so a zero-value multiClient is safe here.
	zero := &multiClient{}
	if _, err := zero.InvokeEmbedding(context.Background(), &qtypes.EmbeddingRequest{Model: "x/y"}, InvokeOptions{Provider: "anthropic"}); err == nil {
		t.Error("expected non-embedding provider to error")
	}
	if _, err := zero.InvokeEmbedding(context.Background(), &qtypes.EmbeddingRequest{Model: "x/y"}, InvokeOptions{Provider: "unknownprov"}); err == nil {
		t.Error("expected unknown provider to error")
	}

	// Positive dispatch: voyage, deepinfra (Qwen3), and gemini are now wired to
	// the OpenAI-compatible embeddings client. Point each at a stub and confirm
	// the switch routes to it (returns the envelope rather than erroring).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"object":"list","data":[{"object":"embedding","embedding":[0.1],"index":0}],"usage":{"prompt_tokens":1,"total_tokens":1}}`)
	}))
	defer srv.Close()
	stub := func(p string) *openAICompatibleClient {
		return &openAICompatibleClient{provider: p, baseURL: srv.URL, apiKey: "k", httpc: srv.Client()}
	}
	m := &multiClient{voyage: stub("voyage"), deepinfra: stub("deepinfra"), geminiEmbed: stub("gemini")}
	for _, prov := range []string{"voyage", "deepinfra", "gemini"} {
		resp, err := m.InvokeEmbedding(context.Background(), &qtypes.EmbeddingRequest{Model: "x/y", Input: "hi"}, InvokeOptions{Provider: prov})
		if err != nil {
			t.Errorf("%s dispatch: %v", prov, err)
			continue
		}
		if len(resp.Data) != 1 {
			t.Errorf("%s resp = %+v", prov, resp)
		}
	}
}

func TestEmbeddingRequestInputs(t *testing.T) {
	cases := []struct {
		in   any
		want int
	}{
		{"hi", 1},
		{[]any{"a", "b"}, 2},
		{[]any{"a", ""}, 1},
		{"", 0},
		{nil, 0},
	}
	for _, tc := range cases {
		r := &qtypes.EmbeddingRequest{Input: tc.in}
		if got := len(r.Inputs()); got != tc.want {
			t.Errorf("Inputs(%v) len = %d, want %d", tc.in, got, tc.want)
		}
	}
}
