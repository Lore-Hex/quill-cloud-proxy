package llm

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

type rerankTransport func(*http.Request) (*http.Response, error)

func (f rerankTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestRerankDocumentedAdapters(t *testing.T) {
	// Literal response fixtures: voyage-reranker-api.txt:112 and
	// cohere-rerank-v2.txt:219-275. Cohere request: lines 197-214.
	for _, provider := range []string{"voyage", "cohere"} {
		t.Run(provider, func(t *testing.T) {
			req := &qtypes.RerankRequest{Query: "Sample query", Documents: []string{"Sample document 1", "Sample document 2"}, TopN: 1, ReturnDocuments: true}
			model := "rerank-2.5-lite"
			wantTokens := 8
			if provider == "cohere" {
				raw, err := os.ReadFile("testdata/rerank/cohere_request.json")
				if err != nil {
					t.Fatal(err)
				}
				req, err = qtypes.ParseRerankRequest(raw)
				if err != nil {
					t.Fatal(err)
				}
				model = req.Model
				wantTokens = 192
			}
			req.SessionID = "private-session"
			req.User = "private-user"
			raw, err := os.ReadFile("testdata/rerank/" + provider + "_response.json")
			if err != nil {
				t.Fatal(err)
			}
			httpc := &http.Client{Transport: rerankTransport(func(r *http.Request) (*http.Response, error) {
				if r.Method != "POST" || r.URL.Path != "/rerank" || r.Header.Get("Authorization") != "Bearer test-key" {
					t.Error("request method, path or credential changed")
				}
				var body map[string]any
				_ = json.NewDecoder(r.Body).Decode(&body)
				if body["model"] != model || body["query"] != req.Query {
					t.Error("model or query changed")
				}
				docs, _ := json.Marshal(body["documents"])
				want, _ := json.Marshal(req.Documents)
				if string(docs) != string(want) {
					t.Error("documents changed")
				}
				expected := 3
				if provider == "voyage" {
					expected = 4
					if body["return_documents"] != false {
						t.Error("provider document echo requested")
					}
				}
				if len(body) != expected {
					t.Error("extra upstream request members")
				}
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(raw))), Header: make(http.Header)}, nil
			})}
			result, err := invokeRerank(t.Context(), httpc, provider, "https://example.test", "test-key", req, InvokeOptions{UpstreamModel: model})
			if err != nil || result.InputTokens == nil || *result.InputTokens != wantTokens {
				t.Fatalf("usage error=%v", err)
			}
		})
	}
}

func TestRerankStrictResponse(t *testing.T) {
	for _, provider := range []string{"voyage", "cohere"} {
		key := "data"
		if provider == "cohere" {
			key = "results"
		}
		for _, rows := range []string{`null`, `{}`, `[{"index":-1,"relevance_score":0.2}]`, `[{"index":2,"relevance_score":0.2}]`, `[{"index":0,"relevance_score":0.2},{"index":0,"relevance_score":0.3}]`, `[{"index":0}]`, `[{"relevance_score":0.5}]`, `[{"index":null,"relevance_score":0.5}]`, `[{"index":0,"relevance_score":null}]`, `[{"index":0,"relevance_score":1e999}]`, `[{"index":0,"relevance_score":"NaN"}]`, `[{"index":0},{"index":1},{"index":2}]`} {
			if _, err := parseRerankResponse(provider, []byte(`{"`+key+`":`+rows+`}`), 2); err == nil {
				t.Fatalf("accepted invalid %s rows", provider)
			}
		}
		for _, raw := range []string{`{}`, `null`, `{"` + key + `":[]} {}`, `{"` + key + `":[],"usage":{"total_tokens":-1},"meta":{"billed_units":{"input_tokens":-1}}}`} {
			if _, err := parseRerankResponse(provider, []byte(raw), 2); err == nil {
				t.Fatal("accepted invalid envelope")
			}
		}
	}
	result, err := parseRerankResponse("cohere", []byte(`{"results":[{"index":0,"relevance_score":0.2,"document":"discard"}],"meta":{"billed_units":{"input_tokens":7.0,"search_units":2},"tokens":{"input_tokens":99}}}`), 1)
	if err != nil || *result.InputTokens != 7 || *result.SearchUnits != 2 || result.Results[0].Document != nil {
		t.Fatal("billed usage or document policy changed")
	}
	result, err = parseRerankResponse("cohere", []byte(`{"results":[],"meta":{"tokens":{"input_tokens":99}}}`), 1)
	if err != nil || result.InputTokens != nil {
		t.Fatal("unbilled tokens used as billed usage")
	}
	for _, tokens := range []string{"-1", "0.5", "1e99", "null"} {
		result, err = parseRerankResponse("voyage", []byte(`{"data":[],"usage":{"total_tokens":`+tokens+`}}`), 1)
		if tokens == "null" {
			if err != nil || result.InputTokens != nil {
				t.Fatal("absent usage rejected")
			}
		} else if err == nil {
			t.Fatal("invalid usage accepted")
		}
	}
	result, err = parseRerankResponse("voyage", []byte(`{"data":[],"usage":{"total_tokens":0}}`), 1)
	if err != nil || result.InputTokens == nil || *result.InputTokens != 0 {
		t.Fatal("zero usage lost")
	}
}

func TestRerankProviderErrors(t *testing.T) {
	for _, status := range []int{400, 401, 413, 422, 429, 500, 503} {
		c := &http.Client{Transport: rerankTransport(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader("PRIVATE-QUERY PRIVATE-DOCUMENT"))}, nil
		})}
		_, err := invokeRerank(context.Background(), c, "voyage", "https://example.test", "key", &qtypes.RerankRequest{}, InvokeOptions{UpstreamModel: "m"})
		if err == nil || strings.Contains(err.Error(), "PRIVATE") {
			t.Fatal("provider text retained")
		}
		if status == 413 {
			if !errors.Is(err, ErrRerankInputLimit) {
				t.Fatal("size classification lost")
			}
		} else if got, ok := HTTPStatusFromError(err); !ok || got != status {
			t.Fatal("status lost")
		}
	}
	for _, raw := range []string{"PRIVATE-QUERY", strings.Repeat(" ", maxRerankResponseBytes+1)} {
		c := &http.Client{Transport: rerankTransport(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(raw))}, nil
		})}
		_, err := invokeRerank(t.Context(), c, "cohere", "https://example.test", "key", &qtypes.RerankRequest{}, InvokeOptions{UpstreamModel: "m"})
		if err == nil || strings.Contains(err.Error(), "PRIVATE") {
			t.Fatal("invalid response accepted or retained")
		}
	}
	c := &http.Client{Transport: rerankTransport(func(*http.Request) (*http.Response, error) { return nil, errors.New("PRIVATE-QUERY") })}
	_, err := invokeRerank(t.Context(), c, "voyage", "https://example.test", "key", &qtypes.RerankRequest{}, InvokeOptions{UpstreamModel: "m"})
	if err == nil || strings.Contains(err.Error(), "PRIVATE") {
		t.Fatal("transport text retained")
	}
	for _, option := range []InvokeOptions{{ProviderAPIKey: "key", UpstreamModel: "m"}, {UsageType: "BYOK", UpstreamModel: "m"}, {}} {
		if _, err := invokeRerank(t.Context(), c, "voyage", "https://example.test", "key", &qtypes.RerankRequest{}, option); err == nil {
			t.Fatal("unsupported options accepted")
		}
	}
}
