package llm

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestRerankAdapterCredentialGuards(t *testing.T) {
	for _, provider := range []string{"voyage", "cohere"} {
		for _, tc := range []struct {
			name, key, model, usage, customer, want string
		}{
			{"customer_key", "platform-key", "m", "Credits", "customer-key", "rerank requires Credits"},
			{"byok", "platform-key", "m", "bYoK", "", "rerank requires Credits"},
			{"missing_platform_key", " \t", "m", "Credits", "", "rerank provider key unavailable"},
			{"missing_model", "platform-key", "", "Credits", "", "rerank upstream model unavailable"},
		} {
			t.Run(provider+"/"+tc.name, func(t *testing.T) {
				httpc := &http.Client{Transport: rerankTransport(func(*http.Request) (*http.Response, error) {
					t.Fatal("rejected option reached provider transport")
					return nil, errors.New("unexpected request")
				})}
				resp, err := invokeRerank(t.Context(), httpc, provider, "https://example.test", tc.key, &qtypes.RerankRequest{Query: "q", Documents: []string{"d"}}, InvokeOptions{UpstreamModel: tc.model, UsageType: tc.usage, ProviderAPIKey: tc.customer})
				if resp != nil || err == nil || err.Error() != tc.want {
					t.Fatalf("response=%+v error=%v; want %s", resp, err, tc.want)
				}
			})
		}
	}
	for _, provider := range []string{"", "openai", "jina"} {
		t.Run("unsupported/"+provider, func(t *testing.T) {
			httpc := &http.Client{Transport: rerankTransport(func(*http.Request) (*http.Response, error) {
				t.Fatal("unsupported provider reached transport")
				return nil, errors.New("unexpected request")
			})}
			if _, err := invokeRerank(t.Context(), httpc, provider, "https://example.test", "platform-key", &qtypes.RerankRequest{}, InvokeOptions{UpstreamModel: "m"}); !errors.Is(err, ErrRerankUnsupported) {
				t.Fatalf("error=%v", err)
			}
			if _, err := parseRerankResponse(provider, []byte(`{"data":[]}`), 1); !errors.Is(err, ErrRerankUnsupported) {
				t.Fatalf("parser error=%v", err)
			}
		})
	}
}

type rerankReadError struct{}

func (rerankReadError) Read([]byte) (int, error) { return 0, errors.New("PRIVATE-READ-ERROR") }
func (rerankReadError) Close() error             { return nil }

func TestRerankAdapterResponseReadGuards(t *testing.T) {
	// Valid JSON above the byte cap must fail before parsing; whitespace-only
	// oversized bodies also fail JSON parsing and would not pin the size guard.
	for _, tc := range []struct {
		name string
		body io.ReadCloser
	}{
		{"too_large", io.NopCloser(strings.NewReader(`{"data":[]}` + strings.Repeat(" ", maxRerankResponseBytes)))},
		{"read_error", rerankReadError{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			httpc := &http.Client{Transport: rerankTransport(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 200, Body: tc.body}, nil
			})}
			resp, err := invokeRerank(t.Context(), httpc, "voyage", "https://example.test", "platform-key", &qtypes.RerankRequest{}, InvokeOptions{UpstreamModel: "m"})
			if resp != nil || err == nil || err.Error() != "invalid rerank provider response" {
				t.Fatalf("response=%+v error=%v", resp, err)
			}
		})
	}
}

func TestRerankAdapterRequestCreationAndDefaultClient(t *testing.T) {
	httpc := &http.Client{Transport: rerankTransport(func(*http.Request) (*http.Response, error) {
		t.Fatal("invalid URL reached provider transport")
		return nil, errors.New("unexpected request")
	})}
	if _, err := invokeRerank(t.Context(), httpc, "voyage", ":PRIVATE-URL", "key", &qtypes.RerankRequest{}, InvokeOptions{UpstreamModel: "m"}); err == nil || err.Error() != "rerank request creation failed" {
		t.Fatalf("error=%v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	// A cancelled context exercises default-client construction without dialing.
	if _, err := invokeRerank(ctx, nil, "voyage", "https://api.voyageai.com/v1", "key", &qtypes.RerankRequest{}, InvokeOptions{UpstreamModel: "m"}); err == nil || err.Error() != "rerank provider request failed" {
		t.Fatalf("error=%v", err)
	}
}

func TestRerankCohereSearchUsageGuards(t *testing.T) {
	for _, value := range []string{"-1", "0.5", "1e99"} {
		t.Run(value, func(t *testing.T) {
			if _, err := parseRerankResponse("cohere", []byte(`{"results":[],"meta":{"billed_units":{"input_tokens":7,"search_units":`+value+`}}}`), 1); err == nil {
				t.Fatal("invalid search usage accepted")
			}
		})
	}
	// All rows are individually valid, so only the row-count guard rejects this.
	if _, err := parseRerankResponse("voyage", []byte(`{"data":[]}`), -1); err == nil {
		t.Fatal("invalid document count accepted")
	}
}
