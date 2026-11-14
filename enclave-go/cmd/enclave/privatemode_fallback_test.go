//go:build llm_multi

package main

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

// Exercise the actual PrivateMode adapter and typed 401, not a generic error.
// The next candidate is simulated; this does not prove remote attestation.
func TestPrivatemodeAttestationRejectionConfidentialFallback(t *testing.T) {
	for _, streaming := range []bool{false, true} {
		for _, alternate := range []bool{false, true} {
			name := "buffered"
			if streaming {
				name = "streaming"
			}
			if alternate {
				name += "/authorized-alternate"
			} else {
				name += "/pinned-provider"
			}
			t.Run(name, func(t *testing.T) {
				calls := 0
				llm.ConfigurePrivatemode(&http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
					calls++
					if r.URL.String() != "https://privatemode.internal:18489/v1/chat/completions" {
						t.Errorf("request escaped encrypted proxy: %s", r.URL)
					}
					return &http.Response{StatusCode: 401, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(
						`{"error":{"message":"active manifest does not match expected manifest sensitive-canary"}}`))}, nil
				})})
				t.Cleanup(func() { llm.ConfigurePrivatemode(nil) })
				req := &types.OpenAIChatRequest{Model: "nyte/confidential", Stream: streaming}
				body := &types.AnthropicMessagesRequest{MaxTokens: 16, Messages: []types.AnthropicMessage{{Role: "user", Content: "synthetic"}}}
				adapter := llm.New(&types.BootstrapData{ProviderAPIKeys: map[string]string{"privatemode": "synthetic-key"}})
				client := &scriptedProviderStreamClient{invoke: func(option llm.InvokeOptions, out io.Writer) error {
					if option.Provider == "privatemode" {
						return adapter.InvokeStreaming(context.Background(), req, body, out, option)
					}
					if option.Provider != "tinfoil" {
						t.Errorf("unexpected provider: %s", option.Provider)
					}
					_, err := io.WriteString(out, providerStreamTestResponse)
					return err
				}}
				options := []llm.InvokeOptions{{Model: "openai/gpt-oss-120b", UpstreamModel: "gpt-oss-120b", Provider: "privatemode", EndpointID: "rejected"}}
				if alternate {
					options = append(options, llm.InvokeOptions{Model: "openai/gpt-oss-120b", Provider: "tinfoil", EndpointID: "authorized"})
				}
				invocation := startProviderInvocation(t.Context(), client, req, body, options, true, nil, "attestation-fallback-test")
				got, err := io.ReadAll(invocation.reader)
				invocation.join()
				if calls != 1 {
					t.Fatalf("rejected provider called %d times", calls)
				}
				if alternate {
					if err != nil || string(got) != providerStreamTestResponse || invocation.selectedRoute.Provider("", nil) != "tinfoil" || invocation.selectedRoute.FallbackCount() != 1 {
						t.Fatalf("authorized fallback failed: body=%q err=%v", got, err)
					}
				} else if err == nil || len(got) != 0 || invocation.selectedRoute.FallbackCount() != 0 || strings.Contains(err.Error(), "sensitive-canary") {
					t.Fatalf("pinned request did not fail closed: body=%q err=%v", got, err)
				}
			})
		}
	}
}
