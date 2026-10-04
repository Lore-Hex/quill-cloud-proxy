//go:build !cloud_aws

package main

import (
	"bufio"
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestGatewayMalformedContentChunkSettles(t *testing.T) {
	t.Setenv("QUILL_USAGE_HEARTBEAT", "off")
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "data: {\"choices\":[{\"delta\":{\"content\":\"hello\"}}]}\n\n"+
			"data: {\"choices\":[broken\n\n"+
			"data: {\"choices\":[{\"delta\":{\"content\":\" world\"},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":5,\"completion_tokens\":2}}\n\n"+
			"data: [DONE]\n\n")
	}))
	defer provider.Close()
	var settles, refunds atomic.Int32
	gateway := trustedrouter.New("http://127.0.0.1:18080", "test", &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		body := `{"data":{"settled":true}}`
		switch r.URL.Path {
		case "/internal/gateway/settle":
			settles.Add(1)
		case "/internal/gateway/refund":
			refunds.Add(1)
			body = `{"data":{"refunded":true}}`
		default:
			t.Errorf("unexpected control request %s", r.URL.Path)
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
	})})
	client := &scriptedProviderStreamClient{invoke: func(_ llm.InvokeOptions, w io.Writer) error {
		return llm.InvokeOpenAICompatibleStreaming(t.Context(), "openai", provider.URL, "test-key",
			&types.OpenAIChatRequest{Model: "model-a", Stream: true}, &types.AnthropicMessagesRequest{}, w, "model-a")
	}}
	auth := &trustedrouter.Authorization{AuthorizationID: "round5", Model: "model-a", Provider: "openai", EndpointID: "first", UsageType: "Credits"}
	var out bytes.Buffer
	serveErrorTestRoute(t.Context(), "chat.completions", true, &out, client, gateway, auth, []llm.InvokeOptions{{Model: "model-a", Provider: "openai", EndpointID: "first"}})
	response, err := http.ReadResponse(bufio.NewReader(&out), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != 200 || settles.Load() != 1 || refunds.Load() != 0 {
		t.Fatalf("status=%d settles=%d refunds=%d body=%s", response.StatusCode, settles.Load(), refunds.Load(), body)
	}
	if !bytes.Contains(body, []byte(`"content":"hello"`)) || !bytes.Contains(body, []byte(`"content":" world"`)) ||
		bytes.Contains(body, []byte(`"error":`)) || !bytes.HasSuffix(body, []byte("data: [DONE]\n\n")) {
		t.Fatalf("good content or successful terminal missing: %s", body)
	}
}
