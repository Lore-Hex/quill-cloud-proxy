package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/streamhttp"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/upstreamcert"
)

func TestPooledHTTPClientUsesTunedTransport(t *testing.T) {
	client := pooledHTTPClient(30 * time.Second)
	if client.Timeout != 30*time.Second {
		t.Fatalf("timeout = %s, want 30s", client.Timeout)
	}
	tracked, ok := client.Transport.(*upstreamcert.Transport)
	if !ok {
		t.Fatalf("transport = %T, want *upstreamcert.Transport", client.Transport)
	}
	transport, ok := tracked.Base.(*http.Transport)
	if !ok {
		t.Fatalf("base transport = %T, want *http.Transport", tracked.Base)
	}
	if !transport.ForceAttemptHTTP2 {
		t.Fatal("ForceAttemptHTTP2 = false, want true")
	}
	if transport.MaxIdleConns < 1024 {
		t.Fatalf("MaxIdleConns = %d, want at least 1024", transport.MaxIdleConns)
	}
	if transport.MaxIdleConnsPerHost < 128 {
		t.Fatalf("MaxIdleConnsPerHost = %d, want at least 128", transport.MaxIdleConnsPerHost)
	}
	if transport.IdleConnTimeout <= 0 {
		t.Fatal("IdleConnTimeout must be positive")
	}
	if transport.DialTLSContext == nil {
		t.Fatal("DialTLSContext must capture the serving TLS connection")
	}
}

func TestFusionOpenAICompatibleHTTPBudget(t *testing.T) {
	for _, fusion := range []bool{false, true} {
		t.Run(fmt.Sprintf("fusion=%t", fusion), func(t *testing.T) {
			ctx := context.Background()
			if fusion {
				ctx = streamhttp.WithFusionTimeout(ctx)
			}
			const oldTotal = 40 * time.Millisecond
			client := &http.Client{Timeout: oldTotal, Transport: byokRoundTripFunc(func(r *http.Request) (*http.Response, error) {
				var wire map[string]any
				if err := json.NewDecoder(r.Body).Decode(&wire); err != nil {
					t.Fatal(err)
				}
				if wire["stream"] != true {
					t.Fatal("collected fusion call must stream upstream")
				}
				if _, ok := wire["max_tokens"]; ok {
					t.Fatalf("unset max_tokens sent: %#v", wire)
				}
				deadline, ok := r.Context().Deadline()
				if !ok || (fusion && time.Until(deadline) < 29*time.Minute) {
					t.Fatalf("wrong upstream deadline: %v", deadline)
				}
				pr, pw := io.Pipe()
				go func() {
					defer func() { _ = pw.CloseWithError(r.Context().Err()) }()
					stop := context.AfterFunc(r.Context(), func() { _ = pw.CloseWithError(r.Context().Err()) })
					defer stop()
					ticker := time.NewTicker(20 * time.Millisecond)
					defer ticker.Stop()
					for i := 0; i < 8; i++ {
						select {
						case <-r.Context().Done():
							return
						case <-ticker.C:
						}
						// Raw SSE keep-alive bytes are progress even without visible tokens.
						if _, err := io.WriteString(pw, ": thinking\n\n"); err != nil {
							return
						}
					}
					_, _ = io.WriteString(pw, "data: {\"choices\":[{\"delta\":{\"content\":\"answer\"},\"finish_reason\":null}]}\n\ndata: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n")
				}()
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: pr}, nil
			})}
			req := &types.OpenAIChatRequest{Model: "deepseek/test", Stream: false, Messages: []types.OpenAIChatMessage{{Role: "user", Content: "hard problem"}}}
			body, err := adapter.ToAnthropic(req, req.Model)
			if err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			err = invokeOpenAICompatibleStreamingWithClient(ctx, client, "deepseek", "https://provider.test/v1", "key", req, body, &out, "test")
			if fusion {
				if err != nil || !strings.Contains(out.String(), "answer") {
					t.Fatalf("output %q, error %v", out.String(), err)
				}
			} else if err == nil {
				t.Fatal("direct call lost its original total timeout")
			}
			if client.Timeout != oldTotal {
				t.Fatal("shared client mutated")
			}
		})
	}
}
