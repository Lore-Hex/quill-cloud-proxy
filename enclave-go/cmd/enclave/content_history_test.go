package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestProviderHistoryUpstreamErrorResponse(t *testing.T) {
	for _, kind := range []string{"widget", "document"} {
		t.Run(kind, func(t *testing.T) {
			body := &types.AnthropicMessagesRequest{Messages: []types.AnthropicMessage{{Role: "assistant", Content: []any{map[string]any{"type": kind}}}}}
			_, err := llm.BuildOpenAICompatibleRequestShape(t.Context(), &types.OpenAIChatRequest{Model: "test"}, body, "test", false)
			if err == nil {
				t.Fatal("unsupported block accepted")
			}
			// Wrapping must preserve the marker used by the HTTP classifier.
			err = fmt.Errorf("dispatch: %w", err)
			code, message := upstreamErrorResponse(err)
			if code != 400 || !strings.Contains(message, kind) || strings.Contains(message, "llm/image:") {
				t.Fatalf("status=%d message=%q error=%v", code, message, err)
			}
			var out bytes.Buffer
			writeClassifiedAnthropicError(&out, code, message, err)
			if !strings.Contains(out.String(), `"source":"router"`) || strings.Contains(out.String(), "provider error") {
				t.Fatalf("response = %s", out.String())
			}
		})
	}
}

type historyProjectionProvider struct{ wire chan map[string]any }

func (p historyProjectionProvider) InvokeStreaming(ctx context.Context, req *types.OpenAIChatRequest, body *types.AnthropicMessagesRequest, out io.Writer, _ ...llm.InvokeOptions) error {
	wire, err := llm.BuildOpenAICompatibleRequestShape(ctx, req, body, "gpt-5.4-mini", false)
	if err != nil {
		return err
	}
	p.wire <- wire
	return writeAnthropicTextTestStream(out, req.Model, "Hello")
}

func TestProviderHistoryMessagesHandler(t *testing.T) {
	for _, kind := range []string{"thinking", "widget"} {
		t.Run(kind, func(t *testing.T) {
			provider := historyProjectionProvider{wire: make(chan map[string]any, 1)}
			gateway := trustedrouter.New("http://127.0.0.1", "test-token", &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				var payload string
				switch r.URL.Path {
				case "/internal/gateway/validate":
					payload = `{"data":{"workspace_id":"ws_history","api_key_hash":"key_history"}}`
				case "/internal/gateway/authorize":
					payload = `{"data":{"authorization_id":"auth_history","workspace_id":"ws_history","api_key_hash":"key_history","model":"openai/gpt-5.4-mini","endpoint_id":"openai/gpt-5.4-mini@openai/prepaid","provider":"openai","usage_type":"Credits","limit_usage_type":"Credits","route_candidates":[]}}`
				case "/internal/gateway/settle":
					payload = `{"data":{"settled":true,"generation_id":"gen_history","cost_microdollars":1,"model":"openai/gpt-5.4-mini","provider":"openai"}}`
				case "/internal/gateway/refund":
					payload = `{"data":{"refunded":true}}`
				default:
					t.Errorf("unexpected mock control-plane path %s", r.URL.Path)
					return nil, fmt.Errorf("unexpected mock control-plane path %s", r.URL.Path)
				}
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(payload))}, nil
			})})
			server, client := net.Pipe()
			defer client.Close()
			if err := client.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
				t.Fatal(err)
			}
			done := make(chan struct{})
			go func() {
				defer close(done)
				serveOne(context.Background(), server, registryForBearer("history-token"), provider, nil, nil, gateway, nil)
			}()
			request := fmt.Sprintf(`{"model":"openai/gpt-5.4-mini","max_tokens":32,"messages":[{"role":"assistant","content":[{"type":%q,"thinking":"private","signature":"signed"},{"type":"text","text":"answer"}]},{"role":"user","content":"continue"}]}`, kind)
			if _, err := fmt.Fprintf(client, "POST /v1/messages HTTP/1.1\r\nAuthorization: Bearer history-token\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(request), request); err != nil {
				t.Fatal(err)
			}
			response, err := http.ReadResponse(bufio.NewReader(client), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			payload, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatal(err)
			}
			if kind == "widget" {
				if response.StatusCode != 400 || !strings.Contains(string(payload), "widget") || !strings.Contains(string(payload), `"source":"router"`) {
					t.Fatalf("status=%d body=%s", response.StatusCode, payload)
				}
			} else {
				if response.StatusCode != 200 {
					t.Fatalf("status=%d body=%s", response.StatusCode, payload)
				}
				select {
				case wire := <-provider.wire:
					encoded, err := json.Marshal(wire["messages"])
					if err != nil {
						t.Fatal(err)
					}
					want := `[{"content":[{"text":"answer","type":"text"}],"role":"assistant"},{"content":"continue","role":"user"}]`
					if string(encoded) != want {
						t.Fatalf("upstream messages = %s; want %s", encoded, want)
					}
				default:
					t.Fatal("provider did not project request")
				}
			}
			_ = client.Close()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("handler did not finish")
			}
		})
	}
}
