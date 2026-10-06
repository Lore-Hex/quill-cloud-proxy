package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/bedrock"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/streamhttp"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/upstreamerror"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	bedrocktypes "github.com/aws/aws-sdk-go-v2/service/bedrockruntime/types"
)

func TestBedrockCleanEOFSettlesOnceAcrossAPIs(t *testing.T) {
	t.Setenv("QUILL_USAGE_HEARTBEAT", "off")
	var wire bytes.Buffer
	encoder := eventstream.NewEncoder()
	for _, payload := range []string{
		`{"type":"message_start","message":{"id":"bedrock-msg","usage":{"input_tokens":5}}}`,
		`{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hello"}}`,
		`{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":2}}`,
	} {
		encoded, err := json.Marshal(map[string][]byte{"bytes": []byte(payload)})
		if err != nil {
			t.Fatal(err)
		}
		if err := encoder.Encode(&wire, eventstream.Message{
			Headers: eventstream.Headers{
				{Name: ":message-type", Value: eventstream.StringValue("event")},
				{Name: ":event-type", Value: eventstream.StringValue("chunk")},
				{Name: ":content-type", Value: eventstream.StringValue("application/json")},
			},
			Payload: encoded,
		}); err != nil {
			t.Fatal(err)
		}
	}
	for _, route := range []string{"messages", "chat.completions", "responses"} {
		t.Run(route, func(t *testing.T) {
			var calls, settlements, refunds atomic.Int32
			// Use net/http's Content-Length reader: its final checksum read
			// returns bytes together with EOF, which the real SDK consumes.
			sdk := bedrockruntime.NewFromConfig(aws.Config{
				Region: "us-east-1", Credentials: credentials.NewStaticCredentialsProvider("test-key", "test-secret", ""), RetryMaxAttempts: 1,
				HTTPClient: streamhttp.Client{Base: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
					calls.Add(1)
					header := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/vnd.amazon.eventstream\r\nContent-Length: %d\r\n\r\n", wire.Len())
					return http.ReadResponse(bufio.NewReader(io.MultiReader(strings.NewReader(header), bytes.NewReader(wire.Bytes()))), r)
				})}},
			})
			provider := streamingProviderFunc(func(ctx context.Context, out io.Writer, _ llm.InvokeOptions) error {
				response, err := sdk.InvokeModelWithResponseStream(ctx, &bedrockruntime.InvokeModelWithResponseStreamInput{
					ModelId: aws.String("test-model"), ContentType: aws.String("application/json"), Body: []byte(`{}`),
				})
				if err != nil {
					return err
				}
				defer response.GetStream().Close()
				upstreamerror.Open(out)
				for event := range response.GetStream().Events() {
					if chunk, ok := event.(*bedrocktypes.ResponseStreamMemberChunk); ok {
						if err := bedrock.RelayEvent(chunk.Value.Bytes, out); err != nil {
							return err
						}
					}
				}
				return response.GetStream().Err()
			})
			auth := costReportingAuthorization()
			gateway := trustedrouter.New("http://127.0.0.1:18080", "test", &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				body := `{"data":{"cost_microdollars":18,"disposition":"finalized"}}`
				switch r.URL.Path {
				case "/internal/gateway/authorize":
					encoded, _ := json.Marshal(map[string]any{"data": auth})
					body = string(encoded)
				case "/internal/gateway/settle":
					settlements.Add(1)
				case "/internal/gateway/refund":
					refunds.Add(1)
				default:
					t.Errorf("unexpected control request %s", r.URL.Path)
				}
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
			})})
			var out bytes.Buffer
			serveErrorTestRoute(t.Context(), route, true, &out, provider, gateway, auth, []llm.InvokeOptions{{Model: "test-model", EndpointID: "served", Provider: "anthropic"}})
			response, err := http.ReadResponse(bufio.NewReader(&out), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatal(err)
			}
			terminal := map[string]string{"messages": "event: message_stop", "chat.completions": "[DONE]", "responses": "event: response.completed"}[route]
			if response.StatusCode != 200 || calls.Load() != 1 || settlements.Load() != 1 || refunds.Load() != 0 || !bytes.Contains(body, []byte("Hello")) || !bytes.Contains(body, []byte(terminal)) || bytes.Contains(body, []byte("event: error")) {
				t.Fatalf("clean Bedrock EOF failed: status=%d calls=%d settles=%d refunds=%d body=%s", response.StatusCode, calls.Load(), settlements.Load(), refunds.Load(), body)
			}
		})
	}
}
