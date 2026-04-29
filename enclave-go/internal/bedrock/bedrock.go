// Package bedrock invokes Bedrock InvokeModelWithResponseStream and
// re-emits the AWS event-stream payloads as native Anthropic SSE bytes
// for the adapter to translate into OpenAI ChatCompletion chunks.
package bedrock

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/aws/aws-sdk-go-v2/aws"
	awscreds "github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime/types"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/vsockhttp"
)

// Client wraps a bedrockruntime.Client backed by a vsock-tunneled HTTP transport.
type Client struct {
	br *bedrockruntime.Client
}

// modelIDMap turns the human-friendly model name we accept on the wire
// into the Bedrock model ID for us-east-1. Confirm against
// `aws bedrock list-foundation-models --region us-east-1` before launch.
var modelIDMap = map[string]string{
	"claude-opus-4-7":            "anthropic.claude-opus-4-7-20251101-v1:0",
	"claude-sonnet-4-6":          "anthropic.claude-sonnet-4-6-20250901-v1:0",
	"claude-haiku-4-5-20251001":  "anthropic.claude-haiku-4-5-20251001-v1:0",
}

// MapModel returns the Bedrock model ID for an OpenAI-friendly name.
func MapModel(name string) (string, bool) {
	id, ok := modelIDMap[name]
	return id, ok
}

// New builds a Bedrock client that talks to bedrock-runtime over a vsock
// tunnel set up on the parent.
func New(boot *qtypes.BootstrapData) *Client {
	tunnels := []vsockhttp.Tunnel{
		{
			Host: fmt.Sprintf("bedrock-runtime.%s.amazonaws.com", boot.Region),
			CID:  bootstrapCIDFromProxy(boot.BedrockVsockProxy),
			Port: bootstrapPortFromProxy(boot.BedrockVsockProxy),
		},
	}
	httpClient := vsockhttp.NewClient(tunnels)

	creds := awscreds.NewStaticCredentialsProvider(
		boot.BedrockAccessKey,
		boot.BedrockSecretKey,
		boot.BedrockSessionTok,
	)

	cfg := aws.Config{
		Region:           boot.Region,
		Credentials:      creds,
		HTTPClient:       httpClient,
		RetryMaxAttempts: 2,
	}
	return &Client{br: bedrockruntime.NewFromConfig(cfg)}
}

// InvokeStreaming sends an Anthropic-shaped body to Bedrock and writes the
// unwrapped Anthropic SSE bytes into `out`. The adapter package reads from
// `out` to translate to OpenAI ChatCompletion chunks.
func (c *Client) InvokeStreaming(
	ctx context.Context,
	modelID string,
	body *qtypes.AnthropicMessagesRequest,
	out io.Writer,
) error {
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("bedrock: marshal body: %w", err)
	}
	resp, err := c.br.InvokeModelWithResponseStream(ctx, &bedrockruntime.InvokeModelWithResponseStreamInput{
		ModelId:     aws.String(modelID),
		ContentType: aws.String("application/json"),
		Accept:      aws.String("application/json"),
		Body:        bodyBytes,
	})
	if err != nil {
		return fmt.Errorf("bedrock: invoke: %w", err)
	}
	defer func() { _ = resp.GetStream().Close() }()

	for event := range resp.GetStream().Events() {
		chunk, ok := event.(*types.ResponseStreamMemberChunk)
		if !ok {
			continue
		}
		// chunk.Value.Bytes is JSON like:
		//   {"type":"content_block_delta","delta":{"type":"text_delta","text":"..."}}
		// Re-emit it as a native Anthropic SSE event so adapter.TransformStream
		// can read it with its existing parser.
		var evt struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(chunk.Value.Bytes, &evt); err != nil {
			continue
		}
		if evt.Type == "" {
			continue
		}
		if _, err := fmt.Fprintf(out, "event: %s\ndata: %s\n\n", evt.Type, chunk.Value.Bytes); err != nil {
			return err
		}
	}
	if err := resp.GetStream().Err(); err != nil {
		return fmt.Errorf("bedrock: stream: %w", err)
	}
	return nil
}

// bootstrapCIDFromProxy / bootstrapPortFromProxy parse "<cid>:<port>" e.g. "3:8003".
func bootstrapCIDFromProxy(s string) uint32 {
	cid, _ := splitCIDPort(s)
	return cid
}

func bootstrapPortFromProxy(s string) uint32 {
	_, port := splitCIDPort(s)
	return port
}

func splitCIDPort(s string) (uint32, uint32) {
	var cid, port uint32
	if _, err := fmt.Sscanf(s, "%d:%d", &cid, &port); err != nil {
		return 3, 8003
	}
	return cid, port
}
