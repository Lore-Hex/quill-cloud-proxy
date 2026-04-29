//go:build !gcp

// AWS Bedrock provider. Compiled by default; opt out with `-tags gcp`.
//
// Thin wrapper over internal/bedrock so the existing AWS-specific
// implementation (SigV4 auth, vsock-tunneled HTTP transport, cross-region
// inference profile IDs, AWS event-stream unwrapping) lives in one place
// without disturbing the working code.
package llm

import (
	"context"
	"fmt"
	"io"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/bedrock"
	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

type awsClient struct {
	br *bedrock.Client
}

func (c *awsClient) InvokeStreaming(
	ctx context.Context,
	modelName string,
	body *qtypes.AnthropicMessagesRequest,
	out io.Writer,
) error {
	id, ok := bedrock.MapModel(modelName)
	if !ok {
		return fmt.Errorf("llm/aws: unknown model: %s", modelName)
	}
	return c.br.InvokeStreaming(ctx, id, body, out)
}

func New(boot *qtypes.BootstrapData) Client {
	return &awsClient{br: bedrock.New(boot)}
}
