//go:build llm_bedrock

// AWS Bedrock provider. Selected with `-tags llm_bedrock`. Bedrock only
// makes sense from inside an AWS-account-attested workload (the
// PCR0-bound KMS condition is the property), so it implicitly assumes
// `cloud_aws` is also set — the build will fail otherwise because
// internal/bedrock relies on internal/vsockhttp which is `cloud_aws`-tagged.
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
