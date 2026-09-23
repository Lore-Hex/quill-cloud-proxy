//go:build cloud_aws

package main

import (
	"context"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/bedrock"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func init() {
	fusionFinalWireProjections = append(fusionFinalWireProjections, fusionWireProjection{
		name: "bedrock", model: "claude-haiku-4-5",
		build: func(_ context.Context, _ *types.OpenAIChatRequest, body *types.AnthropicMessagesRequest) (any, error) {
			return bedrock.BuildRequestShape(body), nil
		},
	})
}
