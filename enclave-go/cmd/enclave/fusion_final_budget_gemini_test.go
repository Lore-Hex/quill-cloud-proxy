//go:build llm_multi

package main

import (
	"context"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func init() {
	for _, model := range []string{"gemini-2.5-pro", "gemini-3.1-pro-preview", "gemini-3.1-flash-image"} {
		fusionFinalWireProjections = append(fusionFinalWireProjections, fusionWireProjection{
			name: model, model: model, gemini: true,
			build: func(ctx context.Context, req *types.OpenAIChatRequest, body *types.AnthropicMessagesRequest) (any, error) {
				return llm.BuildGeminiRequestShape(ctx, req, body, req.Model)
			},
		})
	}
}
