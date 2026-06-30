package main

import (
	"strings"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func applyCustomModelPrompt(req *types.OpenAIChatRequest, authorization *trustedrouter.Authorization) {
	prompt := customModelPrompt(authorization)
	if req == nil || prompt == "" {
		return
	}
	req.Messages = append(
		[]types.OpenAIChatMessage{{Role: "system", Content: prompt}},
		req.Messages...,
	)
}

func applyCustomModelPromptToMessages(
	req *types.OpenAIChatRequest,
	anthropicReq *types.AnthropicMessagesRequest,
	authorization *trustedrouter.Authorization,
) {
	prompt := customModelPrompt(authorization)
	if prompt == "" {
		return
	}
	if req != nil {
		req.Messages = append(
			[]types.OpenAIChatMessage{{Role: "system", Content: prompt}},
			req.Messages...,
		)
	}
	if anthropicReq == nil {
		return
	}
	if anthropicReq.SystemRaw != nil {
		anthropicReq.SystemRaw = prependAnthropicSystemRaw(prompt, anthropicReq.SystemRaw)
	} else if anthropicReq.System != "" {
		anthropicReq.System = prompt + "\n\n" + anthropicReq.System
	} else {
		anthropicReq.System = prompt
	}
}

func customModelResponseModel(fallback string, authorization *trustedrouter.Authorization) string {
	if authorization != nil && authorization.CustomModel != nil {
		modelID := strings.TrimSpace(authorization.CustomModel.ID)
		if modelID != "" {
			return modelID
		}
	}
	return fallback
}

func customModelPrompt(authorization *trustedrouter.Authorization) string {
	if authorization == nil || authorization.CustomModel == nil {
		return ""
	}
	return strings.TrimSpace(authorization.CustomModel.HiddenPrompt)
}

func prependAnthropicSystemRaw(prompt string, raw any) any {
	promptBlock := map[string]any{"type": "text", "text": prompt}
	switch value := raw.(type) {
	case []any:
		out := make([]any, 0, len(value)+1)
		out = append(out, promptBlock)
		out = append(out, value...)
		return out
	case string:
		if strings.TrimSpace(value) == "" {
			return []any{promptBlock}
		}
		return []any{promptBlock, map[string]any{"type": "text", "text": value}}
	default:
		return []any{promptBlock, value}
	}
}
