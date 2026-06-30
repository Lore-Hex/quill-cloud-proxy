package main

import (
	"context"
	"strings"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func maybeResolveCustomModelForOrchestration(
	ctx context.Context,
	req *types.OpenAIChatRequest,
	trGateway *trustedrouter.Client,
	bearer string,
	routeType string,
) (*trustedrouter.Authorization, error) {
	if req == nil || !isCustomModelID(req.Model) {
		return nil, nil
	}
	if trGateway == nil || !trGateway.Enabled() {
		return nil, &adapter.AdapterError{Status: 503, Message: "custom models require the TrustedRouter control plane", Context: "custom_model"}
	}
	authorization, err := trGateway.ResolveCustomModel(ctx, bearer, req.Model, routeType)
	if err != nil {
		return nil, err
	}
	if authorization == nil || authorization.CustomModel == nil {
		return nil, &adapter.AdapterError{Status: 502, Message: "custom model resolution returned no custom model", Context: "custom_model"}
	}
	baseModelID := strings.TrimSpace(authorization.CustomModel.BaseModelID)
	if baseModelID == "" {
		return nil, &adapter.AdapterError{Status: 502, Message: "custom model has no base model", Context: "custom_model.base_model_id"}
	}
	if !isOrchestrationModel(baseModelID) {
		return nil, nil
	}
	req.ResponseModel = strings.TrimSpace(authorization.CustomModel.ID)
	req.Model = baseModelID
	req.Models = nil
	applyCustomModelPrompt(req, authorization)
	return authorization, nil
}

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

func requestResponseModel(req *types.OpenAIChatRequest, fallback string) string {
	if req != nil {
		modelID := strings.TrimSpace(req.ResponseModel)
		if modelID != "" {
			return modelID
		}
	}
	return fallback
}

func isCustomModelID(model string) bool {
	return strings.HasPrefix(strings.TrimSpace(model), "trustedrouter/user-")
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
