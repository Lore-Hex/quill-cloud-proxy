package main

import (
	"strings"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func authorizationResponseModel(fallback string, authorization *trustedrouter.Authorization) string {
	if authorization != nil {
		if modelID := strings.TrimSpace(authorization.ResponseModel); modelID != "" {
			return modelID
		}
	}
	return fallback
}

func hidesPublicRouteMetadata(authorization *trustedrouter.Authorization) bool {
	return authorization != nil && authorization.HidePublicMetadata
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

func requestOrchestrationResponseModel(req *types.OpenAIChatRequest, fallback string) string {
	if req == nil {
		return fallback
	}
	if modelID := strings.TrimSpace(req.ResponseModel); modelID != "" {
		return modelID
	}
	if modelID := strings.TrimSpace(req.Model); modelID != "" && isOrchestrationModel(modelID) {
		return modelID
	}
	return fallback
}
