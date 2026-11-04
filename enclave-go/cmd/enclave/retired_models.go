package main

import (
	"strings"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

const retiredModelMessage = trustedrouter.RetiredModelMessage

func retiredModelManagementPath(path string) bool {
	path = strings.TrimPrefix(path, "/v1")
	for _, root := range []string{"/custom-models", "/user-models", "/models/user-provided", "/internal/gateway/resolve-custom-model"} {
		if path == root || strings.HasPrefix(path, root+"/") {
			return true
		}
	}
	return false
}

func isCustomModelID(model string) bool {
	return trustedrouter.IsRetiredModelID(model)
}

func retiredModelRequest(req *types.OpenAIChatRequest) bool {
	if req == nil {
		return false
	}
	if isCustomModelID(req.Model) {
		return true
	}
	for _, model := range req.Models {
		if isCustomModelID(model) {
			return true
		}
	}
	return false
}
