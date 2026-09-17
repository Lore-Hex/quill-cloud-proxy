package main

import (
	"encoding/json"
	"io"
	"strings"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func validateConfidentialHostRequest(method, path string, body []byte, gateway *trustedrouter.Client) *trustedrouter.ControlPlaneError {
	if method == "GET" {
		switch path {
		case "/health", "/attestation", "/receipt-attestation", "/receipt-key", "/v1/models", "/v1/key":
			return nil
		}
		if strings.HasPrefix(path, "/v1/models/") {
			return nil
		}
	}
	// Explicit allowlist: new APIs must prove their privacy plumbing before
	// accepting prompts on the confidential origin (including files/batches).
	if method != "POST" || (path != "/v1/chat/completions" && path != "/v1/responses" && path != "/v1/messages" && path != "/v1/responses/input_tokens") {
		return &trustedrouter.ControlPlaneError{StatusCode: 400, Type: "confidential_route_unsupported", Message: "This API route is not available on the confidential-only hostname."}
	}
	var request struct {
		Provider *types.ProviderRouting `json:"provider"`
	}
	if err := json.Unmarshal(body, &request); err != nil {
		return &trustedrouter.ControlPlaneError{StatusCode: 400, Type: "invalid_request_error", Message: "Invalid JSON request or provider settings."}
	}
	if err := trustedrouter.ValidateConfidentialRouting(request.Provider); err != nil {
		return err
	}
	if gateway == nil || !gateway.Enabled() {
		return &trustedrouter.ControlPlaneError{StatusCode: 503, Type: "confidential_routing_unavailable", Message: "Confidential route authorization is unavailable."}
	}
	return nil
}

func writeConfidentialHostError(w io.Writer, path string, err *trustedrouter.ControlPlaneError) {
	errorType := "invalid_request_error"
	if err.StatusCode >= 500 {
		errorType = "server_error"
		if path == "/v1/messages" {
			errorType = "api_error"
		}
	}
	errorBody := map[string]any{"error": map[string]any{
		"type": errorType, "code": err.Type, "message": err.Message,
		"status": err.StatusCode, "source": "router",
	}}
	if path == "/v1/messages" {
		errorBody["type"] = "error"
	}
	body, _ := json.Marshal(errorBody)
	writeJSONResponse(w, err.StatusCode, body)
}
