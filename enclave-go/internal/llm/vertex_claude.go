//go:build llm_multi

package llm

import (
	"encoding/json"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/upstreamerror"
)

const vertexClaudeCacheTTLError = `{"error":{"type":"invalid_request_error","param":"cache_control.ttl","message":"Vertex Claude currently supports only five-minute cache writes; omit ttl or use 5m."}}`

// Settlement currently records aggregate cache writes at the 5m multiplier.
// Until it distinguishes 1h writes, reject those before sending paid traffic.
func validateVertexClaudeCacheTTL(body *qtypes.AnthropicMessagesRequest) error {
	wire, err := json.Marshal(body)
	if err != nil {
		return err
	}
	var request struct {
		System   json.RawMessage `json:"system"`
		Messages []struct {
			Content json.RawMessage `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(wire, &request); err != nil {
		return err
	}
	if err := validateVertexClaudeCacheBlocks(request.System); err != nil {
		return err
	}
	for _, message := range request.Messages {
		if err := validateVertexClaudeCacheBlocks(message.Content); err != nil {
			return err
		}
	}
	return nil
}

func validateVertexClaudeCacheBlocks(raw json.RawMessage) error {
	var blocks []struct {
		Type         string          `json:"type"`
		CacheControl map[string]any  `json:"cache_control"`
		Content      json.RawMessage `json:"content"`
	}
	// String content has no cache breakpoints.
	if len(raw) == 0 || raw[0] != '[' {
		return nil
	}
	if json.Unmarshal(raw, &blocks) != nil {
		return &upstreamerror.Error{Status: 400, Body: vertexClaudeCacheTTLError}
	}
	for _, block := range blocks {
		if ttl, exists := block.CacheControl["ttl"]; exists && ttl != "5m" {
			return &upstreamerror.Error{Status: 400, Body: vertexClaudeCacheTTLError}
		}
		// Only tool-result content nests API content blocks. Never interpret
		// tool input data or JSON schemas as cache-control instructions.
		if block.Type == "tool_result" {
			if err := validateVertexClaudeCacheBlocks(block.Content); err != nil {
				return err
			}
		}
	}
	return nil
}
