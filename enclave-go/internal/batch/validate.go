package batch

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

const maxCustomIDBytes = 256

// ParseCreate preserves OpenRouter's stream-parser contract: endpoint and
// model must appear before requests. A normal struct unmarshal cannot enforce
// that observable wire behavior.
func ParseCreate(raw []byte) (CreateRequest, *APIError) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return CreateRequest{}, badRequest("invalid JSON", "", "bad_request")
	}

	var req CreateRequest
	seen := map[string]bool{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return CreateRequest{}, badRequest("invalid JSON", "", "bad_request")
		}
		name, ok := tok.(string)
		if !ok || seen[name] {
			return CreateRequest{}, badRequest("duplicate or invalid top-level field", name, "bad_request")
		}
		seen[name] = true
		switch name {
		case "endpoint":
			if err := dec.Decode(&req.Endpoint); err != nil {
				return CreateRequest{}, badRequest("endpoint must be a string", "endpoint", "bad_request")
			}
		case "model":
			if err := dec.Decode(&req.Model); err != nil {
				return CreateRequest{}, badRequest("model must be a string", "model", "bad_request")
			}
		case "requests":
			if !seen["endpoint"] || !seen["model"] {
				return CreateRequest{}, badRequest("endpoint and model must appear before requests", "requests", "bad_request")
			}
			if err := dec.Decode(&req.Requests); err != nil {
				return CreateRequest{}, badRequest("requests must be an array", "requests", "bad_request")
			}
		default:
			return CreateRequest{}, badRequest(fmt.Sprintf("unknown field %q", name), name, "bad_request")
		}
	}
	if _, err := dec.Token(); err != nil {
		return CreateRequest{}, badRequest("invalid JSON", "", "bad_request")
	}
	if err := ensureEOF(dec); err != nil {
		return CreateRequest{}, badRequest("invalid JSON", "", "bad_request")
	}
	if err := validateCreate(&req); err != nil {
		return CreateRequest{}, err
	}
	return req, nil
}

func ensureEOF(dec *json.Decoder) error {
	if _, err := dec.Token(); err == io.EOF {
		return nil
	} else if err != nil {
		return err
	}
	return fmt.Errorf("trailing JSON")
}

func validateCreate(req *CreateRequest) *APIError {
	req.Endpoint = strings.TrimSpace(req.Endpoint)
	req.Model = strings.TrimSpace(req.Model)
	if _, ok := supportedEndpoints[req.Endpoint]; !ok {
		return badRequest("unsupported batch endpoint", "endpoint", "unsupported_endpoint")
	}
	if req.Model == "" {
		return badRequest("model is required", "model", "bad_request")
	}
	if len(req.Requests) == 0 {
		return badRequest("requests must be a non-empty array", "requests", "bad_request")
	}
	customIDs := make(map[string]struct{}, len(req.Requests))
	for i := range req.Requests {
		item := &req.Requests[i]
		param := fmt.Sprintf("requests[%d]", i)
		if item.CustomID == "" || len(item.CustomID) > maxCustomIDBytes {
			return badRequest("custom_id must be between 1 and 256 bytes", param+".custom_id", "bad_request")
		}
		if _, exists := customIDs[item.CustomID]; exists {
			return badRequest("custom_id must be unique within the batch", param+".custom_id", "duplicate_custom_id")
		}
		customIDs[item.CustomID] = struct{}{}
		body, err := normalizedBody(req.Endpoint, req.Model, item.Body)
		if err != nil {
			err.Param = param + ".body" + err.Param
			return err
		}
		item.Body = body
	}
	return nil
}

func normalizedBody(endpoint, model string, raw json.RawMessage) (json.RawMessage, *APIError) {
	var body map[string]json.RawMessage
	if len(raw) == 0 || json.Unmarshal(raw, &body) != nil || body == nil {
		return nil, badRequest("body must be a JSON object", "", "bad_request")
	}
	if value, ok := body["model"]; ok {
		var innerModel string
		if json.Unmarshal(value, &innerModel) != nil || innerModel != model {
			return nil, badRequest("request body model must match the batch model", ".model", "model_mismatch")
		}
	} else {
		body["model"], _ = json.Marshal(model)
	}
	if value, ok := body["stream"]; ok {
		var stream bool
		if json.Unmarshal(value, &stream) != nil || stream {
			return nil, badRequest("streaming is not supported in batches", ".stream", "unsupported_parameter")
		}
	}
	if endpoint == "/v1/embeddings" {
		if _, ok := body["provider"]; ok {
			return nil, badRequest("provider preferences are not supported for batch embeddings", ".provider", "unsupported_parameter")
		}
		if _, ok := body["input_type"]; ok {
			return nil, badRequest("input_type is not supported for batch embeddings", ".input_type", "unsupported_parameter")
		}
		if input, ok := body["input"]; !ok || !validEmbeddingInput(input) {
			return nil, badRequest("unsupported or missing batch embeddings input", ".input", "unsupported_parameter")
		}
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		return nil, badRequest("invalid request body", "", "bad_request")
	}
	return encoded, nil
}

func validEmbeddingInput(raw json.RawMessage) bool {
	var value any
	if json.Unmarshal(raw, &value) != nil {
		return false
	}
	return validEmbeddingValue(value, 0)
}

func validEmbeddingValue(value any, depth int) bool {
	switch typed := value.(type) {
	case string:
		return depth == 0 && typed != ""
	case []any:
		if len(typed) == 0 || depth >= 2 {
			return false
		}
		switch typed[0].(type) {
		case string:
			if depth != 0 {
				return false
			}
			for _, item := range typed {
				text, ok := item.(string)
				if !ok || text == "" {
					return false
				}
			}
		case float64:
			for _, item := range typed {
				token, ok := item.(float64)
				if !ok || token < 0 || token != float64(int64(token)) {
					return false
				}
			}
		case []any:
			if depth != 0 {
				return false
			}
			for _, item := range typed {
				tokens, ok := item.([]any)
				if !ok || !validEmbeddingValue(tokens, depth+1) {
					return false
				}
			}
		default:
			return false
		}
		return true
	default:
		return false
	}
}

func badRequest(message, param, code string) *APIError {
	return &APIError{Status: 400, Message: message, Type: "invalid_request_error", Code: code, Param: param}
}
