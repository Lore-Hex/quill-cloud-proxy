package llm

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
)

// EmbeddingInputLimitError contains only a validated numeric limit, never input
// text or an upstream error body. Other provider 400s remain provider failures.
type EmbeddingInputLimitError struct {
	MaxTokens int
}

func (e *EmbeddingInputLimitError) Error() string {
	return fmt.Sprintf("Each embedding input must contain at most %d tokens; split longer inputs into smaller chunks.", e.MaxTokens)
}

var embeddingInputLimitPattern = regexp.MustCompile(`^Invalid 'input(?:\[[0-9]+\])?': maximum input length is ([1-9][0-9]{0,7}) tokens\.$`)

func classifyEmbeddingHTTPError(provider string, status int, body []byte) error {
	if provider == "openai" && status == http.StatusBadRequest {
		var payload struct {
			Error struct {
				Type    string `json:"type"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if json.Unmarshal(body, &payload) == nil && payload.Error.Type == "invalid_request_error" {
			if match := embeddingInputLimitPattern.FindStringSubmatch(payload.Error.Message); match != nil {
				limit, err := strconv.Atoi(match[1])
				if err == nil {
					return &EmbeddingInputLimitError{MaxTokens: limit}
				}
			}
		}
	}
	return &upstreamHTTPError{status: status, body: string(body)}
}
