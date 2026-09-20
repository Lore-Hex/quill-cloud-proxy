package llm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestEmbeddingInputLimitClassification(t *testing.T) {
	message := "Invalid 'input[0]': maximum input length is 8192 tokens."
	for _, tc := range []struct {
		name, provider, kind, message string
		status                        int
		wantLimit                     bool
	}{
		{"observed", "openai", "invalid_request_error", message, 400, true},
		{"different_item", "openai", "invalid_request_error", strings.Replace(message, "[0]", "[12]", 1), 400, true},
		{"scalar", "openai", "invalid_request_error", strings.Replace(message, "[0]", "", 1), 400, true},
		{"wrong_provider", "together", "invalid_request_error", message, 400, false},
		{"server_error", "openai", "invalid_request_error", message, 500, false},
		{"rate_limit", "openai", "invalid_request_error", message, 429, false},
		{"wrong_type", "openai", "server_error", message, 400, false},
		{"unknown_400", "openai", "invalid_request_error", "bad upstream model mapping", 400, false},
		{"echoed_input", "openai", "invalid_request_error", message + " PRIVATE-INPUT", 400, false},
		{"zero", "openai", "invalid_request_error", strings.Replace(message, "8192", "0", 1), 400, false},
		{"negative", "openai", "invalid_request_error", strings.Replace(message, "8192", "-1", 1), 400, false},
		{"overflow", "openai", "invalid_request_error", strings.Replace(message, "8192", "99999999999999999999", 1), 400, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body, _ := json.Marshal(map[string]any{"error": map[string]string{"type": tc.kind, "message": tc.message}})
			err := fmt.Errorf("embedding request: %w", classifyEmbeddingHTTPError(tc.provider, tc.status, body))
			var limit *EmbeddingInputLimitError
			if got := errors.As(err, &limit); got != tc.wantLimit {
				t.Fatalf("classified=%v want=%v", got, tc.wantLimit)
			}
			if status, ok := HTTPStatusFromError(err); !ok || status != tc.status {
				t.Fatalf("status=%d ok=%v want=%d", status, ok, tc.status)
			}
			if tc.wantLimit && (limit.MaxTokens != 8192 || strings.Contains(limit.Error(), "input[")) {
				t.Fatalf("unsanitized or incorrect limit: %v", limit)
			}
		})
	}
	var limit *EmbeddingInputLimitError
	if errors.As(classifyEmbeddingHTTPError("openai", 400, []byte(`{"error":`)), &limit) {
		t.Fatal("malformed response must remain an upstream failure")
	}
}

func TestEmbeddingAdapterPreservesInputAndClassifiesProviderRejection(t *testing.T) {
	input := strings.Repeat("PRIVATE-INPUT ", 9000)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Input []string `json:"input"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body.Input) != 1 || body.Input[0] != input {
			t.Error("input was changed or truncated")
		}
		w.WriteHeader(400)
		_, _ = w.Write([]byte(`{"error":{"type":"invalid_request_error","message":"Invalid 'input[0]': maximum input length is 8192 tokens."}}`))
	}))
	defer server.Close()
	_, err := invokeOpenAICompatibleEmbeddings(context.Background(), server.Client(), "openai", server.URL, "test-key", &qtypes.EmbeddingRequest{Model: "openai/text-embedding-3-large", Input: input}, "text-embedding-3-large")
	var limit *EmbeddingInputLimitError
	if !errors.As(err, &limit) || limit.MaxTokens != 8192 {
		t.Fatalf("want input-limit error, got %v", err)
	}
	if strings.Contains(err.Error(), "PRIVATE-INPUT") {
		t.Fatal("customer input leaked into safe error")
	}
}

func TestEmbeddingRequestLimitClassification(t *testing.T) {
	message := "Invalid 'input': maximum request size is 300000 tokens per request."
	for _, tc := range []struct {
		name, message string
		wantLimit     bool
	}{
		{"observed", message, true},
		{"echoed_input", message + " PRIVATE-INPUT", false},
		{"zero", strings.Replace(message, "300000", "0", 1), false},
		{"negative", strings.Replace(message, "300000", "-1", 1), false},
		{"overflow", strings.Replace(message, "300000", "99999999999999999999", 1), false},
		{"wrong_scope", strings.Replace(message, "'input'", "'input[0]'", 1), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body, _ := json.Marshal(map[string]any{"error": map[string]string{"type": "invalid_request_error", "message": tc.message}})
			err := classifyEmbeddingHTTPError("openai", 400, body)
			var limit *EmbeddingInputLimitError
			if errors.As(err, &limit) != tc.wantLimit {
				t.Fatalf("unexpected classification: %v", err)
			}
			if tc.wantLimit && (limit.MaxTokens != 300000 || !limit.RequestLimit || !strings.Contains(limit.Error(), "in total") || !strings.Contains(limit.Error(), "batches")) {
				t.Fatalf("incorrect request-level limit: %v", limit)
			}
		})
	}
}
