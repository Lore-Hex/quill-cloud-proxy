package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

type rejectedEmbeddingLLM struct {
	fakeStreamingLLM
	err   error
	calls int
}

func (f *rejectedEmbeddingLLM) InvokeEmbedding(context.Context, *types.EmbeddingRequest, ...llm.InvokeOptions) (*types.EmbeddingResponse, error) {
	f.calls++
	return nil, f.err
}

func TestEmbeddingErrorsRefundOnceAndNeverExposeInput(t *testing.T) {
	for _, tc := range []struct {
		name   string
		err    error
		status int
	}{
		{"input_limit", fmt.Errorf("wrapped: %w", &llm.EmbeddingInputLimitError{MaxTokens: 8192}), 400},
		{"request_limit", fmt.Errorf("wrapped: %w", &llm.EmbeddingInputLimitError{MaxTokens: 300000, RequestLimit: true}), 400},
		{"unknown", errors.New("provider echoed PRIVATE-STATE in error body"), 502},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plane := &faultyControlPlane{}
			backend := &rejectedEmbeddingLLM{err: tc.err}
			var out bytes.Buffer
			stderr := captureStderr(t, func() {
				serveEmbeddings(context.Background(), &out, backend, []byte(`{"model":"openai/text-embedding-3-large","input":"PRIVATE-STATE"}`), plane.serve(t), true, "test-key", nil, "idem-embed", requestAttributionHeaders{}, "log-embed")
			})
			if !strings.HasPrefix(out.String(), fmt.Sprintf("HTTP/1.1 %d ", tc.status)) {
				t.Fatalf("response: %s", out.String())
			}
			if backend.calls != 1 || len(plane.log.authorize) != 1 || plane.log.refund != 1 || len(plane.log.settle) != 0 {
				t.Fatalf("invoke=%d authorize=%d refund=%d settle=%d", backend.calls, len(plane.log.authorize), plane.log.refund, len(plane.log.settle))
			}
			if strings.Contains(out.String()+stderr, "PRIVATE-STATE") {
				t.Fatal("customer input appeared in response or durable logs")
			}
			if !strings.Contains(stderr, `request_log_id="log-embed"`) {
				t.Fatal("missing correlation id")
			}
			if tc.status == 400 && !strings.Contains(out.String(), "embedding_input_too_long") {
				t.Fatal("missing actionable, stable input error")
			}
			if tc.name == "input_limit" && !strings.Contains(out.String(), "8192") {
				t.Fatal("missing per-input limit")
			}
			if tc.name == "request_limit" && (!strings.Contains(out.String(), "300000") || !strings.Contains(out.String(), "batches")) {
				t.Fatal("missing batch limit")
			}
		})
	}
}
