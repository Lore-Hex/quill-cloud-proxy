package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestChatStreamReportsSettledCostBeforeDone(t *testing.T) {
	for _, tc := range []struct {
		name                                         string
		cost                                         int
		includeUsage, failedSettlement, disconnected bool
	}{
		{name: "paid", cost: 12345, includeUsage: true},
		{name: "free", includeUsage: true},
		{name: "unreported-on-failure", includeUsage: true, failedSettlement: true},
		{name: "usage-opt-out", cost: 12345},
		{name: "disconnect-after-settlement", cost: 12345, includeUsage: true, disconnected: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out chatUsageTestWriter
			settlements := 0
			terminalBeforeSettlement := false
			gateway := trustedrouter.New("https://trustedrouter.com", "internal-test", &http.Client{
				Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
					if r.URL.Path != "/internal/gateway/settle" {
						t.Fatalf("unexpected control-plane path: %s", r.URL.Path)
					}
					settlements++
					terminalBeforeSettlement = strings.Contains(out.String(), "[DONE]")
					if !strings.Contains(out.String(), "Hello") {
						t.Error("answer was buffered until settlement instead of streaming")
					}
					if tc.failedSettlement {
						return &http.Response{StatusCode: 400, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"error":{"message":"test settlement failure"}}`))}, nil
					}
					out.fail.Store(tc.disconnected)
					return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(fmt.Sprintf(`{"data":{"generation_id":"gen_stream","cost_microdollars":%d,"model":"test-model","provider":"test"}}`, tc.cost)))}, nil
				}),
			})
			var req types.OpenAIChatRequest
			if err := json.Unmarshal([]byte(`{"model":"test-model","stream":true,"stream_options":{"include_usage":true},"messages":[{"role":"user","content":"hi"}]}`), &req); err != nil {
				t.Fatal(err)
			}
			req.StreamOptions.IncludeUsage = tc.includeUsage
			authz := &trustedrouter.Authorization{AuthorizationID: "auth_stream", WorkspaceID: "ws_test", APIKeyHash: "key_test", Model: "test-model", EndpointID: "test-endpoint", Provider: "test", UsageType: "Credits"}
			serveStreaming(context.Background(), &out, &fakeStreamingLLM{}, &req, &types.AnthropicMessagesRequest{}, []llm.InvokeOptions{{Model: "test-model", Provider: "test", EndpointID: "test-endpoint"}}, gateway, authz, nil, time.Now(), nil, "chat.completions", "test-stream-cost", "test-model")
			if settlements != 1 || terminalBeforeSettlement == tc.includeUsage {
				t.Errorf("settlements=%d terminalBeforeSettlement=%v includeUsage=%v", settlements, terminalBeforeSettlement, tc.includeUsage)
			}
			if tc.disconnected {
				return
			}
			response, err := http.ReadResponse(bufio.NewReader(&out.Buffer), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatal(err)
			}
			usageChunks := 0
			for _, line := range strings.Split(string(body), "\n") {
				if !strings.HasPrefix(line, "data: {") {
					continue
				}
				var chunk struct {
					Usage map[string]any `json:"usage"`
				}
				if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &chunk); err != nil {
					t.Fatal(err)
				}
				if chunk.Usage == nil {
					continue
				}
				usageChunks++
				var expectedCost any
				if !tc.failedSettlement {
					expectedCost = float64(tc.cost)
				}
				if chunk.Usage["cost_microdollars"] != expectedCost || chunk.Usage["prompt_tokens"] != float64(2) || chunk.Usage["completion_tokens"] != float64(2) {
					t.Errorf("incorrect final usage: %#v", chunk.Usage)
				}
			}
			wantUsage := 0
			if tc.includeUsage {
				wantUsage = 1
			}
			if usageChunks != wantUsage || strings.Count(string(body), "data: [DONE]") != 1 || !strings.HasSuffix(string(body), "data: [DONE]\n\n") {
				t.Errorf("want one usage chunk and one final DONE: %s", body)
			}
		})
	}
}

type chatUsageTestWriter struct {
	bytes.Buffer
	fail atomic.Bool
}

func (w *chatUsageTestWriter) Write(p []byte) (int, error) {
	if w.fail.Load() {
		return 0, io.ErrClosedPipe
	}
	return w.Buffer.Write(p)
}
