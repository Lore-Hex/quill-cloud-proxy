package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestFusionSettlementFinalization(t *testing.T) {
	for _, stage := range []string{"panel", "judge", "final_observed_stream"} {
		for _, scenario := range []struct {
			name    string
			cancel  bool
			fail    bool
			ackLost bool
		}{
			{name: "canceled_after_generation", cancel: true},
			{name: "settlement_failure", fail: true},
			{name: "canceled_and_settlement_failure", cancel: true, fail: true},
			{name: "lost_acknowledgement", fail: true, ackLost: true},
		} {
			t.Run(stage+"/"+scenario.name, func(t *testing.T) {
				q := &settlementRetryQueue{jobs: make(chan settlementRetryJob, 4), maxAttempts: 2}
				oldQueue := settlementRetries
				settlementRetries = q
				t.Cleanup(func() { settlementRetries = oldQueue })

				const requestID = "fusion_settlement_test"
				const requestLogID = "rlog_0123456789abcdef0123456789abcdef"
				const model = "test-model"
				routeType := "fusion." + stage
				key := requestID + ":" + stage + ":0"
				streamed := stage == "final_observed_stream"
				if streamed {
					routeType = "fusion.final"
					key = requestID + ":final"
				}
				ctx := trustedrouter.WithRequestLogID(t.Context(), requestLogID)
				ctx = trustedrouter.WithClientContext(ctx, &types.ClientContext{V: 1, Source: "tr", Attempt: intPtrMainTest(1)})
				ctx, cancel := context.WithCancel(ctx)
				defer cancel()
				var settleBodies []map[string]any
				authorizations, charges := 0, 0
				settled := map[string]bool{}
				gateway := trustedrouter.New("https://trustedrouter.com", "internal", &http.Client{
					Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
						var body map[string]any
						if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
							t.Fatal(err)
						}
						response := func(status int, body string) (*http.Response, error) {
							return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
						}
						switch r.URL.Path {
						case "/internal/gateway/authorize":
							authorizations++
							if body["idempotency_key"] != key || body["route_type"] != routeType {
								t.Fatalf("unexpected authorization identity: %#v", body)
							}
							return response(200, `{"data":{"authorization_id":"auth_fusion","model":"test-model","endpoint_id":"test-endpoint","provider":"test","usage_type":"Credits"}}`)
						case "/internal/gateway/settle":
							settleBodies = append(settleBodies, body)
							if err := r.Context().Err(); err != nil {
								t.Errorf("settlement inherited request cancellation: %v", err)
								return nil, err
							}
							if len(settleBodies) == 1 {
								deadline, ok := r.Context().Deadline()
								if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > 10*time.Second {
									t.Errorf("initial settlement must have a fresh bounded deadline: %v, %v", deadline, ok)
								}
								if scenario.fail && !scenario.ackLost {
									return response(503, `{"error":{"message":"settlement unavailable"}}`)
								}
							}
							// Model the router's idempotent ledger, including a charge whose
							// acknowledgement never reached the original caller.
							identity := fmt.Sprint(body["authorization_id"], "/", body["request_id"])
							alreadySettled := settled[identity]
							if !alreadySettled {
								charges++
								settled[identity] = true
							}
							if len(settleBodies) == 1 && scenario.ackLost {
								return nil, context.DeadlineExceeded
							}
							return response(200, fmt.Sprintf(`{"data":{"settled":true,"already_settled":%t}}`, alreadySettled))
						default:
							t.Fatalf("unexpected control-plane path (must not refund): %s", r.URL.Path)
							return nil, errors.New("unexpected path")
						}
					}),
				})
				req := &types.OpenAIChatRequest{Model: model, Messages: []types.OpenAIChatMessage{{Role: "user", Content: "hello"}}}
				provider := &fusionSettlementLLM{}
				if scenario.cancel {
					provider.afterGeneration = cancel
				}
				var err error
				if streamed {
					var out bytes.Buffer
					err = serveFusionFinalStreamingObserved(ctx, &out, provider, req, fusionConfig{}, []string{model}, "{}", nil, fusionCallResult{}, gateway, nil, "bearer", requestID, requestLogID, req.Messages, 1, nil)
					if !strings.Contains(out.String(), `"content":"Hello"`) {
						t.Fatalf("observed final did not stream its answer: %s", out.String())
					}
				} else {
					_, err = runFusionCallObserved(ctx, provider, req, gateway, nil, "bearer", routeType, key, requestLogID, nil, false, nil, false)
				}
				var attempted *settlementAttemptedError
				if scenario.fail {
					if !errors.As(err, &attempted) {
						t.Fatalf("error = %v, want settlementAttemptedError", err)
					}
					if len(q.jobs) != 1 {
						t.Fatalf("queued settlements = %d, want 1", len(q.jobs))
					}
					job := <-q.jobs
					if job.trGateway != gateway || job.authorization.AuthorizationID != "auth_fusion" ||
						!job.authorization.ControlPlaneEndpointSet || job.authorization.ControlPlaneEndpoint != 0 ||
						job.usage.RequestID != key || job.usage.InputTokens != 11 || job.usage.OutputTokens != 7 ||
						job.usage.CacheReadInputTokens != 3 || job.usage.CacheCreationInputTokens != 5 ||
						job.usage.UsageEstimated || job.usage.RouteType != routeType || job.usage.Streamed != streamed ||
						job.usage.SelectedModel != model || job.usage.SelectedEndpoint != "test-endpoint" {
						t.Fatalf("queued settlement lost billing state: %#v", job)
					}
					q.process(t.Context(), job)
				} else if err != nil {
					t.Fatal(err)
				}
				wantAttempts := 1
				if scenario.fail {
					wantAttempts = 2
				}
				if len(settleBodies) != wantAttempts || authorizations != 1 || charges != 1 || len(q.jobs) != 0 {
					t.Fatalf("settle attempts=%d authorizations=%d charges=%d queued=%d", len(settleBodies), authorizations, charges, len(q.jobs))
				}
				for _, body := range settleBodies {
					// Queue compaction intentionally drops prompt-adjacent metadata.
					delete(body, "metadata")
					if body["request_id"] != key || body["gateway_request_id"] != requestLogID || body["actual_input_tokens"] != float64(11) || body["actual_output_tokens"] != float64(7) || body["route_type"] != routeType || body["streamed"] != streamed {
						t.Errorf("incorrect settlement body: %#v", body)
					}
					if client, ok := body["client"].(map[string]any); !ok || client["source"] != "tr" || client["attempt"] != float64(1) {
						t.Errorf("lost client context: %#v", body["client"])
					}
					if !reflect.DeepEqual(body, settleBodies[0]) {
						t.Errorf("retry changed settlement identity or usage: first=%#v retry=%#v", settleBodies[0], body)
					}
				}
			})
		}
	}
}

type fusionSettlementLLM struct {
	afterGeneration func()
}

func (f *fusionSettlementLLM) InvokeStreaming(_ context.Context, _ *types.OpenAIChatRequest, _ *types.AnthropicMessagesRequest, out io.Writer, _ ...llm.InvokeOptions) error {
	// The provider has produced a complete generation. Simulate the client
	// leaving before the result is collected and settlement begins.
	const generated = `event: message_start
data: {"type":"message_start","message":{"usage":{"input_tokens":11,"output_tokens":0,"cache_read_input_tokens":3,"cache_creation_input_tokens":5}}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hello world"}}

event: message_delta
data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":7}}

event: message_stop
data: {"type":"message_stop"}

`
	if f.afterGeneration != nil {
		f.afterGeneration()
	}
	_, err := io.WriteString(out, generated)
	return err
}
