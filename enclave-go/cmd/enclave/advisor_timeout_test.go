package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/streamhttp"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

type advisorTimeoutLLM func(context.Context, *types.OpenAIChatRequest, io.Writer) error

func (f advisorTimeoutLLM) InvokeStreaming(ctx context.Context, req *types.OpenAIChatRequest, _ *types.AnthropicMessagesRequest, out io.Writer, _ ...llm.InvokeOptions) error {
	return f(ctx, req, out)
}

// Exercise the production HTTP timeout wrapper: its 30-minute fusion budget
// must not extend either advisor deadline inherited from the orchestration.
func advisorBlockedHTTP(t *testing.T, ctx context.Context, budget time.Duration) error {
	t.Helper()
	client := &http.Client{Transport: fusionBudgetTransport(func(r *http.Request) (*http.Response, error) {
		deadline, ok := r.Context().Deadline()
		if !ok || time.Until(deadline) > budget {
			t.Errorf("upstream deadline = %v, present=%t, budget=%s", deadline, ok, budget)
		}
		<-r.Context().Done()
		return nil, r.Context().Err()
	})}
	r, err := http.NewRequestWithContext(ctx, "POST", "https://provider.test/messages", nil)
	if err != nil {
		return err
	}
	_, err = streamhttp.Do(client, r)
	return err
}

func checkAdvisorFinalizationContext(t *testing.T, r *http.Request) {
	t.Helper()
	if r.URL.Path != "/internal/gateway/settle" && r.URL.Path != "/internal/gateway/refund" {
		return
	}
	if err := r.Context().Err(); err != nil {
		t.Errorf("%s inherited cancellation: %v", r.URL.Path, err)
	}
	deadline, ok := r.Context().Deadline()
	if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > 10*time.Second {
		t.Errorf("%s must have a fresh bounded deadline: %v", r.URL.Path, deadline)
	}
}

func TestAdvisorRequestDeadline(t *testing.T) {
	oldTimeout := advisorRequestTimeout
	advisorRequestTimeout = 200 * time.Millisecond
	t.Cleanup(func() { advisorRequestTimeout = oldTimeout })
	for _, kind := range []string{"worker", "fusion advice", "fusion worker", "partner", "hidden"} {
		for _, stream := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/stream=%t", kind, stream), func(t *testing.T) {
				var active, blocked atomic.Int32
				var completionDeadline atomic.Int64
				gateway, recorder := newFusionBudgetGateway(t, func(r *http.Request) {
					// Let a completed panel call settle only after the request expires.
					if r.URL.Path == "/internal/gateway/settle" && completionDeadline.Load() != 0 {
						time.Sleep(time.Until(time.Unix(0, completionDeadline.Load())) + time.Millisecond)
					}
					checkAdvisorFinalizationContext(t, r)
				})
				req := &types.OpenAIChatRequest{Model: trustedRouterPlato40Model, Stream: stream, Messages: []types.OpenAIChatMessage{{Role: "user", Content: "hard problem"}}}
				if kind == "fusion worker" || kind == "partner" || kind == "hidden" {
					req.Model = trustedRouterAdvisorModel
					if kind == "partner" {
						req.Model = parasailLiberty20Model
					}
					if kind == "hidden" {
						req.Model = trustedRouterAthenaModel
					}
					req.Tools = []any{map[string]any{"type": trustedRouterAdvisorTool, "parameters": map[string]any{
						"worker_models": []any{trustedRouterPrometheus40Model}, "advisor_models": []any{"model/fallback"}, "auto_initial_advice": false,
					}}}
				}
				_, panel, _ := fusionPresetPanelForModel(trustedRouterPrometheus40Model)
				provider := advisorTimeoutLLM(func(ctx context.Context, call *types.OpenAIChatRequest, out io.Writer) error {
					active.Add(1)
					defer active.Add(-1)
					stage, _ := call.Metadata["trustedrouter_fusion_stage"].(string)
					if kind == "fusion advice" && stage == "" {
						return writeAnthropicToolUseTestStream(out, advisorAdviceToolName)
					}
					if stage == "panel" && call.Model == panel[0] {
						deadline, _ := ctx.Deadline()
						completionDeadline.Store(deadline.UnixNano())
						return (&fusionSettlementLLM{}).InvokeStreaming(ctx, call, nil, out)
					}
					blocked.Add(1)
					return advisorBlockedHTTP(t, ctx, advisorRequestTimeout)
				})
				ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
				defer cancel()
				var out bytes.Buffer
				started := time.Now()
				handled, err := maybeServeAdvisor(ctx, &out, provider, req, gateway, nil, "bearer", nil, "deadline-test")
				if err != nil || !handled {
					t.Fatalf("handled=%t error=%v", handled, err)
				}
				if elapsed := time.Since(started); elapsed > time.Second {
					t.Fatalf("advisor did not stop at its deadline: %s", elapsed)
				}
				resp, err := http.ReadResponse(bufio.NewReader(&out), nil)
				if err != nil {
					t.Fatal(err)
				}
				defer resp.Body.Close()
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatal(err)
				}
				if stream {
					if resp.StatusCode != 200 || !strings.Contains(string(body), "data: [DONE]") || !strings.Contains(string(body), "error") {
						t.Fatalf("missing stream error: status=%d body=%s", resp.StatusCode, body)
					}
					if kind != "hidden" && !strings.Contains(string(body), "advisor request deadline exceeded") {
						t.Fatalf("missing stream deadline error: %s", body)
					}
				} else {
					var payload struct {
						Error struct {
							Message string `json:"message"`
						} `json:"error"`
					}
					if err := json.Unmarshal(body, &payload); err != nil || resp.StatusCode != 504 || payload.Error.Message != "advisor request deadline exceeded" {
						t.Fatalf("expected 504 JSON deadline error: status=%d body=%s error=%v", resp.StatusCode, body, err)
					}
				}
				if active.Load() != 0 || blocked.Load() == 0 {
					t.Fatalf("provider calls still active=%d blocked calls exercised=%d", active.Load(), blocked.Load())
				}
				recorder.mu.Lock()
				defer recorder.mu.Unlock()
				wantSettled := 1
				if kind == "worker" {
					wantSettled = 0
				}
				if kind == "fusion advice" {
					wantSettled++
				}
				wantRefunded := int(blocked.Load())
				if kind == "partner" {
					wantRefunded++
				}
				if len(recorder.settle) != wantSettled || len(recorder.refund) != wantRefunded || len(recorder.authorize) != wantSettled+wantRefunded {
					t.Fatalf("authorize=%d settle=%d refund=%d; want settle=%d refund=%d", len(recorder.authorize), len(recorder.settle), len(recorder.refund), wantSettled, wantRefunded)
				}
				for _, call := range recorder.settle {
					if strings.HasSuffix(fmt.Sprint(call["route_type"]), "fusion.panel") && (call["actual_input_tokens"] != float64(11) || call["actual_output_tokens"] != float64(7)) {
						t.Errorf("completed inner usage changed: %#v", call)
					}
				}
			})
		}
	}
}

func TestFusionAdvisorDeadline(t *testing.T) {
	oldTimeout := fusionAdvisorTimeout
	fusionAdvisorTimeout = 100 * time.Millisecond
	t.Cleanup(func() { fusionAdvisorTimeout = oldTimeout })
	for _, kind := range []string{"advice tool", "final error", "final fallback"} {
		t.Run(kind, func(t *testing.T) {
			gateway, recorder := newFusionBudgetGateway(t, func(r *http.Request) { checkAdvisorFinalizationContext(t, r) })
			config := testAdvisorConfig(t)
			config.AdvisorModels = []string{trustedRouterPrometheus40Model}
			if kind == "final fallback" {
				config.AdvisorModels = append(config.AdvisorModels, "model/fallback")
			}
			var workerCalls, blocked atomic.Int32
			provider := advisorTimeoutLLM(func(ctx context.Context, req *types.OpenAIChatRequest, out io.Writer) error {
				if req.Model == config.WorkerModels[0] {
					if workerCalls.Add(1) == 1 {
						return writeAnthropicToolUseTestStream(out, advisorAdviceToolName)
					}
					if !strings.Contains(lastChatMessageText(req.Messages), "Advisor unavailable") {
						t.Error("advice failure was not swallowed")
					}
					return writeAnthropicTextTestStream(out, req.Model, "continued without advice")
				}
				if req.Model == "model/fallback" {
					return writeAnthropicTextTestStream(out, req.Model, "fallback answer")
				}
				blocked.Add(1)
				return advisorBlockedHTTP(t, ctx, fusionAdvisorTimeout)
			})
			req := &types.OpenAIChatRequest{Model: trustedRouterAdvisorModel, Messages: []types.OpenAIChatMessage{{Role: "user", Content: "hard problem"}}}
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			started := time.Now()
			var result fusionCallResult
			var err error
			if kind == "advice tool" {
				result, _, _, _, _, err = runAdvisor(ctx, provider, req, config, gateway, nil, "bearer", "id", "log", nil, nil, 0, nil)
			} else {
				result, _, err = runAdvisorFinal(ctx, provider, req, config, req.Messages, gateway, nil, "bearer", "id", "log", nil, nil, 0, nil)
			}
			if time.Since(started) > time.Second || ctx.Err() != nil || blocked.Load() == 0 {
				t.Fatalf("fusion advice did not stop at its own bound: %v", err)
			}
			if kind == "final error" {
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("error=%v, want deadline exceeded", err)
				}
			} else if err != nil || result.Result.Text == "" {
				t.Fatalf("request failed to continue: result=%#v error=%v", result, err)
			}
			recorder.mu.Lock()
			defer recorder.mu.Unlock()
			if len(recorder.refund) != int(blocked.Load()) || len(recorder.authorize) != len(recorder.refund)+len(recorder.settle) {
				t.Fatalf("unfinalized calls: %#v", recorder)
			}
		})
	}
}

func TestFusionCollectorClosesReader(t *testing.T) {
	for _, kind := range []string{"message_stop", "collector error"} {
		t.Run(kind, func(t *testing.T) {
			gateway, recorder := newFusionBudgetGateway(t)
			writerDone := make(chan error, 1)
			provider := advisorTimeoutLLM(func(ctx context.Context, req *types.OpenAIChatRequest, out io.Writer) error {
				var err error
				if kind == "message_stop" {
					err = writeAnthropicTextTestStream(out, req.Model, "complete")
				} else {
					// Exceed the collector's maximum SSE block without a delimiter.
					_, err = io.WriteString(out, strings.Repeat("x", 65*1024*1024))
				}
				if err == nil {
					_, err = io.WriteString(out, ": trailing bytes\n\n")
				}
				writerDone <- err
				return err
			})
			req := &types.OpenAIChatRequest{Model: "model/test", Messages: []types.OpenAIChatMessage{{Role: "user", Content: "hello"}}}
			_, err := runFusionCall(t.Context(), provider, req, gateway, nil, "bearer", "fusion.panel", "id", "log", nil, false)
			if (err != nil) != (kind == "collector error") {
				t.Fatalf("collector error=%v", err)
			}
			select {
			case writeErr := <-writerDone:
				if writeErr == nil {
					t.Fatal("trailing write unexpectedly succeeded")
				}
			case <-time.After(time.Second):
				t.Fatal("provider writer remained blocked after collector returned")
			}
			recorder.mu.Lock()
			defer recorder.mu.Unlock()
			if kind == "message_stop" && (len(recorder.settle) != 1 || len(recorder.refund) != 0) {
				t.Fatal("completed generation was not billed")
			}
			if kind == "collector error" && (len(recorder.settle) != 0 || len(recorder.refund) != 1) {
				t.Fatal("failed generation was not refunded")
			}
		})
	}
}

func TestPartnerSettlementSurvivesAdvisorDeadline(t *testing.T) {
	gateway, recorder := newFusionBudgetGateway(t, func(r *http.Request) { checkAdvisorFinalizationContext(t, r) })
	ctx, cancel := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
	defer cancel()
	req := &types.OpenAIChatRequest{Model: parasailLiberty20Model}
	_, err := settlePartnerTopLevel(ctx, req, gateway, nil, &trustedrouter.Authorization{AuthorizationID: "partner", Model: req.Model}, fusionCallResult{Result: adapter.StreamResult{Text: "completed"}, OutputTokens: 7}, "id", time.Now(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(recorder.settle) != 1 {
		t.Fatalf("settlements=%d", len(recorder.settle))
	}
}

func TestAdvisorDeadlineStopsProviderFallback(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	var calls atomic.Int32
	provider := advisorTimeoutLLM(func(ctx context.Context, _ *types.OpenAIChatRequest, _ io.Writer) error {
		calls.Add(1)
		<-ctx.Done()
		return ctx.Err()
	})
	pr, pw := io.Pipe()
	defer pr.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		invokeProviderStream(ctx, provider, &types.OpenAIChatRequest{Model: "model/first"}, nil, pw,
			[]llm.InvokeOptions{{Model: "model/first"}, {Model: "model/fallback"}}, true, nil, newSelectedRouteTracker(), "log", true, false)
	}()
	_, err := io.ReadAll(pr)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error=%v, want deadline exceeded", err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("provider invocation did not stop")
	}
	if calls.Load() != 1 {
		t.Fatalf("started %d providers after deadline", calls.Load())
	}
}
