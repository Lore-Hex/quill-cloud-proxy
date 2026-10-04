package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestRound2CompletedFusionAdvisorLostAtSettlement(t *testing.T) {
	old := fusionAdvisorTimeout
	fusionAdvisorTimeout = 150 * time.Millisecond
	t.Cleanup(func() { fusionAdvisorTimeout = old })
	var childDeadline time.Time
	provider := advisorTimeoutLLM(func(ctx context.Context, req *types.OpenAIChatRequest, out io.Writer) error {
		if d, ok := ctx.Deadline(); ok {
			// Panel invocations run concurrently. Only the final stage writes this.
			if req.Metadata["trustedrouter_fusion_stage"] == "final" {
				childDeadline = d
			}
		}
		return writeAnthropicTextTestStream(out, req.Model, "A complete useful answer.")
	})
	var finalSettlements int
	started := time.Now()
	gateway, recorder := newFusionBudgetGateway(t, func(r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(body))
		var payload map[string]any
		_ = json.Unmarshal(body, &payload)
		if r.URL.Path == "/internal/gateway/settle" && payload["route_type"] == "fusion.final" {
			finalSettlements++
			// Generation is complete and settlement has its detached context.
			// Let the orchestration's original deadline expire before acknowledging.
			deadline := childDeadline
			if deadline.IsZero() {
				deadline = started.Add(fusionAdvisorTimeout)
			}
			if time.Now().After(deadline) {
				t.Error("final generation did not finish before deadline")
			}
			time.Sleep(time.Until(deadline) + 30*time.Millisecond)
		}
	})
	config := testAdvisorConfig(t)
	config.AdvisorModels = []string{trustedRouterPrometheus40Model}
	req := &types.OpenAIChatRequest{Model: trustedRouterAdvisorModel, Messages: []types.OpenAIChatMessage{{Role: "user", Content: "hello"}}}
	result, attempts, err := runAdvisorFinal(t.Context(), provider, req, config, req.Messages, gateway, nil, "bearer", "r2", "r2", nil, nil, 0, nil)
	if finalSettlements != 1 {
		t.Fatalf("did not reach final settlement: %d, err=%v", finalSettlements, err)
	}
	if err != nil || result.Result.Text == "" {
		t.Fatalf("lost completed fusion advisor: result=%q attempts=%d err=%v settled=%d refunds=%d", result.Result.Text, len(attempts), err, len(recorder.settle), len(recorder.refund))
	}
}

func TestRound2CacheOnlyPartialBilling(t *testing.T) {
	for _, field := range []string{"cache_read_input_tokens", "cache_creation_input_tokens"} {
		t.Run(field, func(t *testing.T) {
			gateway, recorder := newFusionBudgetGateway(t)
			provider := advisorTimeoutLLM(func(ctx context.Context, req *types.OpenAIChatRequest, out io.Writer) error {
				_, err := fmt.Fprintf(out, "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":0,\"output_tokens\":0,\"%s\":4096}}}\n\n", field)
				if err != nil {
					return err
				}
				return context.DeadlineExceeded
			})
			req := &types.OpenAIChatRequest{Model: "anthropic/claude-opus-4.8", Messages: []types.OpenAIChatMessage{{Role: "user", Content: "hello"}}}
			_, err := runFusionCall(t.Context(), provider, req, gateway, nil, "bearer", "advisor.advisor", "r2", "r2", nil, false)
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("err=%v", err)
			}
			if len(recorder.settle) != 1 || len(recorder.refund) != 0 {
				t.Fatalf("provider reported 4096 %s, settlements=%d refunds=%d", field, len(recorder.settle), len(recorder.refund))
			}
		})
	}
}

func TestRound2PartialSettlementRetryOwnership(t *testing.T) {
	q := &settlementRetryQueue{jobs: make(chan settlementRetryJob, 4), maxAttempts: 2}
	old := settlementRetries
	settlementRetries = q
	t.Cleanup(func() { settlementRetries = old })
	providerErr := errors.New("interrupted provider")
	provider := advisorTimeoutLLM(func(ctx context.Context, req *types.OpenAIChatRequest, out io.Writer) error {
		_, err := io.WriteString(out, "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":11}}}\n\n")
		if err != nil {
			return err
		}
		return providerErr
	})
	var calls int
	gateway, recorder := newFusionBudgetGateway(t, func(r *http.Request) {
		if r.URL.Path == "/internal/gateway/settle" {
			calls++
			if calls == 1 {
				// Invalid settlement payload triggers a real control-plane error.
				r.Body = io.NopCloser(strings.NewReader("invalid json"))
			}
		}
	})
	req := &types.OpenAIChatRequest{Model: "model/test", Messages: []types.OpenAIChatMessage{{Role: "user", Content: "hello"}}}
	_, err := runFusionCall(t.Context(), provider, req, gateway, nil, "bearer", "advisor.worker", "r2", "r2", nil, false)
	var attempted *settlementAttemptedError
	if !errors.As(err, &attempted) || !errors.Is(err, providerErr) || len(q.jobs) != 1 {
		t.Fatalf("err=%v queued=%d", err, len(q.jobs))
	}
	job := <-q.jobs
	if job.usage.InputTokens != 11 || !job.usage.UsageEstimated {
		t.Fatalf("bad retry usage: %#v", job.usage)
	}
	q.process(t.Context(), job)
	if len(recorder.authorize) != 1 || len(recorder.refund) != 0 || len(recorder.settle) != 1 || calls != 2 || len(q.jobs) != 0 {
		t.Fatalf("authorization ownership: auth=%d refund=%d settle=%d calls=%d queued=%d", len(recorder.authorize), len(recorder.refund), len(recorder.settle), calls, len(q.jobs))
	}
}
