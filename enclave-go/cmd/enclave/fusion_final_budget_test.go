package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/testutil/fundedrequest"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

type fusionWireProjection struct {
	name, model string
	gemini      bool
	build       func(context.Context, *types.OpenAIChatRequest, *types.AnthropicMessagesRequest) (any, error)
}

// Build-tagged files add Bedrock and Gemini when those serializers are present.
var fusionFinalWireProjections = []fusionWireProjection{
	{"anthropic", "claude-haiku-4-5", false, fusionAnthropicWire},
	{"anthropic-adaptive", "claude-sonnet-4-6", false, fusionAnthropicWire},
}

func fusionAnthropicWire(_ context.Context, req *types.OpenAIChatRequest, body *types.AnthropicMessagesRequest) (any, error) {
	return llm.BuildAnthropicRequestShape(req.Model, req, body), nil
}

// Serialize the actual authorized request at the provider boundary, using the
// production native projection. Only the response and transport are faked.
type fusionFinalWireProbe struct {
	fusionEchoLLM
	projection fusionWireProjection
	recorder   *fusionGatewayRecorder
	mu         sync.Mutex
	wires      []json.RawMessage
	requests   []*types.OpenAIChatRequest
	authorized []map[string]any
}

func (p *fusionFinalWireProbe) InvokeStreaming(ctx context.Context, req *types.OpenAIChatRequest, body *types.AnthropicMessagesRequest, out io.Writer, options ...llm.InvokeOptions) error {
	p.recorder.mu.Lock()
	if len(p.recorder.authorize) == 0 {
		p.recorder.mu.Unlock()
		return fmt.Errorf("dispatch before authorization")
	}
	auth := p.recorder.authorize[len(p.recorder.authorize)-1]
	p.recorder.mu.Unlock()
	wire, err := p.projection.build(ctx, req, body)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(wire)
	if err != nil {
		return err
	}
	p.mu.Lock()
	p.wires = append(p.wires, raw)
	p.requests = append(p.requests, cloneChatRequest(req))
	p.authorized = append(p.authorized, auth)
	p.mu.Unlock()
	return p.fusionEchoLLM.InvokeStreaming(ctx, req, body, out, options...)
}

func TestFusionFinalAuthorizationVersusWire(t *testing.T) {
	for _, projection := range fusionFinalWireProjections {
		for _, path := range []string{"collected", "streaming", "observed-streaming"} {
			for _, tc := range []struct {
				name      string
				limit     *int
				reasoning any
				effort    string
			}{
				{"inherited-32768", intPtrMainTest(8192), map[string]any{"max_tokens": 32768}, ""},
				{"tiny", intPtrMainTest(1), map[string]any{"max_tokens": 32768}, ""},
				{"thinking-minimum", intPtrMainTest(1024), map[string]any{"max_tokens": 32768}, ""},
				{"thinking-minimum-plus-answer", intPtrMainTest(1025), map[string]any{"max_tokens": 32768}, ""},
				{"large-caller", intPtrMainTest(60000), map[string]any{"max_tokens": 32768}, ""},
				{"budget-alias", intPtrMainTest(8192), map[string]any{"budget_tokens": 32768}, ""},
				{"dynamic", intPtrMainTest(8192), map[string]any{"thinking_budget": -1}, ""},
				{"effort", intPtrMainTest(8192), nil, "high"},
				{"unset", nil, map[string]any{"max_tokens": 32768}, ""},
				{"zero", intPtrMainTest(0), map[string]any{"max_tokens": 32768}, ""},
			} {
				t.Run(projection.name+"/"+path+"/"+tc.name, func(t *testing.T) {
					gateway, recorder := newFusionBudgetGateway(t)
					probe := &fusionFinalWireProbe{projection: projection, recorder: recorder}
					req := &types.OpenAIChatRequest{Model: trustedRouterSynthModel, MaxTokens: tc.limit, Reasoning: tc.reasoning, ReasoningEffort: tc.effort, Messages: []types.OpenAIChatMessage{{Role: "user", Content: "hard problem"}}}
					before, _ := json.Marshal(req)
					ctx := context.Background()
					var out bytes.Buffer
					var err error
					config := fusionConfig{MaxCompletionTokens: 32768}
					models := []string{projection.model}
					switch path {
					case "collected":
						var final fusionCallResult
						final, _, err = runFusionFinal(ctx, probe, req, config, models, "analysis", nil, gateway, nil, "test", "id", "log", nil)
						out.WriteString(final.Result.Text)
					case "streaming":
						err = serveFusionFinalStreaming(ctx, &out, probe, req, config, models, "analysis", nil, fusionCallResult{}, gateway, nil, "test", "id", "log", nil)
					case "observed-streaming":
						err = serveFusionFinalStreamingObserved(ctx, &out, probe, req, config, models, "analysis", nil, fusionCallResult{}, gateway, nil, "test", "id", "log", nil, time.Now().Unix(), nil)
					}
					if err != nil {
						t.Fatal(err)
					}
					if !strings.Contains(out.String(), "final answer") {
						t.Fatalf("missing visible answer: %s", out.String())
					}
					probe.mu.Lock()
					defer probe.mu.Unlock()
					if len(probe.wires) != 1 {
						t.Fatalf("dispatches=%d, want 1", len(probe.wires))
					}
					inner, auth := probe.requests[0], probe.authorized[0]
					if auth["route_type"] != "fusion.final" || !reflect.DeepEqual(inner.MaxTokens, tc.limit) {
						t.Fatalf("changed final route or caller cap: inner=%+v auth=%v", inner, auth)
					}
					if tc.limit != nil && *tc.limit > 0 {
						fundedrequest.Check(t, probe.wires[0], int(auth["max_output_tokens"].(float64)), projection.gemini)
						if auth["max_tokens"] != float64(*tc.limit) || auth["max_output_tokens"] != float64(*tc.limit) || inner.InternalOutputTokenLimit != *tc.limit {
							t.Fatalf("final cap != authorized allowance: inner=%+v auth=%v", inner, auth)
						}
					} else {
						// Unset/nonpositive finals keep both historical authorization
						// estimates and native serialization; no new default or clamp.
						if inner.InternalOutputTokenLimit != 0 || auth["max_output_tokens"] != float64(512) || !reflect.DeepEqual(inner.Reasoning, tc.reasoning) {
							t.Fatalf("changed unset semantics: inner=%+v auth=%v", inner, auth)
						}
						legacy := fusionFinalRequest(req, projection.model, "analysis", nil, config)
						body, err := adapter.ToAnthropic(legacy, legacy.Model)
						if err != nil {
							t.Fatal(err)
						}
						wire, err := projection.build(ctx, legacy, body)
						if err != nil {
							t.Fatal(err)
						}
						want, err := json.Marshal(wire)
						if err != nil || !bytes.Equal(probe.wires[0], want) {
							t.Fatalf("changed unset wire: got %s want %s (err %v)", probe.wires[0], want, err)
						}
					}
					after, _ := json.Marshal(req)
					if !bytes.Equal(before, after) || req.InternalOutputTokenLimit != 0 {
						t.Fatalf("mutated caller request: before=%s after=%s", before, after)
					}
				})
			}
		}
	}
}

func TestInnerRouteExplicitAuthorizationVersusWire(t *testing.T) {
	// Audit all callers of runFusionCall*, authorizeFusionCall, and the web
	// search runner. Dynamic/future route names must have the same guarantee.
	for _, route := range []string{
		"fusion.panel", "fusion.judge", "fusion.selector", "fusion.mapreduce.mapper", "fusion.mapreduce.part", "fusion.mapreduce.reducer", "fusion.final",
		"advisor.worker", "advisor.advisor", "advisor.context_summary", "advisor.advisor_final",
		"subagent.controller", "subagent.worker", decideRouteType,
		"responses.web_search.planner", "responses.web_search.final", "chat.completions.web_search.planner", "chat.completions.web_search.final",
		"custom.web_search.planner", "custom.web_search.final", "future.inner",
	} {
		t.Run(route, func(t *testing.T) {
			gateway, recorder := newFusionBudgetGateway(t)
			probe := &fusionFinalWireProbe{projection: fusionFinalWireProjections[0], recorder: recorder}
			req := &types.OpenAIChatRequest{Model: "claude-haiku-4-5", MaxTokens: intPtrMainTest(8192), MaxCompletionTokens: intPtrMainTest(60000), MaxOutputTokens: intPtrMainTest(60000), Reasoning: map[string]any{"max_tokens": 32768}, Messages: []types.OpenAIChatMessage{{Role: "user", Content: "problem"}}}
			if _, err := runFusionCall(context.Background(), probe, req, gateway, nil, "test", route, "id", "log", nil, false); err != nil {
				t.Fatal(err)
			}
			probe.mu.Lock()
			defer probe.mu.Unlock()
			if len(probe.wires) != 1 || probe.authorized[0]["max_output_tokens"] != float64(8192) {
				t.Fatalf("unexpected dispatch/authorization: %+v", probe.authorized)
			}
			fundedrequest.Check(t, probe.wires[0], 8192, false)
			if req.MaxCompletionTokens != nil || req.MaxOutputTokens != nil {
				t.Fatal("conflicting output aliases retained")
			}
		})
	}
}

func TestFusionFinalPreservesCallerLimitWithCatalog(t *testing.T) {
	gateway, ledger := newFusionLedgerGateway(t, 10000000)
	if _, err := gateway.PublicModels(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := gateway.CachedModelOutputLimit("model/capped"); got != 8192 {
		t.Fatalf("catalog fixture cap=%d", got)
	}
	req := &types.OpenAIChatRequest{MaxTokens: intPtrMainTest(16000), Reasoning: map[string]any{"max_tokens": 32768}, Messages: []types.OpenAIChatMessage{{Role: "user", Content: "problem"}}}
	final := fusionFinalRequest(req, "model/capped", "analysis", nil, fusionConfig{MaxCompletionTokens: 32768})
	if _, _, err := authorizeFusionCall(context.Background(), final, gateway, nil, "test", "fusion.final", "id"); err != nil {
		t.Fatal(err)
	}
	if *final.MaxTokens != 16000 || ledger.authorized[0]["max_output_tokens"] != float64(16000) {
		t.Fatalf("final inherited inner default/catalog cap: final=%+v auth=%v", final, ledger.authorized)
	}
}
