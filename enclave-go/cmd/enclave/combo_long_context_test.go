package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/auth"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestSeptemberCombosOnlyUseReviewedMillionTokenComponents(t *testing.T) {
	for model, providers := range longContextComboProviders {
		if slices.Contains(providers, "deepinfra") {
			t.Fatalf("DeepInfra is excluded from every new combo route, including %s", model)
		}
	}
	for _, model := range []string{trustedRouterPrometheus40Model, trustedRouterZeus30Model} {
		_, panel, ok := fusionPresetPanelForModel(model)
		if !ok || len(panel) > 8 || !isFusionModel(model) {
			t.Fatalf("invalid panel %s: %v", model, panel)
		}
		judges, _ := fusionPresetJudgeModelsForModel(model)
		finals, _ := fusionPresetFinalModelsForModel(model)
		if judges[0] != mimo26ProModel || finals[0] != mimo26ProModel {
			t.Fatal("MiMo 2.6 Pro must judge and synthesize")
		}
		for _, member := range append(append(panel, judges...), finals...) {
			if len(longContextComboProviders[member]) == 0 {
				t.Fatalf("unreviewed component %s in %s", member, model)
			}
			if strings.HasPrefix(member, "deepseek/") && member != deepSeekV41FlashModel {
				t.Fatalf("old DeepSeek in new graph: %s", member)
			}
		}
	}
	for _, model := range []string{"minimax/minimax-m3", "qwen/qwen3.8-2.4t-a95b"} {
		if len(longContextComboProviders[model]) < 2 || !slices.Contains(fusionPrometheus40Panel, model) {
			t.Fatalf("missing redundant long-context panel member %s", model)
		}
	}
	for _, model := range []string{trustedRouterPlato40Model, trustedRouterSocrates30Model} {
		config, ok := advisorPresetForModel(model)
		if !ok || config.AutoInitialAdvice || !isLongContextCombo(config.AdvisorModels[0]) {
			t.Fatalf("advisor is not optional or not long-context: %+v", config)
		}
		for _, worker := range config.WorkerModels {
			if len(longContextComboProviders[worker]) == 0 || advisorContextLimitTokens(worker) < 1_000_000 {
				t.Fatalf("short-context worker %s", worker)
			}
		}
		if advisorContextLimitTokens(model) != 1_000_000 {
			t.Fatalf("wrong nested context for %s", model)
		}
	}
}

func TestLongContextPolicyIntersectionAndIsolation(t *testing.T) {
	allow := false
	parent := &types.OpenAIChatRequest{
		Model: trustedRouterPrometheus40Model, InternalLongContextCombo: true,
		Provider: &types.ProviderRouting{Only: types.StringList{"together", "deepinfra"}, Ignore: types.StringList{"novita"}, AllowFallbacks: &allow},
	}
	child := cloneChatRequest(parent)
	child.Model = "qwen/qwen3.8-2.4t-a95b"
	if err := constrainLongContextComboRoute(child); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(child.Provider.Only, types.StringList{"together"}) || *child.Provider.AllowFallbacks || len(child.Provider.Ignore) != 1 {
		t.Fatalf("caller constraints lost: %+v", child.Provider)
	}
	if len(parent.Provider.Only) != 2 {
		t.Fatal("parallel sibling request policy mutated")
	}
	child.Provider.Only = types.StringList{"deepinfra"}
	if constrainLongContextComboRoute(child) == nil {
		t.Fatal("short-context-only provider pin accepted")
	}
	child.Model = "unreviewed/model"
	if constrainLongContextComboRoute(child) == nil {
		t.Fatal("unreviewed override accepted")
	}
	child.InternalLongContextCombo = false
	if err := constrainLongContextComboRoute(child); err != nil {
		t.Fatal("legacy route changed", err)
	}
}

func TestLongContextPolicyCannotBeEnabledFromPublicJSON(t *testing.T) {
	var req types.OpenAIChatRequest
	if err := json.Unmarshal([]byte(`{"InternalLongContextCombo":true,"internal_long_context_combo":true}`), &req); err != nil {
		t.Fatal(err)
	}
	if req.InternalLongContextCombo {
		t.Fatal("public JSON set internal routing policy")
	}
}

func TestLongContextAuthorizationIntegrity(t *testing.T) {
	req := &types.OpenAIChatRequest{Model: "minimax/minimax-m3", InternalLongContextCombo: true}
	if err := constrainLongContextComboRoute(req); err != nil {
		t.Fatal(err)
	}
	good := llm.InvokeOptions{Model: req.Model, Provider: "novita"}
	if err := validateLongContextComboOptions(req, []llm.InvokeOptions{good}); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []llm.InvokeOptions{{Model: req.Model, Provider: "together"}, {Model: "minimax/minimax-m2.7", Provider: "novita"}} {
		if validateLongContextComboOptions(req, []llm.InvokeOptions{good, bad}) == nil {
			t.Fatal("unreviewed fallback reached invocation")
		}
	}
}

func TestLongContextRejectedAuthorizationRefundsExactlyOnce(t *testing.T) {
	refunds := 0
	settles := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/internal/gateway/authorize":
			_, _ = io.WriteString(w, `{"data":{"authorization_id":"auth_wrong_route","model":"minimax/minimax-m3","provider":"deepinfra","endpoint_id":"wrong","usage_type":"Credits"}}`)
		case "/internal/gateway/refund":
			refunds++
			_, _ = io.WriteString(w, `{"data":{"refunded":true}}`)
		case "/internal/gateway/settle":
			settles++
		default:
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	gateway := trustedrouter.New(server.URL, "test", server.Client())
	req := &types.OpenAIChatRequest{Model: "minimax/minimax-m3", InternalLongContextCombo: true}
	_, options, err := authorizeFusionCall(context.Background(), req, gateway, nil, "test", "fusion.panel", "combo-integrity")
	if err == nil || len(options) != 0 || refunds != 1 || settles != 0 {
		t.Fatalf("error=%v options=%v refunds=%d settles=%d", err, options, refunds, settles)
	}
}

type longContextAdvisorTestLLM struct{ fusionEchoLLM }

func (l *longContextAdvisorTestLLM) InvokeStreaming(ctx context.Context, req *types.OpenAIChatRequest, body *types.AnthropicMessagesRequest, out io.Writer, options ...llm.InvokeOptions) error {
	for _, tool := range req.Tools {
		if raw, ok := tool.(map[string]any); ok && functionNameFromTool(raw) == advisorAdviceToolName {
			return writeAnthropicToolUseTestStream(out, advisorAdviceToolName)
		}
	}
	return l.fusionEchoLLM.InvokeStreaming(ctx, req, body, out, options...)
}

func TestSeptemberCombosLocalEndToEnd(t *testing.T) {
	for _, model := range []string{trustedRouterPrometheus40Model, trustedRouterZeus30Model, trustedRouterPlato40Model, trustedRouterSocrates30Model} {
		for _, stream := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/stream=%t", model, stream), func(t *testing.T) {
				gateway, recorder, cleanup := newFusionGatewayRecorder(t)
				defer cleanup()
				server, client := net.Pipe()
				defer client.Close()
				_ = client.SetDeadline(time.Now().Add(15 * time.Second))
				done := make(chan struct{})
				go func() {
					defer close(done)
					serveOne(context.Background(), server, auth.New(nil), &longContextAdvisorTestLLM{}, nil, nil, gateway, nil)
				}()
				payload, _ := json.Marshal(map[string]any{"model": model, "stream": stream, "max_tokens": 512, "messages": []map[string]any{{"role": "user", "content": "Give a short answer."}}})
				_, err := fmt.Fprintf(client, "POST /v1/chat/completions HTTP/1.1\r\nAuthorization: Bearer local-combo-key\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", len(payload), payload)
				if err != nil {
					t.Fatal(err)
				}
				resp, err := http.ReadResponse(bufio.NewReader(client), nil)
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(resp.Body)
				resp.Body.Close()
				if err != nil || resp.StatusCode != 200 || !strings.Contains(string(body), "answer from") {
					t.Fatalf("status=%d error=%v body=%s", resp.StatusCode, err, body)
				}
				if stream && !strings.Contains(string(body), "data: [DONE]") {
					t.Fatal("incomplete SSE")
				}
				client.Close()
				<-done
				recorder.mu.Lock()
				defer recorder.mu.Unlock()
				if len(recorder.authorize) != len(recorder.settle) || len(recorder.refund) != 0 {
					t.Fatal("incorrect settlement lifecycle")
				}
				seen := map[string]bool{}
				for _, call := range recorder.authorize {
					member := call["model"].(string)
					seen[member] = true
					policy, _ := call["provider"].(map[string]any)
					only, _ := policy["only"].([]any)
					if len(only) == 0 {
						t.Fatalf("missing inherited 1M policy on %s", member)
					}
					for _, provider := range only {
						if !slices.Contains(longContextComboProviders[member], provider.(string)) {
							t.Fatalf("unreviewed provider: %v", call)
						}
					}
				}
				panelModel := model
				if config, ok := advisorPresetForModel(model); ok {
					panelModel = config.AdvisorModels[0]
				}
				_, panel, _ := fusionPresetPanelForModel(panelModel)
				for _, member := range panel {
					if !seen[member] {
						t.Fatalf("missing nested component %s", member)
					}
				}
			})
		}
	}
}
