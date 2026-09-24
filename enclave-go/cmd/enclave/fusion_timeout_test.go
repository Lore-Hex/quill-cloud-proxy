package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/auth"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/streamhttp"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

// A socket-free HTTP provider: it uses the same streamhttp.Do entry point as
// production adapters, but NEVER opts itself into fusion timeouts. The context
// must come through one of the two production orchestration call sites.
type fusionHTTPProbe struct {
	fusionEchoLLM
	mu        sync.Mutex
	deadlines []time.Duration
	stages    []string
	limits    []int
	retry     bool
}

func (f *fusionHTTPProbe) InvokeStreaming(ctx context.Context, req *types.OpenAIChatRequest, body *types.AnthropicMessagesRequest, out io.Writer, options ...llm.InvokeOptions) error {
	var wire bytes.Buffer
	if err := f.fusionEchoLLM.InvokeStreaming(ctx, req, body, &wire, options...); err != nil {
		return err
	}
	client := &http.Client{Timeout: 25 * time.Millisecond, Transport: fusionBudgetTransport(func(r *http.Request) (*http.Response, error) {
		deadline, ok := r.Context().Deadline()
		if !ok {
			return nil, fmt.Errorf("missing HTTP deadline")
		}
		f.mu.Lock()
		f.deadlines = append(f.deadlines, time.Until(deadline))
		stage, _ := req.Metadata["trustedrouter_fusion_stage"].(string)
		f.stages = append(f.stages, stage)
		limit := 0
		if req.MaxTokens != nil {
			limit = *req.MaxTokens
		}
		f.limits = append(f.limits, limit)
		retry := f.retry && len(f.deadlines) == 1
		f.mu.Unlock()
		if retry {
			return &http.Response{StatusCode: 429, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("rate limited"))}, nil
		}
		pr, pw := io.Pipe()
		go func() {
			stop := context.AfterFunc(r.Context(), func() { _ = pw.CloseWithError(r.Context().Err()) })
			defer stop()
			defer func() { _ = pw.CloseWithError(r.Context().Err()) }()
			ticker := time.NewTicker(10 * time.Millisecond)
			defer ticker.Stop()
			for i := 0; i < 8; i++ {
				select {
				case <-r.Context().Done():
					return
				case <-ticker.C:
				}
				if _, err := io.WriteString(pw, ": thinking\n\n"); err != nil {
					return
				}
			}
			_, _ = pw.Write(wire.Bytes())
		}()
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: pr}, nil
	})}
	r, err := http.NewRequestWithContext(ctx, "POST", "https://provider.test/messages", nil)
	if err != nil {
		return err
	}
	resp, err := streamhttp.Do(client, r)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("llm/upstream: http %d: rate limited", resp.StatusCode)
	}
	_, err = io.Copy(out, resp.Body)
	return err
}

func TestFusionOrchestrationHTTPTimeouts(t *testing.T) {
	for _, kind := range []string{"panel and judge", "streaming final", "observed streaming final", "nested advisor", "judge retry", "direct", "ordinary advisor"} {
		t.Run(kind, func(t *testing.T) {
			gateway, _ := newFusionBudgetGateway(t)
			provider := &fusionHTTPProbe{retry: kind == "judge retry"}
			req := &types.OpenAIChatRequest{Model: trustedRouterSynthModel, MaxTokens: intPtrMainTest(4096), Messages: []types.OpenAIChatMessage{{Role: "user", Content: "hard problem"}}}
			config := fusionConfig{AnalysisModels: []string{"model/a", "model/b"}, SelectionStrategy: defaultFusionSelectionStrategy}
			ctx := context.Background()
			var err error
			var out bytes.Buffer
			switch kind {
			case "panel and judge":
				_, _, err = runFusionPanelAndJudge(ctx, provider, req, config, []string{"model/judge"}, gateway, nil, "test", "id", "log")
			case "streaming final":
				err = serveFusionFinalStreaming(ctx, &out, provider, req, config, []string{"model/final"}, "analysis", nil, fusionCallResult{}, gateway, nil, "test", "id", "log", nil)
			case "observed streaming final":
				err = serveFusionFinalStreamingObserved(ctx, &out, provider, req, config, []string{"model/final"}, "analysis", nil, fusionCallResult{}, gateway, nil, "test", "id", "log", nil, time.Now().Unix(), nil)
			case "nested advisor":
				ac := advisorConfig{Depth: 3, AdvisorMaxTokens: 4096}
				advisorReq := advisorRequest(req, trustedRouterPrometheus40Model, req.Messages, ac)
				_, err = runFusionAdvisorRequest(ctx, provider, advisorReq, ac, trustedRouterPrometheus40Model, gateway, nil, "test", "id", "log", nil)
			case "judge retry":
				_, _, err = runFusionJudge(ctx, provider, req, config, []string{"model/judge-a", "model/judge-b"}, nil, gateway, nil, "test", "id", "log")
			case "direct":
				server, client := net.Pipe()
				defer client.Close()
				_ = client.SetDeadline(time.Now().Add(10 * time.Second))
				go serveOne(ctx, server, auth.New(nil), provider, nil, nil, gateway, nil)
				payload := `{"model":"model/direct","messages":[{"role":"user","content":"hard problem"}]}`
				if _, writeErr := fmt.Fprintf(client, "POST /v1/chat/completions HTTP/1.1\r\nAuthorization: Bearer test\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", len(payload), payload); writeErr != nil {
					t.Fatal(writeErr)
				}
				resp, readErr := http.ReadResponse(bufio.NewReader(client), nil)
				if readErr != nil {
					t.Fatal(readErr)
				}
				defer resp.Body.Close()
				content, readErr := io.ReadAll(resp.Body)
				if readErr != nil {
					t.Fatal(readErr)
				}
				if resp.StatusCode == 200 {
					t.Fatalf("ordinary direct handler survived HTTP timeout: %s", content)
				}
				err = fmt.Errorf("direct HTTP %d: %s", resp.StatusCode, content)
			default:
				route := "chat.completions"
				if kind == "ordinary advisor" {
					route = "advisor.advisor"
				}
				_, err = runFusionCall(ctx, provider, req, gateway, nil, "test", route, "id", "log", nil, false)
			}
			direct := kind == "direct" || kind == "ordinary advisor"
			if direct {
				if err == nil {
					t.Fatal("ordinary call survived old HTTP deadline")
				}
			} else if err != nil {
				t.Fatal(err)
			}
			provider.mu.Lock()
			defer provider.mu.Unlock()
			wantCalls := map[string]int{"panel and judge": 3, "streaming final": 1, "observed streaming final": 1, "nested advisor": 8, "judge retry": 2, "direct": 1, "ordinary advisor": 1}[kind]
			if len(provider.deadlines) != wantCalls {
				t.Fatalf("attempts=%d want %d", len(provider.deadlines), wantCalls)
			}
			for i, d := range provider.deadlines {
				if direct {
					if d > 25*time.Millisecond {
						t.Fatalf("ordinary deadline=%s", d)
					}
				} else if d < 29*time.Minute || d > 30*time.Minute {
					t.Fatalf("attempt %d deadline=%s: production fusion opt-in missing", i, d)
				}
				if kind == "nested advisor" && (provider.stages[i] == "panel" || provider.stages[i] == "judge") && provider.limits[i] != fusionPanelReasoningTokens {
					t.Fatalf("advisor shrank %s budget to %d", provider.stages[i], provider.limits[i])
				}
			}
			if !direct && kind != "panel and judge" && kind != "judge retry" && kind != "nested advisor" && !strings.Contains(out.String(), "final answer") {
				t.Fatalf("no final output: %s", out.String())
			}
		})
	}
}
