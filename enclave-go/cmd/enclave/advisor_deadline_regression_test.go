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
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

// Regression cases adapted from Sol's SOL_REPROS.go.txt.
func TestReviewCompletedBeforeDeadline(t *testing.T) {
	for _, stream := range []bool{false, true} {
		t.Run(fmt.Sprintf("stream=%t", stream), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
			defer cancel()
			gateway, recorder := newFusionBudgetGateway(t, func(r *http.Request) {
				if r.URL.Path == "/internal/gateway/settle" {
					if ctx.Err() != nil {
						t.Error("generation did not finish before deadline")
					}
					<-ctx.Done()
					checkAdvisorFinalizationContext(t, r)
				}
			})
			req := &types.OpenAIChatRequest{Model: trustedRouterAdvisorModel, Stream: stream, Messages: []types.OpenAIChatMessage{{Role: "user", Content: "hello"}}}
			var out reviewKeepAliveBuffer
			serve := serveAdvisorNonStreaming
			if stream {
				serve = serveAdvisorStreaming
			}
			serve(ctx, &out, &fusionSettlementLLM{}, req, testAdvisorConfig(t), gateway, nil, "bearer", nil, "review")
			resp, err := http.ReadResponse(bufio.NewReader(&out), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "Hello world") || strings.Contains(string(body), "advisor request deadline exceeded") {
				t.Fatalf("lost completed answer: status=%d body=%s", resp.StatusCode, body)
			}
			if len(recorder.settle) != 1 || len(recorder.refund) != 0 {
				t.Fatalf("settlements=%d refunds=%d, want 1/0", len(recorder.settle), len(recorder.refund))
			}
		})
	}
}

func TestReviewPartialGenerationBilling(t *testing.T) {
	for _, tc := range []struct {
		name          string
		input, output int
		reportUsage   bool
	}{
		{"both", 11, 7, true}, {"input_only", 11, 0, true}, {"output_only", 0, 7, true},
		{"zero_usage", 0, 0, true}, {"no_usage", 0, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
			defer cancel()
			gateway, recorder := newFusionBudgetGateway(t, func(r *http.Request) { checkAdvisorFinalizationContext(t, r) })
			provider := advisorTimeoutLLM(func(ctx context.Context, _ *types.OpenAIChatRequest, out io.Writer) error {
				if tc.reportUsage {
					if _, err := fmt.Fprintf(out, "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":%d}}}\n\n", tc.input); err != nil {
						return err
					}
				}
				if _, err := io.WriteString(out, "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"generated and billed tokens\"}}\n\n"); err != nil {
					return err
				}
				if tc.reportUsage {
					if _, err := fmt.Fprintf(out, "event: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":%d}}\n\n", tc.output); err != nil {
						return err
					}
				}
				<-ctx.Done()
				return ctx.Err()
			})
			req := &types.OpenAIChatRequest{Model: "model/test", Messages: []types.OpenAIChatMessage{{Role: "user", Content: "hello"}}}
			result, err := runFusionCall(ctx, provider, req, gateway, nil, "bearer", "fusion.panel", "review", "review", nil, false)
			if !errors.Is(err, context.DeadlineExceeded) || result.Result.Text != "" {
				t.Fatalf("partial generation must fail without an answer: result=%#v err=%v", result, err)
			}
			if tc.input == 0 && tc.output == 0 {
				if len(recorder.refund) != 1 || len(recorder.settle) != 0 {
					t.Fatalf("refunds=%d settlements=%d, want 1/0", len(recorder.refund), len(recorder.settle))
				}
				return
			}
			if len(recorder.settle) != 1 || len(recorder.refund) != 0 {
				t.Fatalf("settlements=%d refunds=%d, want 1/0", len(recorder.settle), len(recorder.refund))
			}
			usage := recorder.settle[0]
			if usage["actual_input_tokens"] != float64(tc.input) || usage["actual_output_tokens"] != float64(tc.output) || usage["usage_estimated"] != true {
				t.Fatalf("incorrect partial settlement: %#v", usage)
			}
		})
	}
}

type reviewKeepAliveBuffer struct {
	bytes.Buffer
	disabled bool
}

func (b *reviewKeepAliveBuffer) ResponseKeepAlive() bool { return !b.disabled }
func (b *reviewKeepAliveBuffer) DisableResponseReuse()   { b.disabled = true }

func TestReviewDeadlineStreamFraming(t *testing.T) {
	for _, stage := range []string{"generation", "partner_settlement"} {
		for _, hidden := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/hidden=%t", stage, hidden), func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
				defer cancel()
				config := testAdvisorConfig(t)
				config.HidePublicMetadata = hidden
				gateway, _ := newFusionBudgetGateway(t)
				provider := advisorTimeoutLLM(func(ctx context.Context, _ *types.OpenAIChatRequest, _ io.Writer) error {
					<-ctx.Done()
					return ctx.Err()
				})
				if stage == "partner_settlement" {
					config.BillingProfile = parasailLiberty20BillingProfile
					provider = func(ctx context.Context, req *types.OpenAIChatRequest, out io.Writer) error {
						return (&fusionSettlementLLM{}).InvokeStreaming(ctx, req, nil, out)
					}
					gateway = trustedrouter.New("https://trustedrouter.com", "internal", &http.Client{Transport: fusionBudgetTransport(func(r *http.Request) (*http.Response, error) {
						var payload map[string]any
						if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
							return nil, err
						}
						body := `{"data":{"settled":true}}`
						switch r.URL.Path {
						case "/internal/gateway/authorize":
							body = fmt.Sprintf(`{"data":{"authorization_id":"auth","model":%q,"endpoint_id":"test","provider":"test","usage_type":"Credits"}}`, payload["model"])
						case "/internal/gateway/settle":
							if payload["route_type"] == parasailLiberty20TopLevelRoute {
								<-ctx.Done()
								checkAdvisorFinalizationContext(t, r)
								return nil, errors.New("partner settlement unavailable")
							}
						default:
							t.Errorf("unexpected control-plane path: %s", r.URL.Path)
						}
						return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
					})})
				}
				req := &types.OpenAIChatRequest{Model: trustedRouterAdvisorModel, Stream: true, Messages: []types.OpenAIChatMessage{{Role: "user", Content: "hello"}}}
				var out reviewKeepAliveBuffer
				serveAdvisorStreaming(ctx, &out, provider, req, config, gateway, nil, "bearer", nil, "review")
				reader := bufio.NewReader(&out)
				resp, err := http.ReadResponse(reader, nil)
				if err != nil {
					t.Fatal(err)
				}
				defer resp.Body.Close()
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatalf("terminal error has broken HTTP framing: %v; body=%s", err, body)
				}
				if out.disabled || resp.Close || strings.Count(string(body), "data: [DONE]") != 1 || !strings.Contains(string(body), "error") {
					t.Fatalf("incomplete terminal error: disabled=%t close=%t body=%s", out.disabled, resp.Close, body)
				}
				// The next response must parse on the same reader, past the zero chunk.
				writeJSONResponse(&out, http.StatusOK, []byte(`{}`))
				next, err := http.ReadResponse(reader, nil)
				if err != nil {
					t.Fatal(err)
				}
				defer next.Body.Close()
				if _, err := io.ReadAll(next.Body); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}
