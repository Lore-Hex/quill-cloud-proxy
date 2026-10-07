package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/billingv1"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/receipt"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

type asyncOutput struct {
	mu   sync.Mutex
	body bytes.Buffer
}

func (w *asyncOutput) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.body.Write(p)
}
func (w *asyncOutput) String() string { w.mu.Lock(); defer w.mu.Unlock(); return w.body.String() }

type asyncCleanupProvider struct{ release, stopped chan struct{} }

func (p *asyncCleanupProvider) InvokeStreaming(ctx context.Context, req *types.OpenAIChatRequest, native *types.AnthropicMessagesRequest, out io.Writer, options ...llm.InvokeOptions) error {
	if err := (&fakeStreamingLLM{}).InvokeStreaming(ctx, req, native, out, options...); err != nil {
		return err
	}
	<-ctx.Done()
	<-p.release
	close(p.stopped)
	return nil
}

func TestAsyncStreamFinalFrameJoinAndPendingMetadata(t *testing.T) {
	t.Setenv("QUILL_USAGE_HEARTBEAT", "off")
	t.Setenv("TR_ASYNC_SETTLE_NEGOTIATE", "on")
	public := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32)).Public().(ed25519.PublicKey)
	t.Setenv("TR_ASYNC_SETTLE_TICKET_PUBLIC_KEYS", `{"test":"router-fixture~`+base64.RawURLEncoding.EncodeToString(public)+`"}`)
	for _, scenario := range []string{"chat.completions", "responses", "chat.completions-stage-d", "responses-stage-d", "chat.completions-cleanup-timeout", "responses-cleanup-timeout", "chat.completions-stage-d-cleanup-timeout", "responses-stage-d-cleanup-timeout", "chat.completions-cancelled", "responses-cancelled", "responses-stage-d-cancelled"} {
		t.Run(scenario, func(t *testing.T) {
			slow := strings.HasSuffix(scenario, "-cleanup-timeout")
			cancelled := strings.HasSuffix(scenario, "-cancelled")
			route := strings.TrimSuffix(strings.TrimSuffix(scenario, "-cleanup-timeout"), "-cancelled")
			stageD := strings.HasSuffix(route, "-stage-d")
			route = strings.TrimSuffix(route, "-stage-d")
			t.Setenv("QUILL_TERMINATE_AT_CAP", "off")
			if stageD {
				t.Setenv("QUILL_USAGE_HEARTBEAT", "on")
			}
			raw, err := os.ReadFile("../../internal/trustedrouter/testdata/async_settlement/authorize_v1_builder.json")
			if err != nil {
				t.Fatal(err)
			}
			var f struct {
				Claims   map[string]any `json:"claims"`
				Response struct {
					Data map[string]any `json:"data"`
				} `json:"response"`
			}
			if err := json.Unmarshal(raw, &f); err != nil {
				t.Fatal(err)
			}
			f.Claims["streamed"], f.Claims["route_type"] = true, route
			f.Claims["iat"], f.Claims["exp"] = time.Now().Unix()-1, time.Now().Unix()+299
			claims, _ := json.Marshal(f.Claims)
			header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","kid":"test","typ":"tr-async-settle-v1"}`))
			signed := header + "." + base64.RawURLEncoding.EncodeToString(claims)
			signature := ed25519.Sign(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32)), []byte(signed))
			f.Response.Data["settlement_ticket"] = signed + "." + base64.RawURLEncoding.EncodeToString(signature)
			for k, v := range map[string]any{"credit_reservation_id": "res-v1", "workspace_id": "ws-v1", "api_key_hash": "key-v1", "invocation_nonce": "nonce-v1", "usage_type": "Credits", "model": "openai/billing-v1", "provider": "openai", "endpoint_id": "openai/billing-v1@openai/prepaid"} {
				f.Response.Data[k] = v
			}
			if stageD {
				f.Response.Data["stage_d"] = map[string]any{"eligible": true}
			}
			provider := &asyncCleanupProvider{make(chan struct{}), make(chan struct{})}
			var release sync.Once
			defer release.Do(func() { close(provider.release) })
			var out asyncOutput
			settled := make(chan struct{}, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/internal/gateway/authorize" {
					_ = json.NewEncoder(w).Encode(f.Response)
					return
				}
				if strings.HasSuffix(r.URL.Path, "/heartbeat") {
					_, _ = io.WriteString(w, `{"accepted":true,"seq":1,"expires_at_ms":1999999999999,"cap_micro":1000000,"running_micro":0}`)
					return
				}
				if r.URL.Path != "/internal/gateway/settle" {
					t.Errorf("unexpected %s", r.URL.Path)
					w.WriteHeader(500)
					return
				}
				select {
				case <-provider.stopped:
				default:
					if !slow && !cancelled {
						t.Error("settle before provider completion")
					}
				}
				before := out.String()
				needle := `"finish_reason":"stop"`
				if route == "responses" {
					needle = "response.output_item.done"
				}
				if !strings.Contains(before, needle) || strings.Contains(before, "[DONE]") {
					t.Errorf("settle order: %s", before)
				}
				if r.Header.Get("X-TR-Settlement-Mode") != "async-v1" {
					t.Error("missing async header")
				}
				var body struct {
					Terminal billingv1.TerminalEnvelope `json:"terminal"`
				}
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Error(err)
				}
				hash, err := billingv1.CanonicalHash(body.Terminal)
				if err != nil {
					t.Error(err)
				}
				w.WriteHeader(202)
				_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"acceptance": map[string]any{"status": "accepted", "payload_hash": hash, "settlement_status": "pending"}, "trusted_router_settlement": map[string]any{"v": 1, "settlement_id": "auth-v1.settle", "settlement_status": "pending", "cost_microdollars": body.Terminal.ChargeMicro, "status_url": "/v1/settlements/auth-v1.settle", "poll_after_ms": 1000}}})
				settled <- struct{}{}
			}))
			defer server.Close()
			t.Setenv("TR_CONTROL_PLANE_BASE_URL", server.URL)
			t.Setenv("TR_INTERNAL_GATEWAY_TOKEN", "test")
			gateway := trustedrouter.New(server.URL, "test", server.Client())
			if stageD {
				signer, err := receipt.NewSigner()
				if err != nil {
					t.Fatal(err)
				}
				gateway.ConfigureStageDBoot(signer)
			}
			req := &types.OpenAIChatRequest{Model: "openai/billing-v1", Stream: true, IdempotencyKey: "stream-test", StreamOptions: &types.ChatStreamOptions{IncludeUsage: true}}
			auth, err := gateway.AuthorizeWithRoute(t.Context(), "key", req, route)
			if err != nil {
				t.Fatal(err)
			}
			if !gateway.AsyncSettlementNegotiated(auth) {
				t.Fatal("not negotiated")
			}
			done := make(chan struct{})
			streamCtx, cancelStream := context.WithCancel(t.Context())
			defer cancelStream()
			go func() {
				defer close(done)
				serveStreaming(streamCtx, &out, provider, req, &types.AnthropicMessagesRequest{}, []llm.InvokeOptions{{Model: auth.Model, Provider: auth.Provider, EndpointID: auth.EndpointID}}, gateway, auth, nil, time.Now(), nil, route, "async-stream", auth.Model)
			}()
			needle := `"finish_reason":"stop"`
			if route == "responses" {
				needle = "response.output_item.done"
			}
			deadline := time.After(3 * time.Second)
			for !strings.Contains(out.String(), needle) {
				select {
				case <-deadline:
					t.Fatalf("final frame delayed: %s", out.String())
				case <-time.After(time.Millisecond):
				}
			}
			select {
			case <-settled:
				t.Fatal("settled before provider joined")
			default:
			}
			if cancelled {
				cancelStream()
			}
			if slow || cancelled {
				go func() { time.Sleep(6 * time.Second); release.Do(func() { close(provider.release) }) }()
			} else {
				release.Do(func() { close(provider.release) })
			}
			select {
			case <-done:
			case <-time.After(9 * time.Second):
				t.Fatal("stream did not finish")
			}
			select {
			case <-settled:
			default:
				t.Error("settlement was not attempted")
			}
			text := out.String()
			if strings.Contains(text, "response.failed") {
				t.Fatal("delivered output failed")
			}
			if route == "chat.completions" {
				for _, line := range strings.Split(text, "\n") {
					if !strings.HasPrefix(line, "data: ") || !strings.Contains(line, `"trusted_router_settlement"`) {
						continue
					}
					var chunk map[string]any
					if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &chunk); err != nil {
						t.Fatal(err)
					}
					fields, ok := chunk["usage"].(map[string]any)
					if !ok || fields["prompt_tokens"] != float64(2) || fields["completion_tokens"] != float64(2) || fields["total_tokens"] != float64(4) || chunk["created"] == nil || chunk["object"] != "chat.completion.chunk" {
						t.Fatalf("invalid final metadata chunk: %v", chunk)
					}
				}
			}
			pending := strings.Index(text, `"trusted_router_settlement"`)
			end := strings.Index(text, "[DONE]")
			if route == "responses" {
				completed := strings.Index(text, "event: response.completed")
				if pending < 0 || completed < pending || end < completed {
					t.Fatalf("metadata must precede completion: %s", text)
				}
			}
			if pending < 0 || end < pending || strings.Index(text, needle) > pending {
				t.Fatalf("metadata ordering: %s", text)
			}
		})
	}
}

func TestAsyncPendingResponseMetadata(t *testing.T) {
	pending := &trustedrouter.PendingSettlement{V: 1, SettlementID: "auth.settle", SettlementStatus: "pending", CostMicrodollars: 2, StatusURL: "/v1/settlements/auth.settle", PollAfterMS: 1000}
	result := &trustedrouter.SettleResult{TrustedRouterSettlement: pending, CostMicrodollars: 2, CostMicrodollarsKnown: true}
	body, err := annotateSettledResponseMetadata([]byte(`{"usage":{"prompt_tokens":1,"completion_tokens":1}}`), nil, result, nil, nil, adapter.StreamResult{}, false)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["trusted_router_settlement"] == nil {
		t.Fatal(string(body))
	}
	usage := decoded["usage"].(map[string]any)
	if usage["cost_microdollars"] != float64(2) {
		t.Fatal(fmt.Sprint(usage))
	}
	if result.Settled || result.GenerationID != "" {
		t.Fatal("pending masquerades as booked")
	}
}

func TestAsyncFailureTerminalOrder(t *testing.T) {
	for _, route := range []string{"responses", "chat.completions"} {
		for _, outcome := range []string{"settled", "refunded", "pending", "none"} {
			t.Run(route+"/"+outcome, func(t *testing.T) {
				var out bytes.Buffer
				var settlement *trustedrouter.SettleResult
				if outcome != "none" {
					settlement = &trustedrouter.SettleResult{CostMicrodollars: 2, CostMicrodollarsKnown: true, FinalizationOutcome: outcome}
				}
				if outcome == "pending" {
					settlement.TrustedRouterSettlement = &trustedrouter.PendingSettlement{V: 1, SettlementStatus: "pending"}
				}
				if err := writeStreamingProviderErrorWithSettlement(&out, route, "id", "model", fmt.Errorf("provider failure"), false, settlement); err != nil {
					t.Fatal(err)
				}
				wire := out.String()
				terminal := `"finish_reason":"error"`
				metadata := `"usage"`
				if route == "responses" {
					terminal = "event: response.failed"
					metadata = "event: trusted_router.settlement"
				}
				end := strings.Index(wire, terminal)
				meta := strings.Index(wire, metadata)
				if end < 0 || strings.Count(wire, "data: [DONE]") != 1 || !strings.HasSuffix(wire, "data: [DONE]\n\n") {
					t.Fatalf("terminal: %s", wire)
				}
				if outcome != "none" && (meta < 0 || meta > end) {
					t.Fatalf("metadata after failure: %s", wire)
				}
				if outcome == "none" && meta >= 0 {
					t.Fatalf("invented settlement: %s", wire)
				}
			})
		}
	}
}

func TestAsyncResponsesOtherFailureTerminals(t *testing.T) {
	for _, path := range []string{"custom_model", "hosted_search"} {
		t.Run(path, func(t *testing.T) {
			var out bytes.Buffer
			var err error
			if path == "custom_model" {
				err = writeUserModelStreamingError(&out, "responses", "id", "model", &userModelDispatchError{callerStatus: 502, message: "failed", refundType: "provider_error"})
			} else {
				emitter := newResponsesWebSearchEmitter(&out, "id", "model", &types.OpenAIChatRequest{})
				err = emitter.Fail(fmt.Errorf("failed"))
			}
			if err != nil {
				t.Fatal(err)
			}
			wire := out.String()
			if path == "custom_model" {
				// Legacy custom-model failures end on response.failed without a
				// [DONE] sentinel. This PR leaves that flag-off path byte-identical;
				// the missing sentinel is tracked as a separate follow-up.
				if strings.Count(wire, "event: response.failed\n") != 1 || strings.Contains(wire, "[DONE]") || !strings.HasSuffix(wire, "\n\n") {
					t.Fatalf("legacy failure terminator changed: %s", wire)
				}
			} else if strings.Count(wire, "event: response.failed\n") != 1 || strings.Count(wire, "data: [DONE]") != 1 || !strings.HasSuffix(wire, "data: [DONE]\n\n") {
				t.Fatalf("failure terminator: %s", wire)
			}
			if strings.Contains(wire, "trusted_router.settlement") {
				t.Fatalf("invented async outcome: %s", wire)
			}
		})
	}
}
