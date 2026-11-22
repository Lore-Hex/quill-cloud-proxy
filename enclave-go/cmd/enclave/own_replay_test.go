package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/speech"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/webfetch"
)

// An authorize can commit at the control plane and lose its response. The
// client retries the same request and gets the stored authorization back with
// idempotent_replay set and its own invocation nonce. That is this request's
// own hold. The handlers below used to answer it with a 409 and no terminal,
// which left the hold open with nothing run. They serve it now.
//
// The other replay, an authorization that belongs to an earlier request, is
// still refused: no provider call, no settle and no refund of a hold that is
// not this request's.

// replayControlPlane answers authorize in one of two ways.
//
//   - own: the first attempt commits and its response is lost (502); the retry
//     gets the same authorization back, replayed, with the nonce it sent.
//   - foreign: the key was used by an earlier request; the stored
//     authorization comes back replayed with that request's nonce.
type replayControlPlane struct {
	mu            sync.Mutex
	foreign       bool
	authorization map[string]any
	storedNonce   string
	authorizes    int
	settles       int
	refunds       int
}

func (p *replayControlPlane) gateway(t *testing.T) *trustedrouter.Client {
	t.Helper()
	return trustedrouter.New("https://trustedrouter.com", "internal-token", &http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			raw, err := io.ReadAll(r.Body)
			if err != nil {
				return nil, err
			}
			var body map[string]any
			_ = json.Unmarshal(raw, &body)
			respond := func(status int, payload string) (*http.Response, error) {
				return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(payload)), Request: r}, nil
			}
			p.mu.Lock()
			defer p.mu.Unlock()
			switch r.URL.Path {
			case "/internal/gateway/validate":
				return respond(200, `{"data":{"workspace_id":"ws_1","api_key_hash":"key_1"}}`)
			case "/internal/gateway/authorize":
				p.authorizes++
				nonce, _ := body["invocation_nonce"].(string)
				data := map[string]any{"idempotent_replay": true}
				for key, value := range p.authorization {
					data[key] = value
				}
				if p.foreign {
					data["invocation_nonce"] = "0123456789abcdef0123456789abcdef"
				} else {
					if p.authorizes == 1 {
						// Committed, and the response never arrives.
						p.storedNonce = nonce
						return respond(502, `{"error":{"message":"bad gateway","type":"server_error"}}`)
					}
					data["invocation_nonce"] = p.storedNonce
				}
				encoded, _ := json.Marshal(map[string]any{"data": data})
				return respond(200, string(encoded))
			case "/internal/gateway/settle":
				p.settles++
				return respond(200, `{"data":{"generation_id":"gen_1","cost_microdollars":100,"cost":0.0001,"settled":true}}`)
			case "/internal/gateway/refund":
				p.refunds++
				return respond(200, `{"data":{"refunded":true}}`)
			}
			t.Errorf("unexpected control-plane path %s", r.URL.Path)
			return respond(500, `{}`)
		}),
	})
}

func (p *replayControlPlane) counts() (authorizes, settles, refunds int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.authorizes, p.settles, p.refunds
}

func TestOwnAuthorizeReplayIsServedAndAnotherRequestsIsRefused(t *testing.T) {
	const speechModel = "x-ai/grok-voice-tts-1.0"
	speechSpec := speech.Models[speechModel]
	handlers := []struct {
		name          string
		authorization map[string]any
		// serve runs the handler and reports how many times the provider ran.
		serve func(t *testing.T, gateway *trustedrouter.Client, out *bytes.Buffer) int
	}{
		{
			name: "speech",
			authorization: map[string]any{
				"authorization_id": "auth_speech", "model": speechModel, "provider": speechSpec.Provider,
				"upstream_model": speechSpec.Upstream, "usage_type": "Credits",
				"endpoint_id": speechModel + "@" + speechSpec.Provider + "/prepaid", "additional_cost_reservation_microdollars": 100,
			},
			serve: func(t *testing.T, gateway *trustedrouter.Client, out *bytes.Buffer) int {
				generator := &fakeSpeech{}
				old := speechProviderGateway
				speechProviderGateway = generator
				t.Cleanup(func() { speechProviderGateway = old })
				request, _ := json.Marshal(map[string]any{"model": speechModel, "input": "hello", "voice": speechSpec.Voices[0], "response_format": speechSpec.Formats[0]})
				serveSpeech(context.Background(), out, request, gateway, "tr-test-key", "speech-replay", requestAttributionHeaders{}, "rlog_speech")
				return generator.called
			},
		},
		{
			name: "transcription",
			authorization: map[string]any{
				"authorization_id": "auth_audio", "model": "openai/whisper-1", "provider": "openai", "upstream_model": "whisper-1",
				"usage_type": "Credits", "endpoint_id": "openai/whisper-1@openai/prepaid", "additional_cost_reservation_microdollars": 100,
			},
			serve: func(t *testing.T, gateway *trustedrouter.Client, out *bytes.Buffer) int {
				provider := &fakeTranscription{}
				old := transcriptionProviderGateway
				transcriptionProviderGateway = provider
				t.Cleanup(func() { transcriptionProviderGateway = old })
				serveTranscription(context.Background(), out, transcriptionBody("openai/whisper-1", nil), gateway, "test-key", "transcription-replay", requestAttributionHeaders{ContentType: "application/json"}, "rlog_audio")
				return provider.calls
			},
		},
		{
			name: "web fetch",
			authorization: map[string]any{
				"authorization_id": "auth_fetch", "model": webfetch.ModelID, "provider": "deepseek", "upstream_model": "fetch",
				"usage_type": "Credits", "endpoint_id": "deepseek/fetch@deepseek/prepaid", "estimated_cost_microdollars": 792,
			},
			serve: func(t *testing.T, gateway *trustedrouter.Client, out *bytes.Buffer) int {
				fetcher := &fakeFetch{scenario: "success"}
				old := webFetchProviderGateway
				webFetchProviderGateway = fetcher
				t.Cleanup(func() { webFetchProviderGateway = old })
				serveWebFetch(context.Background(), out, []byte(`{"url":"https://example.com/"}`), gateway, "tr-test-key", "fetch-replay", requestAttributionHeaders{}, "rlog_fetch")
				return fetcher.calls
			},
		},
	}
	for _, handler := range handlers {
		t.Run(handler.name+"/own retry", func(t *testing.T) {
			plane := &replayControlPlane{authorization: handler.authorization}
			var out bytes.Buffer
			providerCalls := handler.serve(t, plane.gateway(t), &out)
			if !strings.HasPrefix(out.String(), "HTTP/1.1 200 ") {
				t.Fatalf("response: %.200s", out.String())
			}
			authorizes, settles, refunds := plane.counts()
			if authorizes != 2 || providerCalls != 1 || settles != 1 || refunds != 0 {
				t.Fatalf("authorize=%d provider=%d settle=%d refund=%d, want the retried authorize served once and settled once", authorizes, providerCalls, settles, refunds)
			}
		})
		t.Run(handler.name+"/another request", func(t *testing.T) {
			plane := &replayControlPlane{authorization: handler.authorization, foreign: true}
			var out bytes.Buffer
			providerCalls := handler.serve(t, plane.gateway(t), &out)
			if !strings.HasPrefix(out.String(), "HTTP/1.1 409 ") {
				t.Fatalf("response: %.200s", out.String())
			}
			authorizes, settles, refunds := plane.counts()
			if authorizes != 1 || providerCalls != 0 || settles != 0 || refunds != 0 {
				t.Fatalf("authorize=%d provider=%d settle=%d refund=%d, want nothing run and the other request's hold untouched", authorizes, providerCalls, settles, refunds)
			}
		})
	}
}

// ownReplaySelectionGateway hands Polyphemus an authorization the real client
// returned, marked as replayed: the selection admission committed and came
// back to this request's own retry.
type ownReplaySelectionGateway struct {
	selectionGatewayStub
	authorization *trustedrouter.Authorization
}

func (g *ownReplaySelectionGateway) AuthorizeWithRoute(_ context.Context, _ string, req *types.OpenAIChatRequest, _ string) (*trustedrouter.Authorization, error) {
	g.admitted++
	g.request = req
	return g.authorization, nil
}

func TestPolyphemusServesItsOwnReplayedAdmission(t *testing.T) {
	// A tracked authorization: one an authorize call on the real client returned.
	plane := &replayControlPlane{authorization: map[string]any{
		"authorization_id": "auth_select", "model": polyphemusModel, "provider": "telluvian",
		"usage_type": "Credits", "endpoint_id": "selection",
	}}
	authorization, err := plane.gateway(t).AuthorizeWithRoute(context.Background(), "key",
		&types.OpenAIChatRequest{Model: polyphemusModel, Messages: []types.OpenAIChatMessage{{Role: "user", Content: "hi"}}}, polyphemusSelectRoute)
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if !authorization.IdempotentReplay || !authorization.OwnReplay() {
		t.Fatalf("replay=%t own=%t, want the client's own replayed authorization", authorization.IdempotentReplay, authorization.OwnReplay())
	}

	gateway := &ownReplaySelectionGateway{authorization: authorization}
	calls := 0
	selector := selectionStub(func(context.Context, string, llm.SelectionControls, string) (*llm.ModelSelection, error) {
		calls++
		return &llm.ModelSelection{Model: "gemini-3.8-flash"}, nil
	})
	req := selectionTestRequest()
	ctx, err := preparePolyphemus(context.Background(), req, gateway, selector, "key", "test")
	if err != nil {
		t.Fatalf("preparePolyphemus: %v", err)
	}
	if polyphemusReceiptFromContext(ctx) == nil || calls != 1 || gateway.settled != 1 || gateway.refunded != 0 {
		t.Fatalf("selector calls=%d settled=%d refunded=%d receipt=%v, want the selection run and settled once",
			calls, gateway.settled, gateway.refunded, polyphemusReceiptFromContext(ctx) != nil)
	}

	// An authorization that is replayed but not this request's own (here, one no
	// authorize call returned) is still refused, with nothing run or refunded.
	foreign := &ownReplaySelectionGateway{authorization: &trustedrouter.Authorization{
		Model: polyphemusModel, Provider: "telluvian", UsageType: "Credits", EndpointID: "selection", IdempotentReplay: true,
	}}
	calls = 0
	if _, err := preparePolyphemus(context.Background(), selectionTestRequest(), foreign, selector, "key", "test"); err == nil {
		t.Fatal("another request's replayed admission was served")
	}
	if calls != 0 || foreign.settled != 0 || foreign.refunded != 0 {
		t.Fatalf("selector calls=%d settled=%d refunded=%d, want nothing run", calls, foreign.settled, foreign.refunded)
	}
}

// What the handlers rely on: the real client never returns another
// invocation's replayed authorization. It answers with a 409 instead, so a
// replayed authorization a handler holds is always its own.
func TestClientNeverReturnsAnotherInvocationsReplay(t *testing.T) {
	plane := &replayControlPlane{foreign: true, authorization: map[string]any{
		"authorization_id": "auth_other", "model": "openai/gpt-4o-mini", "provider": "openai",
		"usage_type": "Credits", "endpoint_id": "e@openai/prepaid",
	}}
	authorization, err := plane.gateway(t).AuthorizeWithRoute(context.Background(), "key",
		&types.OpenAIChatRequest{Model: "openai/gpt-4o-mini", IdempotencyKey: "reused-key", Messages: []types.OpenAIChatMessage{{Role: "user", Content: "hi"}}}, "chat.completions")
	if authorization != nil || err == nil {
		t.Fatalf("authorization=%v err=%v, want a refusal and no authorization", authorization, err)
	}
	if status := statusFromControlPlaneError(err); status != 409 {
		t.Fatalf("status = %d (%v), want 409", status, err)
	}
	if _, _, refunds := plane.counts(); refunds != 0 {
		t.Fatalf("refunds = %d, want the other request's hold untouched", refunds)
	}
}
