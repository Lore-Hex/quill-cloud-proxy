package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

const selectionTestCatalog = `{"data":[{"id":"google/gemini-3.8-flash","trustedrouter":{"supports_chat":true,"prepaid_available":true}}]}`

type selectionStub func(context.Context, string, float64, string) (*llm.ModelSelection, error)

func (s selectionStub) Select(ctx context.Context, messages string, perf float64, sessionID string) (*llm.ModelSelection, error) {
	return s(ctx, messages, perf, sessionID)
}

type selectionGatewayStub struct {
	admitted, settled, refunded   int
	replay                        bool
	authErr, settleErr, refundErr error
	request                       *types.OpenAIChatRequest
	usage                         trustedrouter.Usage
}

func (g *selectionGatewayStub) PublicModels(context.Context) ([]byte, error) {
	return []byte(selectionTestCatalog), nil
}
func (g *selectionGatewayStub) AuthorizeWithRoute(_ context.Context, _ string, req *types.OpenAIChatRequest, route string) (*trustedrouter.Authorization, error) {
	g.admitted++
	g.request = req
	if route != polyphemusSelectRoute {
		return nil, errors.New("wrong route")
	}
	return &trustedrouter.Authorization{Model: polyphemusModel, Provider: "telluvian", UsageType: "Credits", EndpointID: "selection", IdempotentReplay: g.replay}, g.authErr
}
func (g *selectionGatewayStub) Settle(_ context.Context, _ *trustedrouter.Authorization, usage trustedrouter.Usage) (*trustedrouter.SettleResult, error) {
	g.settled++
	g.usage = usage
	return &trustedrouter.SettleResult{CostMicrodollars: 1, GenerationID: "selection-generation"}, g.settleErr
}
func (g *selectionGatewayStub) Refund(context.Context, *trustedrouter.Authorization, int, string, float64, map[string]any) error {
	g.refunded++
	return g.refundErr
}

func selectionTestRequest() *types.OpenAIChatRequest {
	return &types.OpenAIChatRequest{Model: polyphemusModel, Response: &types.ResponseRequestMeta{}, Messages: []types.OpenAIChatMessage{{Role: "user", Content: "PRIVATE TASK"}}, IdempotencyKey: "same-root"}
}

func TestPolyphemusSelectorSessionIsStableOpaqueAndKeyIsolated(t *testing.T) {
	const session = "private conversation / \u65e5\u672c\u8a9e"
	first := polyphemusSelectorSessionID("test-key-one", session)
	// Independently computed HMAC vector pins the namespace, key and UUID bits.
	if first != "2e7dc99b-4abb-8bfd-869b-7192416a0130" {
		t.Fatal("stable session derivation changed")
	}
	guid := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-8[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	if !guid.MatchString(first) || strings.Contains(first, session) || strings.Contains(first, "test-key") {
		t.Fatalf("not an opaque UUIDv8: %q", first)
	}
	if got := polyphemusSelectorSessionID("test-key-one", session); got != first {
		t.Fatal("same conversation changed identity")
	}
	for _, pair := range [][2]string{{"test-key-two", session}, {"test-key-one", session + "2"}} {
		if got := polyphemusSelectorSessionID(pair[0], pair[1]); got == first || !guid.MatchString(got) {
			t.Fatal("different keys or conversations share identity")
		}
	}
	for _, pair := range [][2]string{{"test-key-one", ""}, {"", session}, {"", ""}} {
		if got := polyphemusSelectorSessionID(pair[0], pair[1]); got != "" {
			t.Fatal("missing caller or session created a shared identity")
		}
	}
}

func TestPolyphemusConversationSessionSurvivesNewTurnsAndStageIDs(t *testing.T) {
	const session = "private-conversation-id"
	const bearer = "test-key-one"
	wantSession := polyphemusSelectorSessionID(bearer, session)
	gateway := &selectionGatewayStub{}
	calls := 0
	selector := selectionStub(func(_ context.Context, messages string, _ float64, sessionID string) (*llm.ModelSelection, error) {
		calls++
		if sessionID != wantSession || strings.Contains(messages, session) || strings.Contains(messages, wantSession) {
			t.Fatal("session changed between turns or entered metered context")
		}
		return &llm.ModelSelection{Model: "gemini-3.8-flash", SessionID: "untrusted-echo"}, nil
	})
	for turn := 0; turn < 2; turn++ {
		req := selectionTestRequest()
		req.SessionID = session
		req.IdempotencyKey = fmt.Sprintf("turn-%d", turn)
		req.Messages[0].Content = fmt.Sprintf("Synthetic task turn %d", turn)
		ctx, err := preparePolyphemus(context.Background(), req, gateway, selector, bearer, "test")
		if err != nil {
			t.Fatal(err)
		}
		if req.SessionID != session || gateway.usage.SessionID != session || gateway.request.SessionID != session {
			t.Fatal("changed caller session or ledger attribution")
		}
		usage := map[string]any{"cost_microdollars": 10}
		annotatePolyphemusUsage(ctx, usage)
		metadata := usage["provider_usage"].(map[string]any)
		if metadata["selector_session_supplied"] != true || usage["cost_microdollars"] != 11 {
			t.Fatal("session changed billing or lacks supplied flag")
		}
		encoded, _ := json.Marshal(usage)
		for _, private := range []string{session, wantSession, bearer, "untrusted-echo"} {
			if strings.Contains(string(encoded), private) {
				t.Fatal("session identifier or credential leaked to usage")
			}
		}
	}
	if calls != 2 || gateway.admitted != 2 || gateway.settled != 2 || gateway.refunded != 0 {
		t.Fatal("session changed per-turn billing lifecycle")
	}
}

func TestPolyphemusSelectionUsesSharedBillingAndPreservesRequest(t *testing.T) {
	req := selectionTestRequest()
	req.Messages[0].Content = "PRIVATE TASK \u65e5\u672c\u8a9e"
	req.Tools = []any{map[string]any{"type": "function", "function": map[string]any{"name": "read_file", "description": strings.Repeat("large schema ", 1000)}}}
	gateway := &selectionGatewayStub{}
	calls := 0
	selectorTokens := 0
	selector := selectionStub(func(_ context.Context, messages string, perf float64, sessionID string) (*llm.ModelSelection, error) {
		calls++
		if gateway.admitted != 1 || gateway.settled != 0 {
			t.Fatal("provider called before admission")
		}
		if !strings.Contains(messages, "PRIVATE TASK") || !strings.Contains(messages, "read_file") || perf != .9 {
			t.Fatal("lost selection context")
		}
		if sessionID != "" {
			t.Fatal("one-shot request acquired a session")
		}
		selectorTokens = len(messages) / 4
		out := &llm.ModelSelection{Model: "gemini-3.8-flash"}
		out.Reasoning.Effort = "high"
		return out, nil
	})
	ctx, err := preparePolyphemus(context.Background(), req, gateway, selector, "private-key", "log-1")
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 || gateway.settled != 1 || gateway.refunded != 0 {
		t.Fatalf("calls=%d settled=%d refunds=%d", calls, gateway.settled, gateway.refunded)
	}
	if gateway.usage.InputTokens != selectorTokens || !gateway.usage.UsageEstimated || gateway.usage.OutputTokens != 0 || gateway.usage.RouteType != polyphemusSelectRoute {
		t.Fatal("incorrect or undisclosed selector token estimate")
	}
	if trustedrouter.EstimateInputTokens(gateway.request) < selectorTokens || len(gateway.request.Tools) != 0 {
		t.Fatal("selector admission did not cover serialized tools/context")
	}
	if selectorTokens < 3000 || req.Messages[0].Content != "PRIVATE TASK \u65e5\u672c\u8a9e" {
		t.Fatal("large tool schema was unmetered or generation context changed")
	}
	if req.Model != "google/gemini-3.8-flash" || req.ResponseModel != polyphemusModel || req.ReasoningEffort != "high" || len(req.Tools) != 1 || req.Provider.Usage != "credits" {
		t.Fatalf("bad continuation: %#v", req)
	}
	if req.IdempotencyKey == gateway.request.IdempotencyKey || gateway.request.RequestFingerprint == "" || strings.Contains(gateway.request.RequestFingerprint, "PRIVATE") {
		t.Fatal("bad stage binding")
	}
	receipt := polyphemusReceiptFromContext(ctx)
	if receipt == nil || receipt.CostMicrodollars != 1 {
		t.Fatal("missing fee")
	}
	usage := map[string]any{"cost_microdollars": 37, "input_tokens": 10}
	annotatePolyphemusUsage(ctx, usage)
	if usage["cost_microdollars"] != 38 || usage["input_tokens"] != 10 {
		t.Fatalf("wrong total: %#v", usage)
	}
	meta := usage["provider_usage"].(map[string]any)
	if meta["selector_input_tokens"] != selectorTokens || meta["selector_usage_estimated"] != true || meta["selector_upstream_cost_known"] != false {
		t.Fatal("missing selector metering disclosure", meta)
	}
	encoded, _ := json.Marshal(usage)
	if strings.Contains(string(encoded), "PRIVATE") || strings.Contains(string(encoded), "private-key") {
		t.Fatal("content leak")
	}
}

func TestPolyphemusFailuresNeverGenerateOrDoubleCharge(t *testing.T) {
	for _, stage := range []string{"admission", "replay", "settlement"} {
		t.Run(stage, func(t *testing.T) {
			gateway := &selectionGatewayStub{}
			if stage == "admission" {
				gateway.authErr = errors.New("denied")
			}
			gateway.replay = stage == "replay"
			if stage == "settlement" {
				gateway.settleErr = errors.New("lost response")
			}
			calls := 0
			selector := selectionStub(func(context.Context, string, float64, string) (*llm.ModelSelection, error) {
				calls++
				if stage == "selection" {
					return nil, errors.New("private provider body")
				}
				if stage == "resolution" {
					return &llm.ModelSelection{Model: "trustedrouter/zeus"}, nil
				}
				return &llm.ModelSelection{Model: "gemini-3.8-flash"}, nil
			})
			req := selectionTestRequest()
			ctx, err := preparePolyphemus(context.Background(), req, gateway, selector, "key", "test")
			if err == nil || polyphemusReceiptFromContext(ctx) != nil || req.Model != polyphemusModel {
				t.Fatal("failure continued to generation")
			}
			if (stage == "admission" || stage == "replay") && calls != 0 {
				t.Fatal("unadmitted upstream call")
			}
			if stage == "selection" || stage == "resolution" {
				if gateway.refunded != 1 || gateway.settled != 0 {
					t.Fatal("failure not refunded")
				}
			}
			if stage == "settlement" && (gateway.refunded != 0 || gateway.settled != 1) {
				t.Fatal("ambiguous settlement was refunded/repeated")
			}
		})
	}
}

func TestPolyphemusSelectorFailuresFallBackToAutoWithoutFee(t *testing.T) {
	for _, stage := range []string{"timeout", "failure", "nil", "unknown_model", "missing_selector", "refund_failure", "cancelled"} {
		t.Run(stage, func(t *testing.T) {
			gateway := &selectionGatewayStub{}
			if stage == "refund_failure" {
				gateway.refundErr = errors.New("unavailable")
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var selector modelSelector = selectionStub(func(context.Context, string, float64, string) (*llm.ModelSelection, error) {
				switch stage {
				case "timeout":
					return nil, context.DeadlineExceeded
				case "nil":
					return nil, nil
				case "unknown_model":
					return &llm.ModelSelection{Model: "trustedrouter/zeus"}, nil
				case "cancelled":
					cancel()
				}
				return nil, errors.New("PRIVATE PROVIDER ERROR")
			})
			if stage == "missing_selector" {
				selector = nil
			}
			req := selectionTestRequest()
			req.ReasoningEffort = "low"
			req.Tools = []any{map[string]any{"type": "function"}}
			outCtx, err := preparePolyphemus(ctx, req, gateway, selector, "key", "test")
			if gateway.admitted != 1 || gateway.refunded != 1 || gateway.settled != 0 {
				t.Fatal("wrong billing sequence", gateway)
			}
			if stage == "refund_failure" || stage == "cancelled" {
				if err == nil || req.Model != polyphemusModel {
					t.Fatal("continued on unsafe failure")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if req.Model != "trustedrouter/auto" || req.ResponseModel != polyphemusModel || req.ReasoningEffort != "low" || len(req.Tools) != 1 {
				t.Fatal("lost fallback request")
			}
			if req.IdempotencyKey == gateway.request.IdempotencyKey || req.RequestFingerprint == "" {
				t.Fatal("missing independent generation admission")
			}
			usage := map[string]any{"cost_microdollars": 37}
			annotatePolyphemusUsage(outCtx, usage)
			meta := usage["provider_usage"].(map[string]any)
			if usage["cost_microdollars"] != 37 || meta["selector_cost_microdollars"] != 0 || meta["selector_fallback_model"] != "trustedrouter/auto" {
				t.Fatal("charged failed selection", usage)
			}
			if meta["selector_input_tokens"] != 0 || meta["selector_usage_estimated"] != true {
				t.Fatal("billed tokens on selector failure", meta)
			}
			encoded, _ := json.Marshal(meta)
			if strings.Contains(string(encoded), "PRIVATE") {
				t.Fatal("provider error leaked")
			}
		})
	}
}

func TestPolyphemusRejectsPrivacyAndByokBeforeAdmission(t *testing.T) {
	yes := true
	for _, provider := range []*types.ProviderRouting{
		{MinPrivacy: "zdr"}, {MinPrivacy: "no-store"}, {MinPrivacy: "confidential"}, {MinPrivacy: "e2e"}, {ZDR: &yes}, {DataCollection: "deny"}, {Usage: "byok"}, {Billing: "BYOK"},
	} {
		req := selectionTestRequest()
		req.Provider = provider
		gateway := &selectionGatewayStub{}
		_, err := preparePolyphemus(context.Background(), req, gateway, selectionStub(func(context.Context, string, float64, string) (*llm.ModelSelection, error) {
			t.Fatal("private context sent")
			return nil, nil
		}), "key", "test")
		if err == nil || gateway.admitted != 0 {
			t.Fatalf("privacy accepted: %#v", provider)
		}
	}
}

func TestPolyphemusResolvesOnlyUniqueConcreteModels(t *testing.T) {
	for _, name := range []string{"gemini-3.8-flash", "google/gemini-3.8-flash"} {
		model, err := resolveSelectedModel([]byte(selectionTestCatalog), name)
		if err != nil || model != "google/gemini-3.8-flash" {
			t.Fatal(model, err)
		}
	}
	for _, name := range []string{"Gemini-3.8-flash", "trustedrouter/auto", "https://evil.test/model", "missing", "../gemini-3.8-flash"} {
		if _, err := resolveSelectedModel([]byte(selectionTestCatalog), name); err == nil {
			t.Fatal("accepted", name)
		}
	}
	ambiguous := strings.Replace(selectionTestCatalog, `]}`, `,{"id":"other/gemini-3.8-flash","trustedrouter":{"supports_chat":true,"prepaid_available":true}}]}`, 1)
	if _, err := resolveSelectedModel([]byte(ambiguous), "gemini-3.8-flash"); err == nil {
		t.Fatal("ambiguous suffix accepted")
	}
	chatOnly := strings.Replace(selectionTestCatalog, `"supports_chat":true`, `"supports_chat":true,"supports_responses":false`, 1)
	if _, err := resolveSelectedModel([]byte(chatOnly), "gemini-3.8-flash"); err == nil {
		t.Fatal("explicitly unsupported Responses target accepted")
	}
}

func TestPolyphemusRejectsWrongRouteAndImage(t *testing.T) {
	req := selectionTestRequest()
	if validatePolyphemus(req, "chat.completions") == nil {
		t.Fatal("chat accepted")
	}
	req.Messages[0].Content = []any{map[string]any{"type": "image_url", "image_url": map[string]any{"url": "https://private.test/image"}}}
	if validatePolyphemus(req, "responses") == nil {
		t.Fatal("image accepted")
	}
}
