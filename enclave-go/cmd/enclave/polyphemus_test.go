package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/polyclass"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

// Privacy tiers as published on /v1/models today.
const selectionTestCatalog = `{"data":[` +
	`{"id":"google/gemini-3.8-flash","trustedrouter":{"supports_chat":true,"prepaid_available":true}},` +
	`{"id":"anthropic/claude-opus-5.5","trustedrouter":{"supports_chat":true,"prepaid_available":true,"privacy_tier":2}},` +
	`{"id":"deepseek/deepseek-v4.1-flash-1017","trustedrouter":{"supports_chat":true,"prepaid_available":true,"privacy_tier":4}},` +
	`{"id":"moonshotai/kimi-k3.1-pro","trustedrouter":{"supports_chat":true,"prepaid_available":true,"privacy_tier":4}}]}`

type classifierStub func(context.Context, string) (polyclass.Result, error)

func (s classifierStub) Classify(ctx context.Context, text string) (polyclass.Result, error) {
	return s(ctx, text)
}

func returns(task string, domain float64) classifierStub {
	return func(context.Context, string) (polyclass.Result, error) {
		return polyclass.Result{Task: task, DomainKnowledge: domain, Tokens: 5}, nil
	}
}

type selectionGatewayStub struct {
	admitted, settled, refunded   int
	replay                        bool
	provider                      string // defaults to "trustedrouter"
	authErr, settleErr, refundErr error
	request                       *types.OpenAIChatRequest
	usage                         trustedrouter.Usage
	catalog                       string // overrides selectionTestCatalog
}

func (g *selectionGatewayStub) PublicModels(context.Context) ([]byte, error) {
	if g.catalog != "" {
		return []byte(g.catalog), nil
	}
	return []byte(selectionTestCatalog), nil
}
func (g *selectionGatewayStub) AuthorizeWithRoute(_ context.Context, _ string, req *types.OpenAIChatRequest, route string) (*trustedrouter.Authorization, error) {
	g.admitted++
	g.request = req
	if route != polyphemusSelectRoute {
		return nil, errors.New("wrong route")
	}
	provider := g.provider
	if provider == "" {
		provider = "trustedrouter"
	}
	return &trustedrouter.Authorization{Model: polyphemusModel, Provider: provider, UsageType: "Credits", EndpointID: "selection", IdempotentReplay: g.replay}, g.authErr
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

func TestPolyphemusRoutingRule(t *testing.T) {
	for _, tc := range []struct {
		task                string
		domain              float64
		tools, confidential bool
		model, tier         string
	}{
		{"Open QA", 0.37, false, false, polyphemusCheapModel, "cheap"},
		{"Summarization", 0.27, false, false, polyphemusCheapModel, "cheap"},
		{"Text Generation", 0.79, false, false, polyphemusCheapModel, "cheap"},
		{"Text Generation", 0.80, false, false, polyphemusStrongModel, "strong"},
		{"Open QA", 0.98, false, false, polyphemusStrongModel, "strong"},
		{"Code Generation", 0.10, false, false, polyphemusStrongModel, "strong"},
		{"Chatbot", 0.30, true, false, polyphemusStrongModel, "strong"},
		{"Open QA", 0.37, false, true, polyphemusConfidentialCheapModel, "cheap"},
		{"Code Generation", 0.99, false, true, polyphemusConfidentialStrongModel, "strong"},
		{"Chatbot", 0.30, true, true, polyphemusConfidentialStrongModel, "strong"},
	} {
		model, tier := choosePolyphemusModel(polyclass.Result{Task: tc.task, DomainKnowledge: tc.domain}, tc.tools, tc.confidential)
		if model != tc.model || tier != tc.tier {
			t.Errorf("%+v: got %s/%s", tc, model, tier)
		}
	}
	if polyphemusStrongModel != "anthropic/claude-opus-5.5" || polyphemusCheapModel != "deepseek/deepseek-v4.1-flash-1017" ||
		polyphemusConfidentialStrongModel != "moonshotai/kimi-k3.1-pro" || polyphemusConfidentialCheapModel != "deepseek/deepseek-v4.1-flash-1017" {
		t.Fatal("model pair changed; update the catalog description and docs with it")
	}
}

func TestPolyphemusClassifiesTheFirstUserTextSoConversationsStick(t *testing.T) {
	messages := []types.OpenAIChatMessage{
		{Role: "system", Content: "SYSTEM PROMPT"},
		{Role: "user", Content: []any{map[string]any{"type": "text", "text": "part one"}, map[string]any{"type": "text", "text": "part two"}}},
		{Role: "assistant", Content: "answer"},
		{Role: "user", Content: "later question"},
		{Role: "tool", ToolCallID: "x", Content: "TOOL OUTPUT"},
	}
	if got := polyphemusSelectionText(messages); got != "part one\npart two" {
		t.Fatalf("got %q", got)
	}
	// Every later turn of the same conversation classifies the same text.
	for turn := 2; turn <= len(messages); turn++ {
		if got := polyphemusSelectionText(messages[:turn]); got != "part one\npart two" {
			t.Fatalf("turn %d classified %q", turn, got)
		}
	}
	if got := polyphemusSelectionText(messages[:1]); got != "" {
		t.Fatalf("system-only conversation selected %q", got)
	}
	blank := []types.OpenAIChatMessage{{Role: "user", Content: "   "}, {Role: "user", Content: "real"}}
	if got := polyphemusSelectionText(blank); got != "real" {
		t.Fatalf("blank first turn: got %q", got)
	}
	// Text past the classifier's cut does not count: that turn is blank to it.
	padded := []types.OpenAIChatMessage{{Role: "user", Content: strings.Repeat(" ", polyclass.MaxTextBytes) + "late"}, {Role: "user", Content: "real"}}
	if got := polyphemusSelectionText(padded); got != "real" {
		t.Fatalf("blank after truncation: got %q", got)
	}
}

func TestPolyphemusEveryTurnOfAConversationGetsTheSameModel(t *testing.T) {
	// A conversation that opens with a coding task stays on the strong model
	// even when a later turn is small talk, and vice versa.
	classify := classifierStub(func(_ context.Context, text string) (polyclass.Result, error) {
		if strings.Contains(text, "Rust") {
			return polyclass.Result{Task: "Code Generation", DomainKnowledge: 0.99}, nil
		}
		return polyclass.Result{Task: "Chatbot", DomainKnowledge: 0.3}, nil
	})
	for opening, want := range map[string]string{"Write a Rust parser": polyphemusStrongModel, "hi there": polyphemusCheapModel} {
		history := []types.OpenAIChatMessage{{Role: "user", Content: opening}}
		for turn, next := range []string{"thanks!", "now explain Rust lifetimes", "ok"} {
			req := selectionTestRequest()
			req.Messages = append([]types.OpenAIChatMessage{}, history...)
			if _, err := preparePolyphemus(context.Background(), req, &selectionGatewayStub{}, classify, "key", "test"); err != nil {
				t.Fatal(err)
			}
			if req.Model != want {
				t.Fatalf("%q turn %d went to %s, want %s", opening, turn, req.Model, want)
			}
			history = append(history, types.OpenAIChatMessage{Role: "assistant", Content: "reply"}, types.OpenAIChatMessage{Role: "user", Content: next})
		}
	}
}

func TestPolyphemusRequiredTierUsesTheControlPlanesNames(t *testing.T) {
	yes, no := true, false
	for _, tc := range []struct {
		provider *types.ProviderRouting
		want     int
	}{
		{nil, 0}, {&types.ProviderRouting{MinPrivacy: "standard"}, 0}, {&types.ProviderRouting{ZDR: &no}, 0},
		{&types.ProviderRouting{MinPrivacy: "no-store"}, 1}, {&types.ProviderRouting{DataCollection: "deny"}, 1},
		{&types.ProviderRouting{MinPrivacy: "zdr"}, 2}, {&types.ProviderRouting{ZDR: &yes}, 2},
		{&types.ProviderRouting{MinPrivacy: "no_store", ZDR: &yes}, 2},
		{&types.ProviderRouting{MinPrivacy: "e2ee"}, 3}, {&types.ProviderRouting{MinPrivacy: "trusted"}, 4},
	} {
		req := selectionTestRequest()
		req.Provider = tc.provider
		if got := polyphemusRequiredTier(context.Background(), req); got != tc.want {
			t.Errorf("%+v: tier %d, want %d", tc.provider, got, tc.want)
		}
	}
	if got := polyphemusRequiredTier(trustedrouter.WithConfidentialOnly(context.Background()), selectionTestRequest()); got != 3 {
		t.Errorf("confidential hostname: tier %d", got)
	}
}

func TestPolyphemusConfidentialUsesTheControlPlanesNames(t *testing.T) {
	for _, name := range []string{"confidential", "trusted", "e2e", "E2EE", " max ", "maximum"} {
		req := selectionTestRequest()
		req.Provider = &types.ProviderRouting{MinPrivacy: name}
		if !polyphemusConfidential(context.Background(), req) {
			t.Errorf("%q not confidential", name)
		}
	}
	for _, name := range []string{"", "any", "standard", "zdr", "no-store"} {
		req := selectionTestRequest()
		req.Provider = &types.ProviderRouting{MinPrivacy: name}
		if polyphemusConfidential(context.Background(), req) {
			t.Errorf("%q treated as confidential", name)
		}
	}
	if !polyphemusConfidential(trustedrouter.WithConfidentialOnly(context.Background()), selectionTestRequest()) {
		t.Error("confidential-only hostname ignored")
	}
}

func TestPolyphemusSelectionUsesSharedBillingAndPreservesRequest(t *testing.T) {
	req := selectionTestRequest()
	req.Messages = []types.OpenAIChatMessage{
		{Role: "system", Content: "PRIVATE SYSTEM"},
		{Role: "user", Content: "PRIVATE TASK 日本語"},
	}
	gateway := &selectionGatewayStub{}
	calls := 0
	classifier := classifierStub(func(_ context.Context, text string) (polyclass.Result, error) {
		calls++
		if gateway.admitted != 1 || gateway.settled != 0 {
			t.Fatal("classified before admission")
		}
		if text != "PRIVATE TASK 日本語" {
			t.Fatalf("classifier saw %q, want only the latest user text", text)
		}
		return polyclass.Result{Task: "Open QA", DomainKnowledge: 0.3}, nil
	})
	ctx, err := preparePolyphemus(context.Background(), req, gateway, classifier, "private-key", "log-1")
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 || gateway.settled != 1 || gateway.refunded != 0 {
		t.Fatalf("calls=%d settled=%d refunds=%d", calls, gateway.settled, gateway.refunded)
	}
	wantTokens := types.ContentTokenEstimate("PRIVATE TASK 日本語")
	if gateway.usage.InputTokens != wantTokens || !gateway.usage.UsageEstimated || gateway.usage.OutputTokens != 0 || gateway.usage.RouteType != polyphemusSelectRoute {
		t.Fatal("selector fee is not metered on the classified text")
	}
	if len(gateway.request.Messages) != 1 || trustedrouter.EstimateInputTokens(gateway.request) < wantTokens {
		t.Fatal("admission does not cover exactly the classified text")
	}
	if req.Model != polyphemusCheapModel || req.ResponseModel != polyphemusModel || req.Provider.Usage != "credits" || len(req.Messages) != 2 {
		t.Fatalf("bad continuation: %#v", req)
	}
	if req.ReasoningEffort != "" {
		t.Fatal("selection must not invent a reasoning effort")
	}
	if req.IdempotencyKey == gateway.request.IdempotencyKey || gateway.request.RequestFingerprint == "" || strings.Contains(gateway.request.RequestFingerprint, "PRIVATE") {
		t.Fatal("bad stage binding")
	}
	usage := map[string]any{"cost_microdollars": 37, "input_tokens": 10}
	annotatePolyphemusUsage(ctx, usage)
	meta := usage["provider_usage"].(map[string]any)
	if usage["cost_microdollars"] != 38 || meta["selector_input_tokens"] != wantTokens || meta["selector_provider"] != "trustedrouter" ||
		meta["selector_runs_in_gateway"] != true || meta["selector_tier"] != "cheap" || meta["selector_task"] != "Open QA" || meta["selected_model"] != polyphemusCheapModel {
		t.Fatalf("receipt: %#v", meta)
	}
	encoded, _ := json.Marshal(usage)
	if strings.Contains(string(encoded), "PRIVATE") || strings.Contains(string(encoded), "private-key") {
		t.Fatal("content leak")
	}
}

func TestPolyphemusToolRequestsGoStrongWithoutClassifierOrFee(t *testing.T) {
	for _, tc := range []struct {
		provider *types.ProviderRouting
		want     string
	}{{nil, polyphemusStrongModel}, {&types.ProviderRouting{MinPrivacy: "confidential"}, polyphemusConfidentialStrongModel}} {
		req := selectionTestRequest()
		req.Provider = tc.provider
		req.Tools = []any{map[string]any{"type": "function", "function": map[string]any{"name": "read_file"}}}
		gateway := &selectionGatewayStub{}
		never := classifierStub(func(context.Context, string) (polyclass.Result, error) {
			t.Fatal("classified a tool request")
			return polyclass.Result{}, nil
		})
		ctx, err := preparePolyphemus(context.Background(), req, gateway, never, "key", "test")
		if err != nil {
			t.Fatal(err)
		}
		if gateway.admitted != 0 || gateway.settled != 0 || gateway.refunded != 0 {
			t.Fatalf("tool request touched selector billing: %+v", gateway)
		}
		if req.Model != tc.want || len(req.Tools) != 1 || req.IdempotencyKey == "" || req.RequestFingerprint == "" {
			t.Fatalf("bad continuation: %#v", req)
		}
		usage := map[string]any{"cost_microdollars": 37}
		annotatePolyphemusUsage(ctx, usage)
		meta := usage["provider_usage"].(map[string]any)
		if usage["cost_microdollars"] != 37 || meta["selector_calls"] != 0 || meta["selector_tier"] != "strong" || meta["selected_model"] != tc.want {
			t.Fatalf("receipt: %#v", meta)
		}
		if _, ok := meta["selector_task"]; ok {
			t.Fatal("receipt claims a classification that never ran")
		}
	}
}

func TestPolyphemusModelBelowTheCallersPrivacyTierIsNeverCharged(t *testing.T) {
	// Opus without a zero-retention endpoint: a zdr request must not pay the
	// selector fee for a model the generation admission would refuse.
	noZDR := strings.Replace(selectionTestCatalog, `"prepaid_available":true,"privacy_tier":2`, `"prepaid_available":true,"privacy_tier":0`, 1)
	req := selectionTestRequest()
	req.Provider = &types.ProviderRouting{MinPrivacy: "zdr"}
	gateway := &selectionGatewayStub{catalog: noZDR}
	if _, err := preparePolyphemus(context.Background(), req, gateway, returns("Code Generation", 0.99), "key", "test"); err != nil {
		t.Fatal(err)
	}
	if gateway.settled != 0 || gateway.refunded != 1 || req.Model != "trustedrouter/auto" || req.Provider.MinPrivacy != "zdr" {
		t.Fatalf("settled=%d refunded=%d model=%s", gateway.settled, gateway.refunded, req.Model)
	}
	// Tool requests skip admission entirely, so nothing is held or refunded.
	req = selectionTestRequest()
	req.Provider = &types.ProviderRouting{MinPrivacy: "zdr"}
	req.Tools = []any{map[string]any{"type": "function"}}
	gateway = &selectionGatewayStub{catalog: noZDR}
	if _, err := preparePolyphemus(context.Background(), req, gateway, returns("Open QA", 0.3), "key", "test"); err != nil {
		t.Fatal(err)
	}
	if gateway.admitted != 0 || req.Model != "trustedrouter/auto" {
		t.Fatalf("admitted=%d model=%s", gateway.admitted, req.Model)
	}
}

func TestPolyphemusFailuresNeverGenerateOrDoubleCharge(t *testing.T) {
	for _, stage := range []string{"admission", "replay", "settlement", "wrong_provider"} {
		t.Run(stage, func(t *testing.T) {
			gateway := &selectionGatewayStub{}
			switch stage {
			case "admission":
				gateway.authErr = errors.New("denied")
			case "replay":
				gateway.replay = true
			case "settlement":
				gateway.settleErr = errors.New("lost response")
			case "wrong_provider":
				gateway.provider = "someone-else"
			}
			calls := 0
			classifier := classifierStub(func(context.Context, string) (polyclass.Result, error) {
				calls++
				return polyclass.Result{Task: "Open QA", DomainKnowledge: 0.3}, nil
			})
			req := selectionTestRequest()
			ctx, err := preparePolyphemus(context.Background(), req, gateway, classifier, "key", "test")
			if err == nil || polyphemusReceiptFromContext(ctx) != nil || req.Model != polyphemusModel {
				t.Fatal("failure continued to generation")
			}
			if stage != "settlement" && calls != 0 {
				t.Fatal("classified without a valid admission")
			}
			if stage == "wrong_provider" && gateway.refunded != 1 {
				t.Fatal("integrity failure not refunded")
			}
			if stage == "settlement" && (gateway.refunded != 0 || gateway.settled != 1) {
				t.Fatal("ambiguous settlement was refunded/repeated")
			}
		})
	}
}

func TestPolyphemusAcceptsTheFormerSelectorProviderSlug(t *testing.T) {
	gateway := &selectionGatewayStub{provider: "telluvian"}
	if _, err := preparePolyphemus(context.Background(), selectionTestRequest(), gateway, returns("Open QA", 0.3), "key", "test"); err != nil {
		t.Fatal(err)
	}
}

func TestPolyphemusClassifierFailuresFallBackToAutoWithoutFee(t *testing.T) {
	for _, stage := range []string{"error", "missing_classifier", "not_in_catalog", "refund_failure", "cancelled"} {
		t.Run(stage, func(t *testing.T) {
			gateway := &selectionGatewayStub{}
			if stage == "refund_failure" {
				gateway.refundErr = errors.New("unavailable")
			}
			if stage == "not_in_catalog" {
				gateway.catalog = `{"data":[{"id":"google/gemini-3.8-flash","trustedrouter":{"supports_chat":true,"prepaid_available":true}}]}`
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var classifier promptClassifier = classifierStub(func(context.Context, string) (polyclass.Result, error) {
				switch stage {
				case "not_in_catalog":
					return polyclass.Result{Task: "Open QA", DomainKnowledge: 0.3}, nil
				case "cancelled":
					cancel()
				}
				return polyclass.Result{}, polyclass.ErrUnavailable
			})
			if stage == "missing_classifier" {
				classifier = nil
			}
			req := selectionTestRequest()
			req.ReasoningEffort = "low"
			outCtx, err := preparePolyphemus(ctx, req, gateway, classifier, "key", "test")
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
			if req.Model != "trustedrouter/auto" || req.ResponseModel != polyphemusModel || req.ReasoningEffort != "low" {
				t.Fatal("lost fallback request")
			}
			usage := map[string]any{"cost_microdollars": 37}
			annotatePolyphemusUsage(outCtx, usage)
			meta := usage["provider_usage"].(map[string]any)
			if usage["cost_microdollars"] != 37 || meta["selector_cost_microdollars"] != 0 || meta["selector_fallback_model"] != "trustedrouter/auto" || meta["selector_input_tokens"] != 0 {
				t.Fatal("charged failed selection", usage)
			}
		})
	}
}

func TestPolyphemusAcceptsPrivacyAndConfidentialRequests(t *testing.T) {
	yes := true
	for _, tc := range []struct {
		provider *types.ProviderRouting
		want     string
	}{
		{&types.ProviderRouting{MinPrivacy: "zdr"}, polyphemusStrongModel},
		{&types.ProviderRouting{MinPrivacy: "no-store"}, polyphemusStrongModel},
		{&types.ProviderRouting{ZDR: &yes}, polyphemusStrongModel},
		{&types.ProviderRouting{DataCollection: "deny"}, polyphemusStrongModel},
		{&types.ProviderRouting{MinPrivacy: "confidential"}, polyphemusConfidentialStrongModel},
		{&types.ProviderRouting{MinPrivacy: "e2e"}, polyphemusConfidentialStrongModel},
	} {
		req := selectionTestRequest()
		req.Provider = tc.provider
		gateway := &selectionGatewayStub{}
		if _, err := preparePolyphemus(context.Background(), req, gateway, returns("Code Generation", 0.99), "key", "test"); err != nil {
			t.Fatalf("%+v: %v", tc.provider, err)
		}
		if req.Model != tc.want {
			t.Errorf("%+v routed to %s, want %s", tc.provider, req.Model, tc.want)
		}
		// The caller's privacy constraint still governs both admissions.
		if gateway.request.Provider.MinPrivacy != tc.provider.MinPrivacy || req.Provider.MinPrivacy != tc.provider.MinPrivacy {
			t.Errorf("%+v: privacy constraint dropped", tc.provider)
		}
	}
}

func TestPolyphemusRejectsByokAndTextlessRequestsBeforeAdmission(t *testing.T) {
	never := classifierStub(func(context.Context, string) (polyclass.Result, error) {
		t.Fatal("classified a request that should be refused")
		return polyclass.Result{}, nil
	})
	for _, provider := range []*types.ProviderRouting{{Usage: "byok"}, {Billing: "BYOK"}, {UsageType: "byok"}} {
		req := selectionTestRequest()
		req.Provider = provider
		gateway := &selectionGatewayStub{}
		if _, err := preparePolyphemus(context.Background(), req, gateway, never, "key", "test"); err == nil || gateway.admitted != 0 {
			t.Fatalf("BYOK accepted: %#v", provider)
		}
	}
	req := selectionTestRequest()
	req.Messages = []types.OpenAIChatMessage{{Role: "system", Content: "only a system prompt"}}
	gateway := &selectionGatewayStub{}
	if _, err := preparePolyphemus(context.Background(), req, gateway, never, "key", "test"); err == nil || gateway.admitted != 0 {
		t.Fatal("textless request admitted")
	}
}

func TestPolyphemusResolvesOnlyExactEligibleModels(t *testing.T) {
	if err := resolveSelectedModel([]byte(selectionTestCatalog), "google/gemini-3.8-flash", 0); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"gemini-3.8-flash", "Google/gemini-3.8-flash", "trustedrouter/auto", "missing"} {
		if resolveSelectedModel([]byte(selectionTestCatalog), name, 0) == nil {
			t.Fatal("accepted", name)
		}
	}
	duplicate := strings.Replace(selectionTestCatalog, `]}`, `,{"id":"google/gemini-3.8-flash","trustedrouter":{"supports_chat":true,"prepaid_available":true}}]}`, 1)
	if resolveSelectedModel([]byte(duplicate), "google/gemini-3.8-flash", 0) == nil {
		t.Fatal("duplicate id accepted")
	}
	for _, flags := range []string{`"supports_chat":true,"prepaid_available":false`, `"supports_chat":false,"prepaid_available":true`, `"supports_chat":true,"prepaid_available":true,"supports_responses":false`} {
		catalog := `{"data":[{"id":"google/gemini-3.8-flash","trustedrouter":{` + flags + `}}]}`
		if resolveSelectedModel([]byte(catalog), "google/gemini-3.8-flash", 0) == nil {
			t.Fatalf("ineligible model accepted: %s", flags)
		}
	}
	if resolveSelectedModel([]byte("not json"), "google/gemini-3.8-flash", 0) == nil {
		t.Fatal("unreadable catalog accepted")
	}
	if resolveSelectedModel([]byte(selectionTestCatalog), polyphemusStrongModel, 2) != nil || resolveSelectedModel([]byte(selectionTestCatalog), polyphemusStrongModel, 3) == nil {
		t.Fatal("privacy tier not enforced at the boundary")
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

func TestPolyphemusIgnoresLegacyControlsButBindsThem(t *testing.T) {
	fingerprint := func(options *types.PolyphemusOptions) (string, string) {
		req := selectionTestRequest()
		req.Polyphemus = options
		gateway := &selectionGatewayStub{}
		if _, err := preparePolyphemus(context.Background(), req, gateway, returns("Open QA", 0.3), "key", "test"); err != nil {
			t.Fatal(err)
		}
		if gateway.request.Polyphemus != nil || req.Polyphemus != nil {
			t.Fatal("controls leaked into admission or the chosen model's request")
		}
		return gateway.request.RequestFingerprint, req.Model
	}
	base, model := fingerprint(nil)
	for _, options := range []*types.PolyphemusOptions{{XPerf: 0.5}, {XPerf: 0.6}, {ModelZoo: "openai/*"}, {XPerf: "openai/gpt-6-astra"}} {
		other, otherModel := fingerprint(options)
		if other == base {
			t.Fatalf("%+v did not change the request fingerprint", options)
		}
		if otherModel != model {
			t.Fatalf("%+v changed the selection", options)
		}
	}
}

func TestPolyphemusOptionsGoThroughTheRealResponsesParser(t *testing.T) {
	good := `{"model":"trustedrouter/polyphemus-1.0","input":"hi","polyphemus":{"x_perf":0.9,"model_zoo":"openai/*"}}`
	req, err := parseResponsesRequest([]byte(good))
	if err != nil || req.Polyphemus == nil || req.Polyphemus.ModelZoo != "openai/*" {
		t.Fatalf("parse: %v %#v", err, req)
	}
	for body, context := range map[string]string{
		`{"model":"trustedrouter/polyphemus-1.0","input":"hi","polyphemus":{"modelZoo":"openai/*"}}`: "polyphemus.modelZoo",
		`{"model":"trustedrouter/polyphemus-1.0","input":"hi","polyphemus":[1]}`:                     "polyphemus",
		`{"model":"trustedrouter/polyphemus-1.0","input":"hi","polyphemus":{"model_zoo":{}}}`:        "polyphemus.model_zoo",
		`{"model":"trustedrouter/polyphemus-1.0","input":"hi","polyphemus":{"x_perf":1e999}}`:        "polyphemus.x_perf",
	} {
		_, err := parseResponsesRequest([]byte(body))
		var aerr *adapter.AdapterError
		if !errors.As(err, &aerr) || aerr.Context != context {
			t.Fatalf("%s: got %v, want rejection on %s", body, err, context)
		}
	}
}

func TestPolyphemusFallbackAlsoClearsCallerControls(t *testing.T) {
	req := selectionTestRequest()
	req.Polyphemus = &types.PolyphemusOptions{XPerf: 0.5, ModelZoo: "openai/*"}
	gateway := &selectionGatewayStub{}
	failing := classifierStub(func(context.Context, string) (polyclass.Result, error) {
		return polyclass.Result{}, polyclass.ErrUnavailable
	})
	if _, err := preparePolyphemus(context.Background(), req, gateway, failing, "key", "test"); err != nil {
		t.Fatal(err)
	}
	if req.Model != "trustedrouter/auto" || req.Polyphemus != nil {
		t.Fatalf("fallback kept caller controls: model=%s options=%#v", req.Model, req.Polyphemus)
	}
}
