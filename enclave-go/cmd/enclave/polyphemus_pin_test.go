package main

import (
	"context"
	"regexp"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/polyclass"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestPolyphemusPinnedCallIDsRoundTripInEveryProvidersCharset(t *testing.T) {
	anthropicID := regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
	for _, upstream := range []string{"toolu_01AbC", "call_9f8e", "fc-123_x", "a"} {
		pinned := polyphemusPinCallID("google/gemini-3.8-flash", upstream)
		if !anthropicID.MatchString(pinned) {
			t.Fatalf("pinned id %q is not provider-safe", pinned)
		}
		model, got, ok := polyphemusUnpinCallID(pinned)
		if !ok || model != "google/gemini-3.8-flash" || got != upstream {
			t.Fatalf("round trip of %q = %q %q %v", upstream, model, got, ok)
		}
	}
	for _, plain := range []string{"", "toolu_01", "pm1", "pm1zz", "pm1ffabc_x", "pm104!!!!_x", "pm104Z29v"} {
		if model, got, ok := polyphemusUnpinCallID(plain); ok || model != "" || got != plain {
			t.Fatalf("%q unexpectedly unpinned to %q %q", plain, model, got)
		}
	}
	if polyphemusPinCallID("google/gemini-3.8-flash", "") != "" {
		t.Fatal("empty upstream id must stay empty so the adapter can mint one")
	}
}

func pinnedHistoryRequest(model string) *types.OpenAIChatRequest {
	req := selectionTestRequest()
	id := polyphemusPinCallID(model, "toolu_01AbC")
	req.Messages = append(req.Messages,
		types.OpenAIChatMessage{Role: "assistant", ToolCalls: []types.OpenAIToolCall{{ID: id, Type: "function", Function: types.OpenAIToolFunction{Name: "web_search", Arguments: "{}"}}}},
		types.OpenAIChatMessage{Role: "tool", ToolCallID: id, Content: "results"},
	)
	return req
}

func TestPolyphemusPinnedConversationSkipsTheSelectorAndItsFee(t *testing.T) {
	req := pinnedHistoryRequest("google/gemini-3.8-flash")
	gateway := &selectionGatewayStub{}
	selector := classifierStub(func(context.Context, string) (polyclass.Result, error) {
		t.Fatal("a pinned conversation ran the classifier")
		return polyclass.Result{}, nil
	})
	ctx, err := preparePolyphemus(context.Background(), req, gateway, selector, "private-key", "log-1")
	if err != nil {
		t.Fatal(err)
	}
	if gateway.admitted != 0 || gateway.settled != 0 || gateway.refunded != 0 {
		t.Fatalf("pinned turn touched selector billing: %+v", gateway)
	}
	if req.Model != "google/gemini-3.8-flash" || req.ResponseModel != polyphemusModel || req.Provider.Usage != "credits" {
		t.Fatalf("bad continuation: %#v", req)
	}
	if req.Messages[1].ToolCalls[0].ID != "toolu_01AbC" || req.Messages[2].ToolCallID != "toolu_01AbC" {
		t.Fatalf("model would see pinned ids: %#v", req.Messages)
	}
	receipt := polyphemusReceiptFromContext(ctx)
	if receipt == nil || !receipt.Pinned || receipt.SelectorCalls != 0 || receipt.CostMicrodollars != 0 {
		t.Fatalf("receipt = %+v", receipt)
	}
	usage := map[string]any{"cost_microdollars": 37}
	annotatePolyphemusUsage(ctx, usage)
	if usage["cost_microdollars"] != 37 || usage["provider_usage"].(map[string]any)["selector_pinned"] != true {
		t.Fatalf("pinned usage = %#v", usage)
	}
	if stamp := polyphemusToolCallStamp(ctx); stamp == nil || stamp("call_2") != polyphemusPinCallID("google/gemini-3.8-flash", "call_2") {
		t.Fatal("next turn's tool calls must carry the same pin")
	}
}

func TestPolyphemusPinToAModelOutsideTheCatalogSelectsAgain(t *testing.T) {
	for _, model := range []string{"openai/not-in-catalog", "trustedrouter/auto", "gemini-3.8-flash"} {
		req := pinnedHistoryRequest(model)
		gateway := &selectionGatewayStub{}
		calls := 0
		selector := classifierStub(func(_ context.Context, text string) (polyclass.Result, error) {
			calls++
			if strings.Contains(text, polyphemusPinPrefix) {
				t.Error("classifier saw pinned ids")
			}
			return polyclass.Result{Task: "Open QA", DomainKnowledge: 0.3}, nil
		})
		ctx, err := preparePolyphemus(context.Background(), req, gateway, selector, "private-key", "log-1")
		if err != nil {
			t.Fatal(err)
		}
		if calls != 1 || gateway.settled != 1 || polyphemusReceiptFromContext(ctx).Pinned {
			t.Fatalf("%s: forged or stale pin bypassed selection (calls=%d)", model, calls)
		}
		if req.Messages[1].ToolCalls[0].ID != "toolu_01AbC" {
			t.Fatalf("%s: pinned id reached the model", model)
		}
	}
}

func TestPolyphemusFallbackAndOtherModelsAreNeverPinned(t *testing.T) {
	if polyphemusToolCallStamp(context.Background()) != nil {
		t.Fatal("non-Polyphemus response was pinned")
	}
	fallback := context.WithValue(context.Background(), polyphemusContextKey{}, &polyphemusReceipt{SelectedModel: "trustedrouter/auto", FallbackReason: "model_selection_failed"})
	if polyphemusToolCallStamp(fallback) != nil {
		t.Fatal("auto fallback was pinned")
	}
}
