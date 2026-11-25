package main

import (
	"errors"
	"io"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestNativeCustomDoesNotAttemptIneligibleRoutes(t *testing.T) {
	const model = "openai/gpt-5.5"
	for _, o := range []llm.InvokeOptions{
		{Model: model, Provider: "azure", UsageType: "Credits"},
		{Model: model, Provider: "openrouter", UsageType: "Credits"},
		{Model: model, Provider: "openai", UsageType: "BYOK"},
		{Model: model, Provider: "openai", UsageType: "Credits", ProviderAPIKey: "fixture"},
		{Model: model, UpstreamModel: "gpt-5.5-pro", Provider: "openai", UsageType: "Credits"},
		{Model: model, UpstreamModel: "gpt-6.2-astra", Provider: "openai", UsageType: "Credits"},
		{Model: "other/model", UpstreamModel: "gpt-5.5", Provider: "openai", UsageType: "Credits"},
		{},
	} {
		r, w := io.Pipe()
		tracker := newSelectedRouteTracker()
		req := &types.OpenAIChatRequest{Model: model, Response: &types.ResponseRequestMeta{NativeCustom: &types.NativeCustomTools{}}}
		// A nil provider would panic if dispatch attempted any upstream call.
		invokeProviderStream(t.Context(), nil, req, nil, w, []llm.InvokeOptions{o}, true, nil, tracker, "fixture", false, false)
		_, err := io.ReadAll(r)
		r.Close()
		var ae *adapter.AdapterError
		if !errors.As(err, &ae) || ae.Status != 400 || tracker.AttemptCount() != 0 {
			t.Fatalf("did not reject before dispatch: %v", err)
		}
	}
}
