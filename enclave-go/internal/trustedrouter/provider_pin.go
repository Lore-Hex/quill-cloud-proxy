package trustedrouter

import (
	"context"
	"maps"
	"strings"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

type providerPinKey struct{}
type providerPin map[string]struct{}

// Only caller input admits public filter aliases. The authorization and the
// actual dispatch must name a concrete, canonical provider, never a group.
func withProviderPin(ctx context.Context, routing *qtypes.ProviderRouting) context.Context {
	if routing == nil || len(routing.Only) == 0 {
		return ctx
	}
	parent, _ := ctx.Value(providerPinKey{}).(providerPin)
	pin := make(providerPin)
	add := func(id string) {
		_, allowed := parent[id]
		if id != "" && (parent == nil || allowed) {
			pin[id] = struct{}{}
		}
	}
	for _, item := range routing.Only {
		id := strings.ToLower(strings.TrimSpace(item))
		id = strings.ReplaceAll(strings.ReplaceAll(id, " ", "-"), "_", "-")
		switch id {
		case "google", "gemini":
			add("google-vertex")
			add("google-ai-studio")
		case "ai-studio", "google-ai":
			add("google-ai-studio")
		case "vertex", "vertex-ai", "google-vertex-ai":
			add("google-vertex")
		case "system1models":
			add("decisionmodelsio")
		case "system1models-eu":
			add("decisionmodelsio-eu")
		case "chatgpt", "chat-gpt":
			add("openai")
		case "mistralai", "mistral-ai":
			add("mistral")
		case "moonshot", "moonshot-ai":
			add("kimi")
		case "z-ai", "zhipu", "zhipuai":
			add("zai")
		case "together-ai", "togetherai":
			add("together")
		default:
			add(id)
		}
	}
	if parent != nil && maps.Equal(parent, pin) {
		return ctx
	}
	return context.WithValue(ctx, providerPinKey{}, pin)
}

func HasProviderPin(ctx context.Context) bool {
	return ctx.Value(providerPinKey{}) != nil
}

// A non-nil empty intersection denies every provider; it is not unrestricted.
func ProviderPinAllows(ctx context.Context, provider string) bool {
	pin, _ := ctx.Value(providerPinKey{}).(providerPin)
	if pin == nil {
		return true
	}
	_, ok := pin[provider]
	return ok
}
