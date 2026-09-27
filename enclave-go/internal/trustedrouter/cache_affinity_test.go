package trustedrouter

import (
	"encoding/json"
	"strings"
	"testing"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestCacheAffinityIsTenantScopedAndOpeningConversationStable(t *testing.T) {
	r := &qtypes.OpenAIChatRequest{Model: "test", Messages: []qtypes.OpenAIChatMessage{
		{Role: "system", Content: "private instructions"}, {Role: "user", Content: "private first question"},
	}}
	key, explicit := cacheAffinity("tenant-one", r, "chat.completions")
	if len(key) != 64 || explicit {
		t.Fatal("expected opaque implicit key")
	}
	r.Messages = append(r.Messages, qtypes.OpenAIChatMessage{Role: "assistant", Content: "answer"}, qtypes.OpenAIChatMessage{Role: "user", Content: "next question"})
	if next, _ := cacheAffinity("tenant-one", r, "responses"); next != key {
		t.Fatal("conversation changed its affinity")
	}
	if other, _ := cacheAffinity("tenant-two", r, "responses"); other == key {
		t.Fatal("cross-tenant affinity")
	}
	r.SessionID = "session"
	r.PromptCacheKey = "cache"
	session, explicit := cacheAffinity("tenant-one", r, "responses")
	if !explicit || session == key {
		t.Fatal("session must take precedence")
	}
	r.PromptCacheKey = "other-cache"
	if next, _ := cacheAffinity("tenant-one", r, "responses"); next != session {
		t.Fatal("cache key overrode session")
	}
	if next, _ := cacheAffinity("tenant-one", r, "images"); next != "" {
		t.Fatal("media affinity is unsupported")
	}
	r.Provider = &qtypes.ProviderRouting{Order: qtypes.StringList{"tinfoil"}}
	if next, _ := cacheAffinity("tenant-one", r, "responses"); next != "" {
		t.Fatal("explicit provider order must win")
	}
}

func TestCacheAffinityWireContainsNoOpeningContentAndIsNotPersisted(t *testing.T) {
	r := &qtypes.OpenAIChatRequest{Model: "test", PromptCacheKey: "private-cache-key"}
	body := chatAuthorizeBody(&Client{}, "tenant", "idem", r, "chat.completions")
	encoded, _ := json.Marshal(body)
	if _, ok := body["cache_affinity_key"]; !ok || strings.Contains(string(encoded), "private-cache-key") {
		t.Fatalf("unsafe metadata: %s", encoded)
	}
	auth := Authorization{cacheAffinityKey: "opaque", cacheAffinityExplicit: true}
	encoded, _ = json.Marshal(auth)
	if strings.Contains(string(encoded), "opaque") || strings.Contains(string(encoded), "affinity") {
		t.Fatal("affinity leaked into durable authorization serialization")
	}
}

func TestPerformancePreferencesPreservedAndCannotUseLocalLease(t *testing.T) {
	r := &qtypes.OpenAIChatRequest{Model: "test", Stream: true, Provider: &qtypes.ProviderRouting{Usage: "credits", PreferredMaxLatency: 2.0, PreferredMinThroughput: map[string]any{"p90": 30.0}}}
	body := chatAuthorizeBody(&Client{}, "tenant", "idem", r, "chat.completions")
	encoded, _ := json.Marshal(body)
	if !strings.Contains(string(encoded), `"preferred_max_latency":2`) || !strings.Contains(string(encoded), `"preferred_min_throughput":{"p90":30}`) {
		t.Fatal("routing preferences disappeared")
	}
	if admissionWireMissReason(r) != "unsupported_provider_preferences" {
		t.Fatal("local admission ignored performance preferences")
	}
}
