package trustedrouter

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

// This secret never leaves the enclave. A lookup hash known to the control
// plane must not be enough to guess low-entropy opening prompts offline.
var cacheAffinitySecret = func() []byte {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil
	}
	return key
}()

// Only an opaque tenant-keyed digest crosses the enclave boundary. No opening
// prompt, cache key or extra copy of a session identifier enters durable state.
func cacheAffinity(lookupHash string, req *qtypes.OpenAIChatRequest, routeType string) (string, bool) {
	if req == nil || lookupHash == "" || len(cacheAffinitySecret) == 0 || (routeType != "chat.completions" && routeType != "responses" && routeType != "messages") {
		return "", false
	}
	if req.Provider != nil && len(req.Provider.Order) > 0 {
		return "", false
	}
	mac := hmac.New(sha256.New, cacheAffinitySecret)
	encoder := json.NewEncoder(mac)
	_ = encoder.Encode("trustedrouter/cache-affinity/v1")
	_ = encoder.Encode(lookupHash)
	explicit := req.SessionID != ""
	if explicit {
		_ = encoder.Encode("session")
		_ = encoder.Encode(req.SessionID)
	} else if req.PromptCacheKey != "" {
		_ = encoder.Encode("cache-key")
		_ = encoder.Encode(req.PromptCacheKey)
	} else {
		_ = encoder.Encode("opening-messages")
		found := false
		for _, message := range req.Messages {
			// Implicit affinity is text-only. An explicit session works for
			// multimodal chat without hashing image bytes or downloading media.
			text, ok := message.Content.(string)
			if !ok || len(text) > 64*1024 {
				return "", false
			}
			_ = encoder.Encode(message.Role)
			_ = encoder.Encode(text)
			if message.Role != "system" && message.Role != "developer" {
				found = true
				break
			}
		}
		if !found {
			return "", false
		}
	}
	return hex.EncodeToString(mac.Sum(nil)), explicit
}
