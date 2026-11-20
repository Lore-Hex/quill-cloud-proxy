package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
)

// Decode from the exact allowlisted field. The raw caller identifier is never
// placed in a provider request struct, a tag, or an authorization request.
func parseCallerSafety(raw json.RawMessage) (string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return "", nil
	}
	var id string
	if !utf8.Valid(raw) || json.Unmarshal(raw, &id) != nil || len(id) > 64 || strings.TrimSpace(id) == "" || strings.IndexFunc(id, unicode.IsControl) >= 0 {
		return "", &adapter.AdapterError{Status: 400, Context: "safety_identifier", Message: "safety_identifier must be a nonblank string of at most 64 UTF-8 bytes without control characters"}
	}
	sum := sha256.Sum256([]byte("trustedrouter/caller-safety/input/v1\x00" + id))
	return hex.EncodeToString(sum[:]), nil
}
