package llm

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
)

// Observe at most one accepted POST per endpoint per boot. Log only fixed
// categories, never the subject, serialized body, headers or request ID.
type safetyEgressWitness struct {
	chat, responses sync.Once
	out             io.Writer
}

var openAISafetyEgress = safetyEgressWitness{out: os.Stderr}

func (w *safetyEgressWitness) observe(resp *http.Response, body []byte, expected string) {
	if resp.StatusCode < 200 || resp.StatusCode >= 300 || resp.TLS == nil || len(resp.TLS.VerifiedChains) == 0 {
		return
	}
	r := resp.Request
	if r == nil || r.URL == nil || r.Response != nil || r.Method != http.MethodPost ||
		r.URL.Scheme != "https" || r.URL.Host != "api.openai.com" {
		return
	}
	var once *sync.Once
	switch r.URL.Path {
	case "/v1/chat/completions":
		once = &w.chat
	case "/v1/responses":
		once = &w.responses
	default:
		return
	}
	once.Do(func() {
		var sent struct {
			Identifier string `json:"safety_identifier"`
		}
		_, err := hex.DecodeString(expected)
		match := len(expected) == 64 && err == nil && expected == strings.ToLower(expected) &&
			json.Unmarshal(body, &sent) == nil && sent.Identifier == expected
		fmt.Fprintf(w.out, "openai.safety_egress path=%s upstream=2xx matched_sha256=%t\n", r.URL.Path, match)
	})
}
