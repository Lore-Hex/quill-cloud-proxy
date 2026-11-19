package llm

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"strings"
	"testing"
)

func TestSafetyEgressWitness(t *testing.T) {
	id := strings.Repeat("7b", 32)
	body := []byte(`{"prompt":"not for logs","safety_identifier":"` + id + `"}`)
	for _, tc := range []struct {
		name, url, expected  string
		status               int
		verified, redirected bool
		want                 string
	}{
		{"direct", "https://api.openai.com/v1/responses", id, 200, true, false, "true"},
		{"wrong value", "https://api.openai.com/v1/chat/completions", strings.Repeat("ab", 32), 200, true, false, "false"},
		{"raw", "https://api.openai.com/v1/responses", "user@example.invalid", 200, true, false, "false"},
		{"other host", "https://example.invalid/v1/responses", id, 200, true, false, ""},
		{"other path", "https://api.openai.com/v1/embeddings", id, 200, true, false, ""},
		{"redirect", "https://api.openai.com/v1/responses", id, 200, true, true, ""},
		{"no verified TLS", "https://api.openai.com/v1/responses", id, 200, false, false, ""},
		{"upstream error", "https://api.openai.com/v1/responses", id, 400, true, false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, err := http.NewRequest(http.MethodPost, tc.url, bytes.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			resp := &http.Response{StatusCode: tc.status, Request: r}
			if tc.verified {
				resp.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{{}}}}
			}
			if tc.redirected {
				r.Response = &http.Response{StatusCode: http.StatusTemporaryRedirect}
			}
			var log bytes.Buffer
			w := safetyEgressWitness{out: &log}
			w.observe(resp, body, tc.expected)
			w.observe(resp, body, tc.expected)
			want := ""
			if tc.want != "" {
				want = "openai.safety_egress path=" + r.URL.Path + " upstream=2xx matched_sha256=" + tc.want + "\n"
			}
			if log.String() != want {
				t.Fatal("unexpected egress evidence")
			}
		})
	}
}
