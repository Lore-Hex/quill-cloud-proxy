package webfetch

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

type transport func(*http.Request) (*http.Response, error)

func (f transport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestParse(t *testing.T) {
	for _, raw := range []string{
		`{}`, `null`, `{"url":null}`, `{"url":"file:///etc/passwd"}`,
		`{"url":"https://user:password@example.com"}`, `{"url":"https://localhost"}`,
		`{"url":"https://127.0.0.1"}`, `{"url":"https://[::1]"}`, `{"url":"http://169.254.169.254"}`,
		`{"url":"https://example.com","headers":{"Authorization":"secret"}}`,
		`{"url":"https://example.com","model":"deepseek/deepseek-flash"}`,
		`{"url":"https://example.com","provider":{"options":{"headers":{}}}}`,
		`{"url":"https://example.com"} {}`, `{"url":"https://example.com/` + strings.Repeat("x", 8192) + `"}`,
	} {
		if _, err := Parse([]byte(raw)); err == nil {
			t.Errorf("accepted %s", raw[:min(150, len(raw))])
		}
	}
	r, err := Parse([]byte(`{"url":"https://example.com/?private=value","provider":{"min_privacy":"zdr"}}`))
	if err != nil || r.Model != ModelID || r.URL != "https://example.com/?private=value" {
		t.Fatalf("%v %v", r, err)
	}
}

func TestFetchTransport(t *testing.T) {
	for _, scenario := range []string{"success", "empty-title", "empty", "missing-title", "malformed", "redirect", "429", "oversize", "content-type", "missing-key"} {
		t.Run(scenario, func(t *testing.T) {
			calls := 0
			client := &http.Client{Transport: transport(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.URL.String() != endpoint || r.Method != "POST" || r.Header.Get("Authorization") != "Bearer secret" {
					t.Fatalf("wrong destination/auth: %s", r.URL)
				}
				var body map[string]any
				json.NewDecoder(r.Body).Decode(&body)
				if len(body) != 1 || body["url"] != "https://example.com/?private=value" {
					t.Fatalf("unexpected body %v", body)
				}
				status, data, contentType := 200, `{"title":"Example","content":"# Example","private_extra":"discard"}`, "application/json"
				switch scenario {
				case "empty-title":
					data = `{"title":"","content":"Example"}`
				case "empty":
					data = `{"title":"Example","content":"  "}`
				case "missing-title":
					data = `{"content":"Example"}`
				case "malformed":
					data = `{"error":"private URL"}`
				case "redirect":
					status = 302
				case "429":
					status = 429
				case "oversize":
					data = strings.Repeat("x", MaxResponseBytes+1)
				case "content-type":
					contentType = "text/html"
				}
				return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {contentType}, "Location": {"https://evil.example"}}, Body: io.NopCloser(strings.NewReader(data)), Request: r}, nil
			})}
			key := "secret"
			if scenario == "missing-key" {
				key = ""
			}
			result, err := New(client, key).Fetch(context.Background(), &Request{URL: "https://example.com/?private=value"})
			if scenario == "success" || scenario == "empty-title" {
				if err != nil || result.Content == "" {
					t.Fatalf("%v %v", result, err)
				}
			} else if err == nil || strings.Contains(err.Error(), "private") {
				t.Fatalf("unexpected error %v", err)
			}
			wantCalls := 1
			if scenario == "missing-key" {
				wantCalls = 0
			}
			if calls != wantCalls {
				t.Fatalf("retried or followed URL: %d", calls)
			}
		})
	}
}
