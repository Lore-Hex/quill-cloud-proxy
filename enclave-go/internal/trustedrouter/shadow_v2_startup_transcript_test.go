package trustedrouter

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"testing"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

// This test also compiles on 21292b56. Its literal was captured there with
// shadow on, the existing v1 reply, and in-memory request/response transport.
func TestStartupNonOptedTranscript(t *testing.T) {
	t.Setenv("TR_ASYNC_SETTLE_NEGOTIATE", "off")
	t.Setenv("TR_ASYNC_SETTLE_SHADOW", "on")
	fixture := map[string]json.RawMessage{}
	if json.Unmarshal(asyncFixture(t, "authorize_v1"), &fixture) != nil {
		t.Fatal("v1 fixture")
	}
	var transcript []any
	for _, route := range []string{"chat.completions", "responses", "messages"} {
		c := New("https://trustedrouter.com", "test", &http.Client{Transport: liveOracleTransport(func(r *http.Request) (*http.Response, error) {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatal(err)
			}
			reply := `{"data":{"settled":true,"cost_microdollars":2}}`
			if r.URL.Path == "/internal/gateway/authorize" {
				reply = string(fixture["response"])
			}
			transcript = append(transcript, map[string]any{"method": r.Method, "url": r.URL.String(), "headers": r.Header, "body": string(body), "response": reply})
			return v2Reply(reply), nil
		})})
		c.asyncShadow = true
		inv := &authorizationInvocation{nonce: "nonce-v1"}
		inv.once.Do(func() {})
		ctx := context.WithValue(t.Context(), authorizationInvocationContextKey{}, inv)
		a, err := c.AuthorizeWithRoute(ctx, "fixture-input", &qtypes.OpenAIChatRequest{Model: "fixture", IdempotencyKey: "fixture-id"}, route)
		if err != nil {
			t.Fatal(err)
		}
		// The full exported outcome and presence of every retained private branch
		// are captured. The v1 retained shadow snapshot is checked separately.
		transcript = append(transcript, map[string]any{"authorization": a, "shadow_retained": a.shadowSettlement != nil, "async_retained": a.async != nil})
		result, err := c.Settle(ctx, a, Usage{InputTokens: 3, OutputTokens: 2, RouteType: route, ElapsedSeconds: 1})
		if err != nil {
			t.Fatal(err)
		}
		transcript = append(transcript, map[string]any{"settle_result": result})
		if err = c.Refund(ctx, a, 502, "upstream_error", 1, nil); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := json.MarshalIndent(transcript, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if out := os.Getenv("STARTUP_BASE_TRANSCRIPT_OUTPUT"); out != "" {
		if err = os.WriteFile(out, raw, 0600); err != nil {
			t.Fatal(err)
		}
		return
	}
	expected, err := os.ReadFile("testdata/shadow_v2_startup_nonopted_transcript.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, expected) {
		t.Fatal("full non-opted request/response transcript differs from base")
	}
}
