package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/abuse"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/authcache"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
)

func TestAstraR2HeaderValidationBeforeBillingHit(t *testing.T) {
	t.Setenv("TR_REQUEST_METADATA_ENFORCEMENT", "enforce")
	for route, body := range map[string]string{
		"/v1/chat/completions": astraChat,
		"/v1/responses":        `{"model":"test-model","input":"hi"}`,
		"/v1/messages":         `{"model":"test-model","max_tokens":10,"messages":[{"role":"user","content":"hi"}]}`,
		"/v1/embeddings":       `{"model":"test-model","input":"hi"}`,
		"/v1/images":           `{"model":"google/gemini-3.1-flash-image","prompt":"cat"}`,
		"/api/alpha/decide":    decideBody,
	} {
		t.Run(route, func(t *testing.T) {
			gateway := astraGateway(t)
			headers := "HTTP-Referer: not-a-url\r\n"
			cold, _ := astraRequest(t, gateway, route, body, headers)
			if parseHTTPStatus(cold) != 400 {
				t.Fatalf("cold: %s", cold)
			}
			seed, _ := astraRequest(t, gateway, route, body, "")
			if parseHTTPStatus(seed) != 402 {
				t.Fatalf("seed: %s", seed)
			}
			warm, logs := astraRequest(t, gateway, route, body, headers)
			if parseHTTPStatus(warm) != 400 {
				t.Fatalf("header validation masked: cold=400 warm=%d logs=%q", parseHTTPStatus(warm), logs)
			}
		})
	}
}

func TestAstraR2AbuseAccounting(t *testing.T) {
	gateway := astraGateway(t)
	negative := authcache.New(time.Minute, 10)
	limiter := abuse.NewLimiter(0.001, 2, 10)
	guard := abuse.NewProtector(negative, limiter)
	gateway.SetCredentialGuard(guard)
	for i := 0; i < 4; i++ {
		resp, logs := astraRequest(t, gateway, "/v1/chat/completions", astraChat, "")
		if parseHTTPStatus(resp) != 402 {
			t.Fatalf("billing response: %s", resp)
		}
		if i > 0 && logs != "" {
			t.Fatalf("hit logs: %s", logs)
		}
	}
	if stats := guard.Stats(); stats.NegativeCacheHits != 0 || stats.RateLimitedRejects != 0 || stats.BucketOccupancy != 0 {
		t.Fatalf("billing consumed failures: %+v", stats)
	}
	negative.Remember(trustedrouter.LookupHash("review-key"), &trustedrouter.ControlPlaneError{StatusCode: 401, Type: "invalid_api_key"}, time.Now())
	for i, want := range []int{401, 401, 429} {
		resp, logs := astraRequest(t, gateway, "/v1/chat/completions", astraChat, "")
		if parseHTTPStatus(resp) != want {
			t.Fatalf("request %d got %s", i, resp)
		}
		for _, event := range []string{"request_accept", "request_start", "request_end"} {
			if strings.Count(logs, "enclave."+event) != 1 {
				t.Fatalf("lost audit: %s", logs)
			}
		}
		outcome := "auth_cached_reject"
		if want == 429 {
			outcome = "auth_rate_limited"
		}
		if !strings.Contains(logs, `outcome="`+outcome+`"`) {
			t.Fatalf("outcome: %s", logs)
		}
	}
	if stats := guard.Stats(); stats.NegativeCacheHits != 2 || stats.RateLimitedRejects != 1 {
		t.Fatalf("duplicate accounting: %+v", stats)
	}
}

type astraR2ContextGuard struct {
	sawClient bool
	calls     int
}

func (g *astraR2ContextGuard) BeforeCredentialCheck(ctx context.Context, _ string) error {
	g.calls++
	g.sawClient = trustedrouter.ClientContextFromContext(ctx) != nil
	return nil
}
func (g *astraR2ContextGuard) AfterCredentialCheck(context.Context, string, error) {}

func TestAstraR2InvalidTargetPreservesAuditClientContext(t *testing.T) {
	gateway := astraGateway(t)
	guard := &astraR2ContextGuard{}
	gateway.SetCredentialGuard(guard)
	resp, _ := astraRequest(t, gateway, "/v1/chat/completions?nonce=not-hex", astraChat, "User-Agent: trusted-router-py/1.2.3\r\n")
	if parseHTTPStatus(resp) != 400 || guard.calls != 1 {
		t.Fatalf("response=%s guard=%+v", resp, guard)
	}
	if !guard.sawClient {
		t.Fatal("invalid-target audit lookup lost client context")
	}
}
