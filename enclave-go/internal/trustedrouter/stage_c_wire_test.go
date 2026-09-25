package trustedrouter

import (
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/receipt"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/spendlease"
	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

// Count both operations: Ed25519 is deterministic, so equal signatures alone
// cannot detect re-signing the same receipt or boot proof on a retry.
type observedStageCSigner struct {
	*receipt.Signer
	messages atomic.Int32
	digests  atomic.Int32
}

func (s *observedStageCSigner) SignMessage(b []byte) ([]byte, error) {
	s.messages.Add(1)
	return s.Signer.SignMessage(b)
}
func (s *observedStageCSigner) SignDigest(d [sha256.Size]byte) ([]byte, error) {
	s.digests.Add(1)
	return s.Signer.SignDigest(d)
}
func stageCCapacity(t *testing.T, c *Client) int64 {
	t.Helper()
	// For an authoritative, enabled grant BeforeRequest observes the actual
	// atomic capacity without spending it, even with an empty estimate request.
	echo := c.spendLease.state.BeforeRequest(stageCFixtureLookupHash, spendlease.EstimateRequest{}, time.UnixMilli(2_000_000_005_000))
	if echo.RemainingMicro == nil {
		t.Fatalf("missing lookup-keyed capacity: %+v", echo)
	}
	return *echo.RemainingMicro
}

func TestStageCWireCopiesPublicStream(t *testing.T) {
	for _, stream := range []bool{false, true} {
		req := stageCFixtureRequest()
		req.Stream = stream
		c := &Client{region: "us-central1"}
		ordinary := chatAuthorizeBody(c, stageCFixtureLookupHash, req.IdempotencyKey, req, "responses")
		body := admissionAuthorizeBody(c, stageCFixtureLookupHash, ordinary, &spendlease.Admission{Receipt: "receipt"})
		if got, exists := body["stream"]; !exists || got != stream {
			t.Fatalf("public stream=%t serialized as %v (present=%t)", stream, got, exists)
		}
	}
}

func TestStageCWireMissBeforeCapacityOrSigning(t *testing.T) {
	cases := []struct {
		name, reason string
		edit         func(*qtypes.OpenAIChatRequest)
	}{
		{"whitespace_only", "cap_not_enforceable", func(r *qtypes.OpenAIChatRequest) { r.ServiceTier = " \t\n" }},
		{"padded_default", "cap_not_enforceable", func(r *qtypes.OpenAIChatRequest) { r.ServiceTier = " default " }},
		{"uppercase_default", "cap_not_enforceable", func(r *qtypes.OpenAIChatRequest) { r.ServiceTier = "DEFAULT" }},
		{"mixed_case_default", "cap_not_enforceable", func(r *qtypes.OpenAIChatRequest) { r.ServiceTier = " DeFaUlT " }},
		{"overlength_default", "cap_not_enforceable", func(r *qtypes.OpenAIChatRequest) { r.ServiceTier = strings.Repeat(" ", 21) + "default" }},
		{"priority", "cap_not_enforceable", func(r *qtypes.OpenAIChatRequest) { r.ServiceTier = "priority" }},
		{"auto", "cap_not_enforceable", func(r *qtypes.OpenAIChatRequest) { r.ServiceTier = "auto" }},
		{"priority_normalized", "cap_not_enforceable", func(r *qtypes.OpenAIChatRequest) { r.ServiceTier = " \tPrIoRiTy\n" }},
		{"auto_normalized", "cap_not_enforceable", func(r *qtypes.OpenAIChatRequest) { r.ServiceTier = " AUTO " }},
		{"unknown_tier", "cap_not_enforceable", func(r *qtypes.OpenAIChatRequest) { r.ServiceTier = "flex" }},
		{"non_streaming", "not_streaming", func(r *qtypes.OpenAIChatRequest) { r.Stream = false }},
		{"usage_type_only", "unsupported_provider_preferences", func(r *qtypes.OpenAIChatRequest) { r.Provider.Usage = ""; r.Provider.UsageType = "credits" }},
		{"billing_only", "unsupported_provider_preferences", func(r *qtypes.OpenAIChatRequest) { r.Provider.Usage = ""; r.Provider.Billing = "credits" }},
		{"usage_type", "unsupported_provider_preferences", func(r *qtypes.OpenAIChatRequest) { r.Provider.UsageType = "credits" }},
		{"billing", "unsupported_provider_preferences", func(r *qtypes.OpenAIChatRequest) { r.Provider.Billing = "credits" }},
		{"max_price", "unsupported_provider_preferences", func(r *qtypes.OpenAIChatRequest) { r.Provider.MaxPrice = map[string]any{"prompt": 1} }},
		{"jurisdiction", "unsupported_provider_preferences", func(r *qtypes.OpenAIChatRequest) { r.Provider.Jurisdiction = "US" }},
		{"sort", "unsupported_provider_preferences", func(r *qtypes.OpenAIChatRequest) { r.Provider.Sort = "price" }},
		{"options", "unsupported_provider_preferences", func(r *qtypes.OpenAIChatRequest) { r.Provider.Options = map[string]any{"x": true} }},
		{"quantizations", "unsupported_provider_preferences", func(r *qtypes.OpenAIChatRequest) { r.Provider.Quantizations = qtypes.StringList{"fp16"} }},
		{"min_privacy", "unsupported_provider_preferences", func(r *qtypes.OpenAIChatRequest) { r.Provider.MinPrivacy = "zdr" }},
		{"country", "unsupported_provider_preferences", func(r *qtypes.OpenAIChatRequest) { r.Provider.Country = "US" }},
		{"headquarters_country", "unsupported_provider_preferences", func(r *qtypes.OpenAIChatRequest) { r.Provider.HeadquartersCountry = "US" }},
		{"provider_country", "unsupported_provider_preferences", func(r *qtypes.OpenAIChatRequest) { r.Provider.ProviderCountry = "US" }},
		{"zdr_false", "unsupported_provider_preferences", func(r *qtypes.OpenAIChatRequest) { r.Provider.ZDR = new(bool) }},
		{"user", "unsupported_attribution", func(r *qtypes.OpenAIChatRequest) { r.User = "user" }},
		{"session_id", "unsupported_attribution", func(r *qtypes.OpenAIChatRequest) { r.SessionID = "session" }},
		{"trace_empty", "unsupported_attribution", func(r *qtypes.OpenAIChatRequest) { r.Trace = map[string]any{} }},
		{"metadata_empty", "unsupported_attribution", func(r *qtypes.OpenAIChatRequest) { r.Metadata = map[string]any{} }},
		{"tags_empty", "unsupported_attribution", func(r *qtypes.OpenAIChatRequest) { r.Tags = &qtypes.RequestTags{} }},
		{"app", "unsupported_attribution", func(r *qtypes.OpenAIChatRequest) { r.App = "app" }},
		{"http_referer", "unsupported_attribution", func(r *qtypes.OpenAIChatRequest) { r.HTTPReferer = "https://example.com" }},
		{"app_categories", "unsupported_attribution", func(r *qtypes.OpenAIChatRequest) { r.AppCategories = []string{"tools"} }},
		{"request_fingerprint", "unsupported_attribution", func(r *qtypes.OpenAIChatRequest) { r.RequestFingerprint = "fingerprint" }},
	}
	for _, route := range []string{"chat.completions", "responses"} {
		for _, tc := range cases {
			t.Run(route+"/"+tc.name, func(t *testing.T) {
				req := stageCFixtureRequest()
				tc.edit(req)
				grantRequest := *req
				grantRequest.ServiceTier = strings.ToLower(strings.TrimSpace(req.ServiceTier))
				c, signer, claims := stageCAdmissionClientForRequest(t, "admission_accepted_response.json", http.StatusOK, nil, route, &grantRequest, nil)
				observed := &observedStageCSigner{Signer: signer}
				c.spendLease.signer = observed
				ctx := fixedStageCContext()
				if reason := admissionWireMissReason(req); reason != tc.reason {
					t.Fatalf("reason=%q want=%q", reason, tc.reason)
				}
				before := stageCCapacity(t, c)
				plan, err := c.PrepareSpendLeaseAdmission(ctx, "sk-stage-c-fixture", req, route, time.UnixMilli(2_000_000_005_000))
				if err != nil || plan != nil {
					t.Fatalf("miss: plan=%v err=%v", plan, err)
				}
				if after := stageCCapacity(t, c); after != before || before != claims.CapMicro {
					t.Fatalf("miss spent capacity: before=%d after=%d cap=%d", before, after, claims.CapMicro)
				}
				if observed.messages.Load() != 0 || observed.digests.Load() != 0 {
					t.Fatal("miss invoked signer")
				}
				// Exercise the ordinary fallback and compare every original field, including
				// attribution and unsupported provider preferences, against its builder.
				calls := 0
				c.httpc.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
					calls++
					var body map[string]json.RawMessage
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
						t.Fatal(err)
					}
					if _, ok := body["spend_lease_admission"]; ok {
						t.Fatal("miss sent admission")
					}
					if string(body["invocation_nonce"]) != `"00112233445566778899aabbccddeeff"` {
						t.Fatal("ordinary nonce lost")
					}
					expected, err := json.Marshal(chatAuthorizeBody(c, stageCFixtureLookupHash, req.IdempotencyKey, req, route))
					if err != nil {
						t.Fatal(err)
					}
					var want map[string]json.RawMessage
					if err := json.Unmarshal(expected, &want); err != nil {
						t.Fatal(err)
					}
					for key, value := range want {
						if string(body[key]) != string(value) {
							t.Fatalf("ordinary field %s lost: %s want %s", key, body[key], value)
						}
					}
					return replayResponse(r, []byte(`{"data":{"authorization_id":"ordinary","request_metadata_version":1}}`)), nil
				})
				if _, err := c.AuthorizeWithRoute(ctx, "sk-stage-c-fixture", req, route); err != nil {
					t.Fatal(err)
				}
				if calls != 1 || stageCCapacity(t, c) != before || observed.messages.Load() != 0 || observed.digests.Load() != 1 {
					t.Fatal("ordinary fallback spent admission capacity or failed to authorize")
				}

			})
		}
	}
}
