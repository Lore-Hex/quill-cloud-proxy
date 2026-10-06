package trustedrouter

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/shadowobserve"
)

func TestLiteralAuthorizeErrorEnvelopes(t *testing.T) {
	raw, err := os.ReadFile("../speculation/testdata/speculation_v1/authorize-error-envelopes.json")
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	if hex.EncodeToString(digest[:]) != "a2f388da8afd619793fedfb78013dcdf61843ae0a9b5dca936647ca8582746d4" {
		t.Fatal("fixture changed")
	}
	var fixture struct {
		Cases map[string]struct {
			Path       string
			Status     int
			RetryAfter *string `json:"retry_after"`
			Body       string  `json:"body_exact"`
		}
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Cases) != 5 {
		t.Fatal("missing literal case")
	}
	for name, tc := range fixture.Cases {
		t.Run(name, func(t *testing.T) {
			c, _ := stageDTestClient(t, func(*http.Request) (*http.Response, error) {
				h := make(http.Header)
				if tc.RetryAfter != nil {
					h.Set("Retry-After", *tc.RetryAfter)
				}
				return &http.Response{StatusCode: tc.Status, Header: h, Body: io.NopCloser(strings.NewReader(tc.Body))}, nil
			})
			c.shadow = newTestShadowObserver()
			sample := &shadowAttempt{}
			ctx := context.WithValue(t.Context(), shadowAttemptKey{}, sample)
			_, err := c.postJSONBytesAtEndpoint(ctx, tc.Path, []byte(`{}`), nil, -1)
			var cp *ControlPlaneError
			if !errors.As(err, &cp) || cp.StatusCode != tc.Status {
				t.Fatal("status", err)
			}
			kind, want := name, ""
			switch name {
			case "invalid_api_key":
				want = "key_invalid"
			case "insufficient_credits":
				want = "credit_exhausted"
			case "billing_paused":
				kind, want = "forbidden", "billing_paused"
			case "storage_unavailable", "storage_conflict":
				kind, want = "service_unavailable", "infrastructure_error"
			}
			status, reason := shadowError(cp)
			if cp.Type != kind || status != tc.Status || reason != want {
				t.Fatal("classification", cp.Type, status, reason)
			}
			retry := ""
			if tc.RetryAfter != nil {
				retry = *tc.RetryAfter
			}
			if cp.RetryAfter != retry {
				t.Fatal("retry-after", cp.RetryAfter)
			}
			if cp.ShadowScope != (shadowobserve.Identity{}) || cp.RateScope != "" {
				t.Fatal("scope invented")
			}
			if sample.timing == nil || *sample.timing != (shadowobserve.RouterTiming{}) {
				t.Fatal("typed timing missing", sample.timing)
			}
		})
	}
}
