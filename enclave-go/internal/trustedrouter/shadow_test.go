package trustedrouter

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/shadowobserve"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/spendlease"
	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

type shadowSeedSigner ed25519.PrivateKey

func (shadowSeedSigner) Kid() string { return "boot" }
func (s shadowSeedSigner) SignDigest(d [32]byte) ([]byte, error) {
	return ed25519.Sign(ed25519.PrivateKey(s), d[:]), nil
}
func TestShadowBootOnlyFrozenWire(t *testing.T) {
	b, err := os.ReadFile("../speculation/testdata/speculation_v1/shadow-refresh-wire.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Items    []shadowobserve.Identity `json:"items"`
		Request  string                   `json:"request_body_exact"`
		Header   string                   `json:"boot_auth_header"`
		Response string                   `json:"response_body_exact"`
		Boot     struct {
			Seed string `json:"test_only_private_seed_hex"`
		} `json:"boot"`
	}
	if json.Unmarshal(b, &f) != nil {
		t.Fatal("fixture")
	}
	seed, _ := hex.DecodeString(f.Boot.Seed)
	c := New("http://127.0.0.1:18080", "gateway-token", &http.Client{Transport: stageDWireRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		body, _ := io.ReadAll(req.Body)
		if string(body) != f.Request || req.URL.Path != shadowobserve.RefreshPath || len(req.Header.Values(spendlease.BootAuthHeader)) != 1 || req.Header.Get(spendlease.BootAuthHeader) != f.Header || req.Header.Get(internalTokenHeader) != "gateway-token" {
			t.Errorf("wire mismatch %s %v", body, req.Header)
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(f.Response)), Header: make(http.Header)}, nil
	})})
	c.ConfigureShadowBoot(shadowSeedSigner(ed25519.NewKeyFromSeed(seed)))
	if c.stageDBootSigner != nil {
		t.Fatal("refresh setup installed ordinary signer")
	}
	results, m := c.RefreshShadow(t.Context(), f.Items)
	if m != nil || len(results) != 1 || results[0].Grant == "" || c.spendLease != nil {
		t.Fatal(results, m)
	}
}
func TestShadowRetryTimingAndByteParity(t *testing.T) {
	var original []byte
	var signature string
	attempt := 0
	c, _ := stageDTestClient(t, func(req *http.Request) (*http.Response, error) {
		attempt++
		body, _ := io.ReadAll(req.Body)
		if attempt == 1 {
			original = body
			signature = req.Header.Get(spendlease.BootAuthHeader)
		} else if !bytes.Equal(body, original) || signature != req.Header.Get(spendlease.BootAuthHeader) {
			t.Fatal("retry bytes changed")
		}
		status := 200
		response := `{"data":{"authorization_id":"auth","workspace_id":"w","api_key_hash":"k","timing":{"total_ms":8,"key_lookup_ms":1,"routing_ms":1,"store_ms":2,"post_commit_ms":1,"spanner_rpcs":5}}}`
		if attempt == 1 {
			status = 503
			response = `{"error":{"type":"storage_error"},"data":{"timing":{"total_ms":9,"key_lookup_ms":1,"routing_ms":1,"store_ms":2,"post_commit_ms":1,"spanner_rpcs":5}}}`
		}
		return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(response))}, nil
	})
	c.authorizeRetry = retryPolicy{attempts: 2, sleep: func(context.Context, time.Duration) error { return nil }}
	healthObserver := &reviewVerdictObserver{testShadowObserver: newTestShadowObserver()}
	c.shadow = healthObserver
	ctx := WithRequestLogID(WithAuthorizationInvocation(t.Context()), "rlog_"+strings.Repeat("a", 32))
	req := &qtypes.OpenAIChatRequest{Model: "fixture-text"}
	if _, err := c.AuthorizeWithRoute(ctx, "key", req, "chat.completions"); err != nil {
		t.Fatal(err)
	}
	if len(healthObserver.statuses) != 1 || healthObserver.statuses[0] != 503 {
		t.Fatal("retry did not close health", healthObserver.statuses)
	}
	if attempt != 2 {
		t.Fatal(attempt)
	}
	var rec shadowobserve.Record
	for len(c.shadow.Records()) > 0 {
		rec = <-c.shadow.Records()
	}
	if len(rec.Attempts) != 2 || rec.Attempts[0].Timing == nil || rec.Attempts[0].Timing.TotalMS != 9 || rec.Attempts[1].Timing.TotalMS != 8 || rec.InvocationNonce == "" || rec.AuthorizationID != "auth" || rec.DenialID == "" {
		t.Fatalf("%+v", rec)
	}
	if rec.Decision.Eligible || rec.MeasuredP != nil {
		t.Fatal("self qualified")
	}
}
func TestShadowOffBodyAndSignatureParity(t *testing.T) {
	var captures [][]byte
	var headers []string
	c, _ := stageDTestClient(t, func(req *http.Request) (*http.Response, error) {
		b, _ := io.ReadAll(req.Body)
		captures = append(captures, b)
		headers = append(headers, req.Header.Get(spendlease.BootAuthHeader))
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"data":{"authorization_id":"auth","workspace_id":"w","api_key_hash":"k"}}`))}, nil
	})
	for _, mode := range []shadowobserve.Mode{shadowobserve.Off, shadowobserve.Shadow} {
		ctx, cancel := context.WithCancel(t.Context())
		if mode == shadowobserve.Shadow {
			c.ConfigureSpeculation(ctx, newTestShadowObserver())
		} else {
			c.ConfigureSpeculation(ctx, nil)
		}
		inv := &authorizationInvocation{nonce: "fixed-nonce"}
		inv.once.Do(func() {})
		ctx = context.WithValue(ctx, authorizationInvocationContextKey{}, inv)
		if _, _, err := c.authorizeAtDecodeSeam(ctx, strings.Repeat("a", 64), map[string]any{"idempotency_key": "fixed-key"}, spendlease.EstimateRequest{}); err != nil {
			t.Fatal(err)
		}
		cancel()
	}
	if !bytes.Equal(captures[0], captures[1]) || headers[0] != headers[1] {
		t.Fatal("off/shadow body or signature changed")
	}
}
func TestShadowMissFailuresNeverTouchOrdinary(t *testing.T) {
	c := New("http://127.0.0.1:18080", "", nil)
	id := shadowobserve.Identity{KeyID: "k", WorkspaceID: "w", LookupDigest: strings.Repeat("a", 64)}
	if _, m := c.RefreshShadow(t.Context(), nil); m == nil {
		t.Fatal("empty")
	}
	if _, m := c.RefreshShadow(t.Context(), []shadowobserve.Identity{id}); m.Code != "boot-unavailable" {
		t.Fatal(m)
	}
	c.stageDBootSigner = shadowBadSigner{}
	if _, m := c.RefreshShadow(t.Context(), []shadowobserve.Identity{id}); m.Code != "boot-unavailable" {
		t.Fatal(m)
	}
	c.stageDBootSigner = shadowSeedSigner(ed25519.NewKeyFromSeed(make([]byte, 32)))
	c.httpc = &http.Client{Transport: stageDWireRoundTripFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("transport") })}
	if _, m := c.RefreshShadow(t.Context(), []shadowobserve.Identity{id}); m.Code != "transport-unavailable" {
		t.Fatal(m)
	}
	c.httpc = &http.Client{Transport: stageDWireRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 503, Header: make(http.Header), Body: io.NopCloser(&shadowReadFailure{})}, nil
	})}
	if _, m := c.RefreshShadow(t.Context(), []shadowobserve.Identity{id}); m.Code != "malformed-response" {
		t.Fatal(m)
	}
	var nilClient *Client
	nilClient.ConfigureSpeculation(t.Context(), nil)
	if nilClient.Speculation() != nil {
		t.Fatal("nil")
	}
	ctx := t.Context()
	if ctx != ctx {
		t.Fatal("off allocated")
	}
	c.shadow = newTestShadowObserver()
	if c.Speculation() == nil {
		t.Fatal("no decision")
	}
	if _, done := c.beginShadowAttempt(ctx, spendlease.AuthorizePath); done != nil {
		t.Fatal("no execution")
	}
	if p, e := c.PrepareSpendLeaseAdmission(ctx, "k", nil, "", time.Now()); p != nil || e != nil {
		t.Fatal("legacy admission")
	}
}

type shadowBadSigner struct{}

func (shadowBadSigner) Kid() string                         { return "boot" }
func (shadowBadSigner) SignDigest([32]byte) ([]byte, error) { return nil, errors.New("sign") }

type shadowReadFailure struct{}

func (*shadowReadFailure) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
func TestShadowTimingBodyBounded(t *testing.T) {
	for _, raw := range []string{`{"data":{"timing":null}}`, strings.Repeat("x", (1<<20)+1)} {
		sample := &shadowAttempt{}
		r := &shadowTimingBody{ReadCloser: io.NopCloser(strings.NewReader(raw)), sample: sample}
		_, _ = io.Copy(io.Discard, r)
		_ = r.Close()
		if sample.timing != nil || r.raw != nil {
			t.Fatal("retained raw")
		}
	}
	if s, _ := shadowError(errors.New("private")); s != 503 {
		t.Fatal(s)
	}
}

type testShadowObserver struct {
	origin  time.Time
	records chan shadowobserve.Record
}

func newTestShadowObserver() *testShadowObserver {
	return &testShadowObserver{time.Now(), make(chan shadowobserve.Record, 32)}
}
func (s *testShadowObserver) Mono() time.Duration                              { return time.Since(s.origin) }
func (s *testShadowObserver) Emit(r shadowobserve.Record)                      { s.records <- r }
func (s *testShadowObserver) Release(shadowobserve.Identity, string)           {}
func (s *testShadowObserver) Run(ctx context.Context, _ shadowobserve.Refresh) { <-ctx.Done() }
func (s *testShadowObserver) Excluded(string) *shadowobserve.Execution {
	return shadowobserve.NewExecution(s, shadowobserve.NewID(), shadowobserve.Decision{Reason: "grant_missing"}, shadowobserve.Identity{}, shadowobserve.Route{})
}
func (s *testShadowObserver) ObserveAuthorized(shadowobserve.Identity)   {}
func (s *testShadowObserver) ObserveVerdict(string, int, string, string) {}
func (s *testShadowObserver) Suppressed(string)                          {}
func (s *testShadowObserver) Records() <-chan shadowobserve.Record       { return s.records }

func TestShadowSelfQualificationPredecisionBeforeNetwork(t *testing.T) {
	observer := newTestShadowObserver()
	c, _ := stageDTestClient(t, func(*http.Request) (*http.Response, error) {
		select {
		case r := <-observer.Records():
			if r.Kind != "predecision" || r.Decision.Eligible {
				t.Error("self qualification: predecision must precede current success")
			}
		default:
			t.Error("self qualification: authorize began before immutable predecision")
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"data":{"authorization_id":"auth","workspace_id":"w","api_key_hash":"k"}}`))}, nil
	})
	c.shadow = observer
	if _, _, err := c.authorizeAtDecodeSeam(t.Context(), strings.Repeat("a", 64), map[string]any{"idempotency_key": "fixed"}, spendlease.EstimateRequest{}); err != nil {
		t.Fatal(err)
	}
}

func TestShadowAuthenticatedReasonNormalization(t *testing.T) {
	for _, tc := range []struct {
		status     int
		kind, want string
	}{{401, "invalid_api_key", "key_invalid"}, {402, "key_limit_exceeded", "key_limit_exceeded"}, {429, "key_window_limit_exceeded", "key_window_limit_exceeded"}, {403, "forbidden", "billing_paused"}, {401, "unknown_api_key", ""}} {
		status, reason := shadowError(&ControlPlaneError{StatusCode: tc.status, Type: tc.kind, Message: "billing_paused"})
		if status != tc.status || reason != tc.want {
			t.Fatal(tc, status, reason)
		}
	}
}
