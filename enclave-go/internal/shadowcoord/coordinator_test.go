package shadowcoord

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/shadowobserve"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/speculation"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/spendlease"
)

type wireFixture struct {
	Items         []Identity               `json:"items"`
	Request       string                   `json:"request_body_exact"`
	RequestDigest string                   `json:"request_body_sha256"`
	Header        string                   `json:"boot_auth_header"`
	Response      string                   `json:"response_body_exact"`
	Grant         string                   `json:"grant_jws"`
	Claims        map[string]any           `json:"grant_claims"`
	Context       map[string]any           `json:"context"`
	Keys          []speculation.TrustedKey `json:"trusted_test_keys"`
	Boot          struct {
		Seed string `json:"test_only_private_seed_hex"`
	} `json:"boot"`
	Misses []struct {
		Name   string `json:"name"`
		Status int    `json:"response_status"`
		Body   string `json:"response_body_exact"`
	} `json:"misses"`
}

func fixture(t testing.TB) wireFixture {
	t.Helper()
	b, err := os.ReadFile("../speculation/testdata/speculation_v1/shadow-refresh-wire.json")
	if err != nil {
		t.Fatal(err)
	}
	if got := sha256.Sum256(b); hex.EncodeToString(got[:]) != "ad8d4161013cdf442aa4f221abf06c418ee15353d646487ac95ac8419d8aef39" {
		t.Fatal("fixture digest")
	}
	var f wireFixture
	if err = json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	f.Context = normalize(f.Context).(map[string]any)
	f.Claims = normalize(f.Claims).(map[string]any)
	return f
}

type fixtureSigner ed25519.PrivateKey

func (fixtureSigner) Kid() string { return "boot" }
func (s fixtureSigner) SignDigest(d [32]byte) ([]byte, error) {
	return ed25519.Sign(ed25519.PrivateKey(s), d[:]), nil
}
func TestFrozenRefreshRoundTrip(t *testing.T) {
	f := fixture(t)
	b, m := EncodeBatch(f.Items)
	if m != nil || string(b) != f.Request {
		t.Fatalf("wire %s %v", b, m)
	}
	h := sha256.Sum256(b)
	if hex.EncodeToString(h[:]) != f.RequestDigest {
		t.Fatal("request digest")
	}
	seed, _ := hex.DecodeString(f.Boot.Seed)
	proof, err := spendlease.SignAuthorize(fixtureSigner(ed25519.NewKeyFromSeed(seed)), "POST", RefreshPath, b)
	if err != nil || proof.HeaderValue() != f.Header {
		t.Fatalf("boot auth %v %s", err, proof.HeaderValue())
	}
	items, m := DecodeBatch(200, []byte(f.Response), f.Items)
	if m != nil || len(items) != 1 || items[0].Grant != f.Grant {
		t.Fatal(items, m)
	}
	grant, err := speculation.VerifyGrant(items[0].Grant, f.Keys, f.Context, int64(2000), true)
	if err != nil {
		t.Fatal(err)
	}
	claims, _ := grant.Claims()
	if !reflect.DeepEqual(claims, f.Claims) {
		t.Fatal("claims differ")
	}
	for _, v := range f.Misses {
		t.Run(v.Name, func(t *testing.T) {
			items, batch := DecodeBatch(v.Status, []byte(v.Body), f.Items)
			if batch != nil {
				if batch.Status != v.Status || batch.Code == "malformed-response" {
					t.Fatal(batch)
				}
			} else if len(items) != 1 || items[0].Miss == nil || items[0].Miss.Status != v.Status {
				t.Fatal(items)
			}
		})
	}
}
func TestUnknownMissTyping(t *testing.T) {
	f := fixture(t)
	for _, status := range []int{400, 401, 413, 503, 599} {
		_, m := DecodeBatch(status, []byte(`{"miss":"future-code"}`), f.Items)
		if m == nil || m.Status != status || m.Code != "future-code" {
			t.Fatal(m)
		}
	}
	b := strings.Replace(f.Response, `"grant":"`+f.Grant+`"`, `"miss":"future-item-code"`, 1)
	r, m := DecodeBatch(200, []byte(b), f.Items)
	if m != nil || r[0].Miss.Code != "future-item-code" {
		t.Fatal(r, m)
	}
}

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (f *fakeClock) Now() time.Time      { f.mu.Lock(); defer f.mu.Unlock(); return f.now }
func (f *fakeClock) add(d time.Duration) { f.mu.Lock(); defer f.mu.Unlock(); f.now = f.now.Add(d) }
func setup(t testing.TB) (*Coordinator, *fakeClock, speculation.ParsedRequest, Refresh, wireFixture) {
	f := fixture(t)
	route := f.Context["route"].(map[string]any)
	cert := speculation.AdapterCertificate{Route: route, BoundAlgorithm: speculation.ConservativeUTF8Bytes, FramingKnown: true, HardOutputCap: true, SingleAttempt: true, NoHiddenTools: true, NoHiddenReasoning: true, VendorPricesBounded: true}
	local := speculation.LocalContext{Bindings: f.Context, Certificates: []speculation.AdapterCertificate{cert}, RequestPolicyHash: route["routing_policy_hash"].(string), OwnerBootID: "boot", OwnerBootCount: 1, PilotAllowed: true, PaidProvenance: true, KeyEligible: true, BootVerified: true, PolicyFresh: true, StageDEnabled: true}
	health := speculation.LocalHealth{WorkspaceID: "w", KeyID: "k", Provider: "fixture-provider", Workspace: speculation.ScopeHealth{Known: true, Healthy: true}, Key: speculation.ScopeHealth{Known: true, Healthy: true}, ProviderKnown: true, ProviderHealthy: true, InfrastructureHealthy: true}
	clock := &fakeClock{now: time.Unix(2000, 0)}
	c := New(Shadow, Config{Keys: f.Keys, Evidence: []Evidence{{Identity: f.Items[0], Local: local, Health: health, RemoteKnown: true, ValidUntil: 2100}}}, clock)
	body := ParseRequest([]byte(`{"model":"fixture-text","stream":true,"messages":[{"role":"user","content":"secret-prompt"}],"max_tokens":512,"provider":{"usage":"Credits"}}`))
	req := speculation.ParsedRequest{Body: body, RouteType: "chat.completions", CallerIdempotency: speculation.CaptureCallerIdempotency(false, body)}
	refresh := func(context.Context, []Identity) ([]Result, *Miss) {
		return []Result{{Identity: f.Items[0], Grant: f.Grant}}, nil
	}
	return c, clock, req, refresh, f
}
func warm(c *Coordinator, f wireFixture, r Refresh) {
	c.ObserveAuthorized(f.Items[0])
	c.RefreshOnce(context.Background(), r)
}
func TestSelfQualificationAndImmutableDecision(t *testing.T) {
	c, _, req, refresh, f := setup(t)
	before := c.Predecision(f.Items[0].LookupDigest, req)
	if before.Decision().Eligible {
		t.Fatal("self qualification")
	}
	warm(c, f, refresh)
	before.StartAuthorize("nonce", "denial")
	before.EndAuthorize("auth", 200)
	if before.Decision().Eligible {
		t.Fatal("current response rewrote decision")
	}
	next := c.Predecision(f.Items[0].LookupDigest, req)
	if !next.Decision().Eligible {
		t.Fatal(next.Decision())
	}
	c.ObserveVerdict(f.Items[0].LookupDigest, 402, "", "")
	c.RefreshOnce(context.Background(), refresh)
	if !next.Decision().Eligible {
		t.Fatal("denial rewrote immutable decision")
	}
	if got := c.Predecision(f.Items[0].LookupDigest, req).Decision(); got.Eligible || got.Reason != "workspace_latched" {
		t.Fatal(got)
	}
}
func TestPermitRefreshAndConcurrency(t *testing.T) {
	c, _, req, r, f := setup(t)
	warm(c, f, r)
	first := c.Predecision(f.Items[0].LookupDigest, req)
	if !first.Decision().Eligible {
		t.Fatal(first.Decision())
	}
	if got := c.Predecision(f.Items[0].LookupDigest, req).Decision(); got.Reason != "simulated-concurrency" {
		t.Fatal(got)
	}
	first.EndAuthorize("auth", 200)
	c.RefreshOnce(context.Background(), r)
	if got := c.Predecision(f.Items[0].LookupDigest, req).Decision(); got.Reason != "simulated-permits-exhausted" {
		t.Fatal(got)
	}
}
func TestLateGrantOriginalDeadline(t *testing.T) {
	c, clock, req, r, f := setup(t)
	clock.add(27 * time.Second)
	warm(c, f, r)
	clock.add(time.Second)
	c.RefreshOnce(context.Background(), r)
	if got := c.Predecision(f.Items[0].LookupDigest, req).Decision(); got.Eligible || got.Reason != "start_deadline" {
		t.Fatal(got)
	}
}
func TestConcurrentRenewalDenyAndNoTimerRecovery(t *testing.T) {
	c, clock, req, r, f := setup(t)
	warm(c, f, r)
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(2)
		go func() { defer wg.Done(); c.RefreshOnce(context.Background(), r) }()
		go func() { defer wg.Done(); c.ObserveVerdict(f.Items[0].LookupDigest, 402, "", "") }()
	}
	wg.Wait()
	clock.add(6 * time.Second)
	c.Suppressed("original")
	if got := c.Predecision(f.Items[0].LookupDigest, req).Decision(); got.Reason != "workspace_latched" {
		t.Fatal(got)
	}
}
func TestRetryFailureCannotBeReopenedBySuccess(t *testing.T) {
	c, _, req, r, f := setup(t)
	warm(c, f, r)
	c.ObserveVerdict(f.Items[0].LookupDigest, 503, "infrastructure_error", "")
	c.ObserveAuthorized(f.Items[0])
	c.RefreshOnce(context.Background(), r)
	if got := c.Predecision(f.Items[0].LookupDigest, req).Decision(); got.Reason != "health_unhealthy" {
		t.Fatal(got)
	}
}
func TestMode(t *testing.T) {
	for _, raw := range []string{"", "off", "shadow", "enforce", "garbage", "SHADOW", " off"} {
		m, e := ParseMode(raw)
		valid := raw == "" || raw == "off" || raw == "shadow"
		if (e == nil) != valid {
			t.Fatal(raw, m, e)
		}
		if valid && raw != "shadow" && New(m, Config{}, nil) != nil {
			t.Fatal("off allocated")
		}
	}
}
func TestCallerIdempotencyAndExclusions(t *testing.T) {
	for _, kind := range []string{"header", "body", "tools", "responses", "advisor", "fusion", "confidential", "receipts"} {
		t.Run(kind, func(t *testing.T) {
			c, _, req, r, f := setup(t)
			warm(c, f, r)
			switch kind {
			case "header":
				req.CallerIdempotency = speculation.CaptureCallerIdempotency(true, req.Body)
			case "body":
				req.Body["idempotency_key"] = ""
				req.CallerIdempotency = speculation.CaptureCallerIdempotency(false, req.Body)
				delete(req.Body, "idempotency_key")
			case "tools":
				req.Body["tools"] = []any{}
			case "confidential":
				req.ConfidentialOnly = true
			case "receipts":
				req.InferenceReceipts = true
			default:
				req.RouteType = kind
			}
			if got := c.Predecision(f.Items[0].LookupDigest, req).Decision(); got.Eligible {
				t.Fatal(kind, got)
			}
		})
	}
}
func TestSuppressionJoinsAndTelemetryAllowlist(t *testing.T) {
	c, _, req, r, f := setup(t)
	warm(c, f, r)
	x := c.Predecision(f.Items[0].LookupDigest, req)
	x.StartAuthorize("nonce", "rlog_original")
	x.EndAuthorize("", 402)
	x.Finish()
	c.Suppressed("rlog_original")
	c.Suppressed("rlog_original")
	ids := map[string]bool{}
	suppressed := 0
	for len(c.records) > 0 {
		rec := <-c.records
		if ids[rec.ObservationID] {
			t.Fatal("duplicate observation")
		}
		ids[rec.ObservationID] = true
		b, _ := json.Marshal(rec)
		for _, secret := range []string{`"prompt"`, "secret-prompt", "BYOK", "raw_body", "headers", "messages", "grant_jws"} {
			if strings.Contains(string(b), secret) {
				t.Fatal("telemetry content", string(b))
			}
		}
		if rec.Kind == "billing_backoff_suppressed" {
			suppressed++
			if rec.OriginalDenialID != "rlog_original" || rec.Decision != nil || rec.MeasuredP != nil {
				t.Fatal(rec)
			}
		}
	}
	if suppressed != 2 {
		t.Fatal(suppressed)
	}
}

func TestBoundedHotSetAndWorkerLoss(t *testing.T) {
	c := New(Shadow, Config{}, nil)
	for i := 0; i < MaxIdentities+1; i++ {
		c.ObserveAuthorized(Identity{KeyID: strconv.Itoa(i), WorkspaceID: "w", LookupDigest: strings.Repeat("a", 64)})
	}
	c.ObserveAuthorized(Identity{})
	if len(c.entries) != 256 || len(c.batch()) != 64 {
		t.Fatal("unbounded")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	c.Run(ctx, nil)
	var nilCoordinator *Coordinator
	nilCoordinator.Run(ctx, nil)
	nilCoordinator.ObserveAuthorized(Identity{})
	nilCoordinator.ObserveVerdict("", 503, "", "")
	nilCoordinator.Suppressed("")
	if nilCoordinator.Predecision("", speculation.ParsedRequest{}) != nil {
		t.Fatal("nil")
	}
	for range 600 {
		c.Suppressed("original")
	}
	if c.Dropped() == 0 || len(c.Records()) != 100 {
		t.Fatal("loss not bounded")
	}
	if ParseRequest([]byte("bad")) != nil || ParseRequest([]byte(strings.Repeat("x", (1<<20)+1))) != nil {
		t.Fatal("parser bound")
	}
}
func TestRefreshFailuresAndEvidence(t *testing.T) {
	for _, kind := range []string{"batch", "item", "unconfigured", "policy", "invalid", "clock", "empty", "unknown"} {
		t.Run(kind, func(t *testing.T) {
			c, clock, req, r, f := setup(t)
			switch kind {
			case "batch":
				r = func(context.Context, []Identity) ([]Result, *Miss) {
					return nil, &Miss{Status: 503, Code: "future-code"}
				}
			case "item":
				r = func(context.Context, []Identity) ([]Result, *Miss) {
					return []Result{{Identity: f.Items[0], Miss: &Miss{Status: 200, Code: "future-item"}}}, nil
				}
			case "policy":
				clock.add(101 * time.Second)
			case "invalid":
				r = func(context.Context, []Identity) ([]Result, *Miss) {
					return []Result{{Identity: f.Items[0], Grant: "bad"}}, nil
				}
			case "clock":
				c.config.ClockUncertainty = 40 * time.Second
			case "empty":
				c.RefreshOnce(t.Context(), func(context.Context, []Identity) ([]Result, *Miss) { t.Fatal("no hot keys"); return nil, nil })
				return
			case "unknown":
				r = func(context.Context, []Identity) ([]Result, *Miss) {
					return []Result{{Identity: Identity{KeyID: "unknown"}, Grant: f.Grant}}, nil
				}
			case "unconfigured":
				c = New(Shadow, Config{}, clock)
			}
			warm(c, f, r)
			if got := c.Predecision(f.Items[0].LookupDigest, req).Decision(); got.Eligible {
				t.Fatal(got)
			}
		})
	}
	c, _, _, _, _ := setup(t)
	c.setMiss(Identity{}, &Miss{})
}
func TestAdmissionUncertaintyAndBounds(t *testing.T) {
	for _, kind := range []string{"remote", "tier2-budget", "workspace-budget", "slot-budget", "fleet-budget", "journal", "ambiguous", "preferences", "prefix", "history", "policy", "key-denial", "generic-400"} {
		t.Run(kind, func(t *testing.T) {
			c, clock, req, r, f := setup(t)
			warm(c, f, r)
			s := c.entries[f.Items[0]]
			switch kind {
			case "remote":
				s.evidence.RemoteKnown = false
			case "tier2-budget":
				s.evidence.Local.Bindings["tier_ceiling_micro"] = int64(100000000)
				s.evidence.WorkspaceRetained = 250000
			case "workspace-budget":
				s.evidence.WorkspaceRetained = 1000000
			case "slot-budget":
				s.evidence.SlotRetained = 1000000
			case "fleet-budget":
				s.evidence.FleetRetained = 10000000
			case "journal":
				for i := 0; i < 4096; i++ {
					s.consumed[strconv.Itoa(i)] = true
				}
			case "ambiguous":
				id := f.Items[0]
				id.KeyID = "other"
				c.entries[id] = &state{}
				c.index(id)
			case "preferences":
				req.Body["provider"].(map[string]any)["only"] = []any{"different"}
			case "prefix":
				s.evidence.Local.Certificates[0].SystemPrefix = []string{"hidden"}
			case "history":
				clock.add(21 * time.Second)
			case "policy":
				s.evidenceDeadline = clock.Now()
			case "key-denial":
				c.ObserveVerdict(f.Items[0].LookupDigest, 401, "key_revoked", "")
			case "generic-400":
				c.ObserveVerdict(f.Items[0].LookupDigest, 400, "validation", "")
			}
			got := c.Predecision(f.Items[0].LookupDigest, req).Decision()
			if got.Eligible != (kind == "generic-400") {
				t.Fatal(kind, got)
			}
		})
	}
}
func TestMalformedRefreshBounds(t *testing.T) {
	f := fixture(t)
	for _, items := range [][]Identity{nil, make([]Identity, 65), {{KeyID: "!"}}} {
		if _, m := EncodeBatch(items); m == nil {
			t.Fatal("invalid batch")
		}
	}
	bodies := []string{"bad", `{}`, `{"miss":"secret with spaces"}`, strings.Repeat("x", MaxResponseBytes+1), strings.Replace(f.Response, `"authority":"shadow-only"`, `"authority":"real"`, 1), strings.Replace(f.Response, `"key_id":"k"`, `"key_id":"other"`, 1), strings.Replace(f.Response, `"grant":"`+f.Grant+`"`, `"grant":"`+f.Grant+`","miss":"also"`, 1)}
	for _, b := range bodies {
		if _, m := DecodeBatch(200, []byte(b), f.Items); m == nil || m.Code != "malformed-response" {
			t.Fatal(m)
		}
	}
}
func TestExecutionBoundedAndNil(t *testing.T) {
	var x *Execution
	x.StartAuthorize("", "")
	x.EndAuthorize("", 402)
	x.ObserveAttempt(0, 200, nil)
	x.ProviderStart(Route{}, true)
	x.ProviderEnd(true)
	x.Content(false)
	x.Finish()
	if x.Now() != 0 {
		t.Fatal("nil")
	}
	if WithExecution(t.Context(), nil) != t.Context() || FromContext(nil) != nil || FromContext(t.Context()) != nil {
		t.Fatal("context")
	}
	c, _, req, r, f := setup(t)
	warm(c, f, r)
	x = c.Predecision(f.Items[0].LookupDigest, req)
	if FromContext(WithExecution(t.Context(), x)) != x {
		t.Fatal("context")
	}
	for range 20 {
		x.ObserveAttempt(x.Now(), 503, nil)
	}

	x.StartAuthorize("nonce", "")
	x.EndAuthorize("auth", 200)
	x.ProviderStart(Route{Endpoint: "ep1", Provider: "fixture-provider", Model: "fixture-text"}, true)
	x.Content(false)
	x.Content(false)
	x.Content(true)
	x.Content(true)
	x.Finish()
	x.Finish()
	var stream ContentStream
	if stream.Feed([]byte("data:" + strings.Repeat("x", 65537) + "\n")) {
		t.Fatal("oversize content")
	}
	if (&ContentStream{}).Feed([]byte("data: bad\n")) {
		t.Fatal("malformed content")
	}
}

var EncodeBatch = shadowobserve.EncodeBatch
var DecodeBatch = shadowobserve.DecodeBatch
var ParseMode = shadowobserve.ParseMode
var WithExecution = shadowobserve.WithExecution
var FromContext = shadowobserve.FromContext
var DecodeTiming = shadowobserve.DecodeTiming
var Union = shadowobserve.Union
var Intersection = shadowobserve.Intersection

type ContentStream = shadowobserve.ContentStream
type Interval = shadowobserve.Interval

func TestInfrastructureBreakerIsKeyBootScoped(t *testing.T) {
	c, _, req, r, f := setup(t)
	warm(c, f, r)
	other := Identity{KeyID: "other", LookupDigest: strings.Repeat("b", 64), WorkspaceID: "w"}
	c.ObserveAuthorized(other)
	c.ObserveVerdict(other.LookupDigest, 503, "transport_error", "")
	if got := c.Predecision(f.Items[0].LookupDigest, req).Decision(); !got.Eligible {
		t.Fatal("other key infrastructure failure fenced healthy key", got)
	}
	c.ObserveVerdict("", 503, "transport_error", "")
	if got := c.Predecision(f.Items[0].LookupDigest, req).Decision(); got.Reason != "health_unhealthy" {
		t.Fatal("unresolved boot health", got)
	}
}
func TestTrustedConfigurationCopiedAndMalformedFailsClosed(t *testing.T) {
	c, _, req, r, f := setup(t)
	warm(c, f, r)
	f.Context["key_id"] = "changed"
	if got := c.Predecision(f.Items[0].LookupDigest, req).Decision(); !got.Eligible {
		t.Fatal("configuration aliased", got)
	}
	invalid := Config{Evidence: []Evidence{{Identity: f.Items[0], Local: speculation.LocalContext{Bindings: map[string]any{"unsupported": make(chan int)}}}}}
	if c := New(Shadow, invalid, nil); len(c.entries) != 0 {
		t.Fatal("unfreezable evidence accepted")
	}
	b := ParseRequest([]byte(`{"integer":9007199254740993,"fraction":0.5}`))
	if b["integer"] != int64(9007199254740993) || b["fraction"] != 0.5 {
		t.Fatal("numeric type loss", b)
	}
}

func TestRefreshGrantCannotCrossIdentityWithMisboundConfiguration(t *testing.T) {
	c, clock, req, _, f := setup(t)
	other := Identity{KeyID: "other", WorkspaceID: "w", LookupDigest: strings.Repeat("b", 64)}
	cfg := c.config
	cfg.Evidence[0].Identity = other
	c = New(Shadow, cfg, clock)
	c.ObserveAuthorized(other)
	c.RefreshOnce(t.Context(), func(context.Context, []Identity) ([]Result, *Miss) {
		return []Result{{Identity: other, Grant: f.Grant}}, nil
	})
	if got := c.Predecision(other.LookupDigest, req).Decision(); got.Eligible || got.Reason != "grant-identity-mismatch" {
		t.Fatal("cross-identity grant accepted", got)
	}
}
