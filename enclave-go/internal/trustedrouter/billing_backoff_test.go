package trustedrouter

import (
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func billingTestError() *ControlPlaneError {
	return &ControlPlaneError{Path: "/internal/gateway/authorize", StatusCode: 402, Type: "insufficient_credits", Message: "Insufficient credits", RetryAfter: "3", Body: "not retained"}
}

func TestBillingBackoffTTL(t *testing.T) {
	c := NewBillingBackoff(5*time.Second, 2)
	now := time.Unix(100, 0)
	key := LookupHash("key-one")
	if !c.Remember(key, "credential", "request", false, billingTestError(), now) {
		t.Fatal("denial not stored")
	}
	for _, delta := range []time.Duration{0, 4 * time.Second, 5*time.Second - time.Nanosecond} {
		got, hit := c.Get(key, false, now.Add(delta))
		if !hit || got.Error.Message != "Insufficient credits" || got.Error.Body != "" {
			t.Fatalf("live denial = %+v, hit=%v", got, hit)
		}
	}
	if c.Remember(key, "credential", "concurrent", false, billingTestError(), now.Add(4*time.Second)) {
		t.Fatal("concurrent denial replaced window")
	}
	if _, hit := c.Get(key, false, now.Add(5*time.Second)); hit {
		t.Fatal("window extended on hit: entry live at original expiry")
	}
}

func TestBillingBackoffScope(t *testing.T) {
	now := time.Now()
	for _, tc := range []struct {
		name       string
		err        error
		idempotent bool
		want       bool
	}{
		{"credits", billingTestError(), false, true},
		{"key limit", &ControlPlaneError{Path: "/internal/gateway/authorize", StatusCode: 402, Type: "key_limit"}, false, false},
		{"budget", &ControlPlaneError{Path: "/internal/gateway/authorize", StatusCode: 402, Type: "budget_exceeded"}, false, false},
		{"bare 402", &ControlPlaneError{Path: "/internal/gateway/authorize", StatusCode: 402}, false, false},
		{"validate", &ControlPlaneError{Path: "/internal/gateway/validate", StatusCode: 402, Type: "insufficient_credits"}, false, false},
		{"server", &ControlPlaneError{Path: "/internal/gateway/authorize", StatusCode: 503, Type: "insufficient_credits"}, false, false},
		{"timeout", errors.New("timeout"), false, false},
		{"idempotent", billingTestError(), true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := NewBillingBackoff(5*time.Second, 2)
			if got := c.Remember(LookupHash("key"), "id", "request", tc.idempotent, tc.err, now); got != tc.want {
				t.Fatalf("Remember = %v, want %v", got, tc.want)
			}
		})
	}
	c := NewBillingBackoff(5*time.Second, 2)
	c.Remember(LookupHash("key"), "id", "request", false, billingTestError(), now)
	if _, hit := c.Get(LookupHash("key"), true, now); hit {
		t.Fatal("idempotent request hit cache")
	}
	if _, hit := c.Get(LookupHash("other"), false, now); hit {
		t.Fatal("entry shared across credentials")
	}
	if c.Remember("raw-secret-key", "id", "request", false, billingTestError(), now) {
		t.Fatal("stored raw key")
	}
	disabled := NewBillingBackoff(0, 2)
	if disabled.Remember(LookupHash("key"), "id", "request", false, billingTestError(), now) {
		t.Fatal("disabled cache stored entry")
	}
}

func TestBillingBackoffCapExpiryFirst(t *testing.T) {
	c := NewBillingBackoff(5*time.Second, 2)
	now := time.Unix(100, 0)
	a, b, d := LookupHash("a"), LookupHash("b"), LookupHash("d")
	c.Remember(a, "a", "a", false, billingTestError(), now)
	c.Remember(b, "b", "b", false, billingTestError(), now.Add(time.Second))
	c.Get(a, false, now.Add(4*time.Second)) // hits do not change eviction order
	c.Remember(d, "d", "d", false, billingTestError(), now.Add(5*time.Second))
	if len(c.entries) != 2 || c.entries[a] != nil || c.entries[b] == nil || c.entries[d] == nil {
		t.Fatal("expired entry not evicted first")
	}
	c.Remember(a, "a", "new", false, billingTestError(), now.Add(5*time.Second))
	if len(c.entries) != 2 || c.entries[b] != nil {
		t.Fatal("capacity exceeded or oldest live entry not evicted")
	}
}

func TestBillingBackoffConcurrent(t *testing.T) {
	c := NewBillingBackoff(5*time.Second, 2)
	now := time.Now()
	key := LookupHash("key")
	c.Remember(key, "id", "request", false, billingTestError(), now)
	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.Get(key, false, now)
			c.Remember(key, "id", "request", false, billingTestError(), now)
			c.SetCredentialID(key, "request", "id")
		}()
	}
	wg.Wait()
	if got := c.entries[key].Value.(*billingEntry).suppressed; got != 50 {
		t.Fatalf("suppressed=%d, want 50", got)
	}
}

func TestBillingBackoffEnv(t *testing.T) {
	for _, tc := range []struct {
		value string
		want  time.Duration
	}{{"", 5 * time.Second}, {"0", 0}, {"123", 123 * time.Millisecond}, {"-1", 5 * time.Second}, {"bad", 5 * time.Second}, {"9223372036854775807", 5 * time.Second}} {
		t.Run(tc.value, func(t *testing.T) {
			t.Setenv("QUILL_BILLING_402_BACKOFF_MS", tc.value)
			if got := billingBackoffFromEnv().ttl; got != tc.want {
				t.Fatalf("ttl=%v want %v", got, tc.want)
			}
		})
	}
}

func TestBillingBackoffOutOfOrderVerdicts(t *testing.T) {
	c := NewBillingBackoff(5*time.Second, 2)
	now := time.Unix(100, 0)
	newer, older := LookupHash("newer"), LookupHash("older")
	// Model goroutines taking timestamps in one order and the mutex in another.
	c.Remember(newer, "newer", "newer", false, billingTestError(), now.Add(time.Second))
	c.Remember(older, "older", "older", false, billingTestError(), now)
	if _, hit := c.Get(older, false, now.Add(5*time.Second)); hit {
		t.Fatal("expired verdict hidden behind newer entry")
	}
	if _, hit := c.Get(newer, false, now.Add(5*time.Second)); !hit {
		t.Fatal("newer verdict expired early")
	}
}

func captureBillingStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stderr
	os.Stderr = w
	fn()
	os.Stderr = old
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

// A one-off 402 already has its request_end line; its window adds no summary.
// A window that suppressed requests is summarized exactly once, after unlock.
func TestBillingBackoffSummaryOnlyForSuppressedWindows(t *testing.T) {
	c := NewBillingBackoff(5*time.Second, 4)
	now := time.Unix(100, 0)
	key := LookupHash("key-quiet")
	if !c.Remember(key, "credential", "request", false, billingTestError(), now) {
		t.Fatal("denial not stored")
	}
	logs := captureBillingStderr(t, func() {
		if _, hit := c.Get(key, false, now.Add(5*time.Second)); hit {
			t.Fatal("expired window still live")
		}
	})
	if strings.Contains(logs, "billing_402_backoff") {
		t.Fatalf("a window that suppressed nothing logged a summary: %s", logs)
	}
	if !c.Remember(key, "credential", "request-2", false, billingTestError(), now.Add(6*time.Second)) {
		t.Fatal("second denial not stored")
	}
	if _, hit := c.Get(key, false, now.Add(7*time.Second)); !hit {
		t.Fatal("live window missed")
	}
	logs = captureBillingStderr(t, func() {
		if _, hit := c.Get(key, false, now.Add(12*time.Second)); hit {
			t.Fatal("expired window still live")
		}
	})
	if strings.Count(logs, "enclave.billing_402_backoff") != 1 || !strings.Contains(logs, " suppressed=1 window_ms=5000") {
		t.Fatalf("suppressed window summary = %q", logs)
	}
}
