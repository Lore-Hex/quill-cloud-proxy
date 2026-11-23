//go:build cloud_gcp

package attestation

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestLauncherQueueBoundsWaitAndAdmission(t *testing.T) {
	q := newTokenQueue(1, 10*time.Millisecond, time.Second)
	q.active <- struct{}{}
	if _, err := q.mint(t.Context(), nil); !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, ErrIssuerUnavailable) {
		t.Fatalf("queue timeout: %v", err)
	}
	if len(q.admitted) != 0 {
		t.Fatal("queue slot leaked")
	}
	q.admitted <- struct{}{}
	q.admitted <- struct{}{}
	if _, err := q.mint(t.Context(), nil); !errors.Is(err, ErrIssuerUnavailable) {
		t.Fatalf("full queue: %v", err)
	}
}

func TestLauncherQueueWaitCoversSlowIssuanceTail(t *testing.T) {
	// Google's issuer occasionally takes 8 to 15 s; a waiter queued behind one
	// such mint must not give up at the old 5 s.
	if launcherTokens.waitTimeout < 15*time.Second {
		t.Fatalf("queue wait %s is shorter than the slow-issuance tail", launcherTokens.waitTimeout)
	}
	if launcherTokens.waitTimeout > launcherTokens.mintTimeout {
		t.Fatal("waiting must not outlast the mint budget")
	}
	if cap(launcherTokens.admitted) != 5 || cap(launcherTokens.active) != 1 {
		t.Fatal("waiter capacity and issuance concurrency must stay at four and one")
	}
}

// waitFor polls cond until it holds or a generous deadline passes, so the test
// asserts queue state instead of assuming goroutine scheduling.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestLauncherWaiterBehindSlowMintSucceedsWithinWait(t *testing.T) {
	old := requestToken
	defer func() { requestToken = old }()
	release := make(chan struct{})
	requestToken = func(ctx context.Context, body []byte) ([]byte, error) {
		if string(body) == "slow" {
			select {
			case <-release:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		return append([]byte(nil), body...), nil
	}
	// Generous wait and mint budgets: the test proves a queued caller is
	// served once the slow mint finishes, not anything about wall-clock speed.
	q := newTokenQueue(1, 30*time.Second, 30*time.Second)
	slowDone := make(chan error, 1)
	go func() { _, err := q.mint(t.Context(), []byte("slow")); slowDone <- err }()
	waitFor(t, "the slow mint to hold the launcher", func() bool { return len(q.active) == 1 })
	waiterDone := make(chan error, 1)
	go func() { _, err := q.mint(t.Context(), []byte("waiter")); waiterDone <- err }()
	// The waiter holds an admission slot while it waits for the launcher.
	waitFor(t, "the waiter to be queued", func() bool { return len(q.admitted) == 2 })
	select {
	case err := <-waiterDone:
		t.Fatalf("waiter returned while the launcher was busy: %v", err)
	default:
	}
	close(release)
	if err := <-slowDone; err != nil {
		t.Fatalf("slow mint: %v", err)
	}
	if err := <-waiterDone; err != nil {
		t.Fatalf("waiter behind a slow mint failed within its wait: %v", err)
	}
	if len(q.admitted) != 0 || len(q.active) != 0 {
		t.Fatal("slots leaked")
	}
}

func TestLauncherMintDeadlineAndCapacityRecovery(t *testing.T) {
	old := requestToken
	defer func() { requestToken = old }()
	q := newTokenQueue(1, time.Second, 10*time.Millisecond)
	requestToken = func(ctx context.Context, _ []byte) ([]byte, error) { <-ctx.Done(); return nil, ctx.Err() }
	if _, err := q.mint(t.Context(), nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("mint timeout: %v", err)
	}
	requestToken = func(context.Context, []byte) ([]byte, error) { return []byte("fresh"), nil }
	if _, err := q.mint(t.Context(), nil); err != nil {
		t.Fatalf("capacity did not recover: %v", err)
	}
	if len(q.admitted) != 0 || len(q.active) != 0 {
		t.Fatal("slots leaked")
	}
}

func TestLauncherBudgetAndEveryCallerMintsDistinctEvidence(t *testing.T) {
	old := requestToken
	defer func() { requestToken = old }()
	var bodies []string
	requestToken = func(ctx context.Context, body []byte) ([]byte, error) {
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) < 25*time.Second || time.Until(deadline) > 30*time.Second {
			t.Fatal("issuer budget must be bounded and tolerate >5s issuance")
		}
		bodies = append(bodies, string(body))
		return append([]byte(nil), body...), nil
	}
	for _, nonce := range []string{"first", "second"} {
		if _, err := GetContext(t.Context(), []byte("leaf"), nil, []byte(nonce), []byte("tls-session"), nil); err != nil {
			t.Fatal(err)
		}
	}
	if len(bodies) != 2 || bodies[0] == bodies[1] {
		t.Fatal("nonce-bound requests were cached or coalesced")
	}
}

type launcherRoundTrip func(*http.Request) (*http.Response, error)

func (f launcherRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestLauncherResponseBoundsAndRedaction(t *testing.T) {
	old := launcherHTTP
	defer func() { launcherHTTP = old }()
	for _, test := range []struct {
		name      string
		status    int
		body      string
		wantError bool
	}{
		{"success", 200, "signed.jwt.evidence", false},
		{"empty", 200, "", true},
		{"oversize", 200, strings.Repeat("x", maxTokenBytes+1), true},
		{"issuer error", 500, "secret-token-and-nonce", true},
		{"redirect", 302, "secret-token-and-nonce", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			launcherHTTP = &http.Client{Transport: launcherRoundTrip(func(r *http.Request) (*http.Response, error) {
				if r.Method != "POST" || r.URL.String() != attestationTokenURL {
					t.Fatal("wrong issuer request")
				}
				return &http.Response{StatusCode: test.status, Body: io.NopCloser(strings.NewReader(test.body)), Header: make(http.Header)}, nil
			})}
			got, err := requestTokenFromLauncher(t.Context(), []byte("{}"))
			if (err != nil) != test.wantError {
				t.Fatalf("error = %v", err)
			}
			if err != nil && strings.Contains(err.Error(), "secret-token-and-nonce") {
				t.Fatal("issuer body leaked")
			}
			if err == nil && string(got) != test.body {
				t.Fatal("evidence modified")
			}
		})
	}
}

func TestLauncherHTTPHonorsCallerCancellation(t *testing.T) {
	started := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
	}))
	defer server.Close()
	old := launcherHTTP
	defer func() { launcherHTTP = old }()
	launcherHTTP = &http.Client{Transport: launcherRoundTrip(func(r *http.Request) (*http.Response, error) {
		forward, err := http.NewRequestWithContext(r.Context(), "GET", server.URL, nil)
		if err != nil {
			return nil, err
		}
		return http.DefaultTransport.RoundTrip(forward)
	})}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { _, err := requestTokenFromLauncher(ctx, []byte("{}")); done <- err }()
	<-started
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation: %v", err)
	}
}
