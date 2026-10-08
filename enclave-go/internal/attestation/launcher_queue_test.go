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
