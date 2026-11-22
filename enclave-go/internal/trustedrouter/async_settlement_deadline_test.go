package trustedrouter

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// syncAttemptCase drives one snapshot-sync attempt to an end. The server cases
// reach a real control plane that holds the sync request open, so the error is
// whatever net/http returns when this settle's own context ends. The transport
// cases fail the sync request while the settle's context is still live.
type syncAttemptCase struct {
	// timeout bounds the whole settle; cancel cancels it once the sync request
	// has reached the control plane.
	timeout time.Duration
	cancel  bool
	// transport fails the sync request without reaching the control plane.
	transport func(*testing.T) error
}

// innerDialTimeout is a real net.Dialer timeout: the dialer's own deadline, not
// the settle's. It satisfies errors.Is(err, context.DeadlineExceeded) although
// no request byte left the gateway, which is why the attempt is classified by
// its context and not by the transport error.
func innerDialTimeout(t *testing.T) error {
	t.Helper()
	_, err := (&net.Dialer{Timeout: time.Nanosecond}).DialContext(context.Background(), "tcp", "127.0.0.1:9")
	if err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("precondition: a dialer timeout should satisfy errors.Is(context.DeadlineExceeded), got %v", err)
	}
	return err
}

var syncAttemptCases = map[string]syncAttemptCase{
	// The terminal paths bound the settle (QUILL_SETTLE_BEFORE_TERMINAL_MS) and
	// the router is still applying the snapshot sync when that bound passes.
	"own_deadline": {timeout: 500 * time.Millisecond},
	// Cancellation of the settle's context while the sync request is in flight.
	"own_cancel": {timeout: 5 * time.Second, cancel: true},
	// Genuine network failures, as net/http reports them, with the context live.
	"refused": {timeout: 5 * time.Second, transport: func(*testing.T) error {
		return &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}
	}},
	"reset": {timeout: 5 * time.Second, transport: func(*testing.T) error {
		return &net.OpError{Op: "read", Net: "tcp", Err: os.NewSyscallError("read", syscall.ECONNRESET)}
	}},
	"dns": {timeout: 5 * time.Second, transport: func(*testing.T) error {
		return &net.OpError{Op: "dial", Net: "tcp", Err: &net.DNSError{Err: "no such host", Name: "control-plane.invalid", IsNotFound: true}}
	}},
	"inner_dial_timeout": {timeout: 5 * time.Second, transport: innerDialTimeout},
}

type syncAttemptPlane struct {
	client      *Client
	auth        *Authorization
	syncArrived chan struct{}
	mu          sync.Mutex
	syncCalls   int
	legacyCalls int
}

// newSyncAttemptPlane answers the async-v1 attempt with sync_required, holds
// every sync request open until its caller gives up, and books a legacy settle
// at cost 19 (the async charge is 2), so a legacy fallback is visible.
func newSyncAttemptPlane(t *testing.T, tc syncAttemptCase) *syncAttemptPlane {
	t.Helper()
	p := &syncAttemptPlane{syncArrived: make(chan struct{}, 8)}
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Header.Get(asyncSettlementHeader) {
		case "async-v1":
			_, _ = io.WriteString(w, `{"data":{"acceptance":{"status":"sync_required"},"reason":"admission_stale"}}`)
		case "sync":
			p.syncArrived <- struct{}{}
			// The router keeps applying the snapshot sync; only the gateway stops
			// waiting for it.
			select {
			case <-r.Context().Done():
			case <-release:
			}
		default:
			p.mu.Lock()
			p.legacyCalls++
			p.mu.Unlock()
			_, _ = io.WriteString(w, `{"data":{"settled":true,"cost_microdollars":19}}`)
		}
	}))
	t.Cleanup(server.Close)
	t.Cleanup(func() { close(release) })
	p.auth = fixtureAuthorization(t, true)
	p.client = bindFixture(t, p.auth)
	p.client.baseURLs = []string{server.URL}
	p.auth.pinControlPlaneEndpoint(0)
	p.client.httpc = &http.Client{Transport: asyncRoundTripper(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get(asyncSettlementHeader) == "sync" {
			p.mu.Lock()
			p.syncCalls++
			p.mu.Unlock()
			if tc.transport != nil {
				return nil, tc.transport(t)
			}
		}
		return http.DefaultTransport.RoundTrip(r)
	})}
	return p
}

func (p *syncAttemptPlane) counts() (syncCalls, legacyCalls int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.syncCalls, p.legacyCalls
}

// settleContext bounds the settle as tc says and, for a cancellation case,
// cancels it once the sync request has reached the control plane.
func (p *syncAttemptPlane) settleContext(t *testing.T, tc syncAttemptCase) context.Context {
	t.Helper()
	ctx, cancelTimeout := context.WithTimeout(t.Context(), tc.timeout)
	t.Cleanup(cancelTimeout)
	if !tc.cancel {
		return ctx
	}
	ctx, cancel := context.WithCancel(ctx)
	t.Cleanup(cancel)
	go func() {
		select {
		case <-p.syncArrived:
			cancel()
		case <-ctx.Done():
		}
	}()
	return ctx
}

// A snapshot-sync attempt that ends because its own context ended reports that
// context's error, still as a soft failure. Any other transport failure keeps
// the exact classification it had: hard, and the literal "network".
func TestSnapshotSyncAttemptClassifiesByItsOwnContext(t *testing.T) {
	for name, tc := range syncAttemptCases {
		t.Run(name, func(t *testing.T) {
			p := newSyncAttemptPlane(t, tc)
			ctx := context.WithValue(p.settleContext(t, tc), asyncModeKey{}, "sync")
			result, hard, err := p.client.snapshotSyncAttempt(ctx, 0, []byte(`{}`), "", 2, p.auth)
			if result != nil || err == nil {
				t.Fatalf("result=%+v err=%v, want a failed attempt", result, err)
			}
			switch {
			case tc.transport != nil:
				if !hard || err.Error() != "network" || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
					t.Fatalf("hard=%t err=%q deadline=%t canceled=%t, want hard=true err=%q with no context cause",
						hard, err, errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled), "network")
				}
			case tc.cancel:
				if hard || !errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("hard=%t err=%q canceled=%t deadline=%t, want a soft failure that is context.Canceled only",
						hard, err, errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded))
				}
			default:
				if hard || !errors.Is(err, context.DeadlineExceeded) || !strings.HasPrefix(err.Error(), "network") {
					t.Fatalf("hard=%t err=%q deadline=%t, want a soft failure that is context.DeadlineExceeded and still reads network",
						hard, err, errors.Is(err, context.DeadlineExceeded))
				}
			}
		})
	}
}

// Through Settle: a snapshot sync the gateway stopped waiting for returns its
// context's error to the caller, with one sync request and no legacy settle,
// so the caller can tell the router may still be applying it. A genuine network
// failure still retries the sync request and then falls back to legacy in-line
// under the unchanged "snapshot_sync_network" reason.
func TestAsyncSettleReportsAbandonedSnapshotSyncAsItsContextError(t *testing.T) {
	for name, tc := range syncAttemptCases {
		t.Run(name, func(t *testing.T) {
			p := newSyncAttemptPlane(t, tc)
			ctx := p.settleContext(t, tc)
			var result *SettleResult
			var err error
			started := time.Now()
			logs := captureAsyncLogs(t, func() { result, err = p.client.Settle(ctx, p.auth, fixtureUsage()) })
			took := time.Since(started)
			syncCalls, legacyCalls := p.counts()
			if tc.transport != nil {
				if err != nil || result == nil || !result.Settled || result.CostMicrodollars != 19 {
					t.Fatalf("result=%+v err=%v, want the in-line legacy settle", result, err)
				}
				if syncCalls != 3 || legacyCalls != 1 || !strings.Contains(logs, `event="legacy_fallback" reason="snapshot_sync_network"`) {
					t.Fatalf("sync=%d legacy=%d logs=%s, want three sync attempts then one legacy settle", syncCalls, legacyCalls, logs)
				}
				return
			}
			want := context.DeadlineExceeded
			if tc.cancel {
				want = context.Canceled
			}
			if result != nil || !errors.Is(err, want) {
				t.Fatalf("result=%+v err=%v, want %v", result, err, want)
			}
			if tc.cancel && errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("err=%v: a cancellation reported as a deadline", err)
			}
			if syncCalls != 1 || legacyCalls != 0 || strings.Contains(logs, "legacy_fallback") {
				t.Fatalf("sync=%d legacy=%d logs=%s, want the one abandoned sync request and no legacy settle", syncCalls, legacyCalls, logs)
			}
			if took > 2*time.Second {
				t.Fatalf("settle took %s; it should end when its context does", took)
			}
		})
	}
}
