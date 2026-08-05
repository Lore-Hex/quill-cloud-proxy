package trustedrouter

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestParseControlPlaneEndpointsOrdersTrimsAndDedupes(t *testing.T) {
	got := parseControlPlaneEndpoints(
		" https://aws.trustedrouter.com/v1/ , https://trustedrouter.com/v1 ,, https://aws.trustedrouter.com/v1 ",
	)
	want := []string{"https://aws.trustedrouter.com/v1", "https://trustedrouter.com/v1"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("index %d: got %q want %q (order is load-bearing — index 0 is this cloud's own plane)", i, got[i], want[i])
		}
	}
	if len(parseControlPlaneEndpoints("   ")) != 0 {
		t.Error("a blank value must yield no endpoints, so Enabled() stays false")
	}
	// The single-value case must behave exactly as before this change.
	if one := parseControlPlaneEndpoints("https://trustedrouter.com/v1"); len(one) != 1 {
		t.Errorf("single endpoint must stay single, got %v", one)
	}
}

func TestIsDialFailureOnlyTagsTheDialer(t *testing.T) {
	if !isDialFailure(&dialFailure{err: errors.New("connection refused")}) {
		t.Error("a tagged dial error must be recognised")
	}
	if !isDialFailure(fmt.Errorf("wrapped: %w", &dialFailure{err: errors.New("boom")})) {
		t.Error("must see through wrapping — postJSON wraps errors with %w")
	}
	// Everything below may have reached a server, so failing over could
	// double-escrow or double-bill.
	if isDialFailure(errors.New("plain error")) {
		t.Error("an untagged error must not be treated as a dial failure")
	}
	if isDialFailure(&ControlPlaneError{StatusCode: 503}) {
		t.Error("a control-plane response is NOT a dial failure: the server processed the request")
	}
	if isDialFailure(context.Canceled) || isDialFailure(context.DeadlineExceeded) {
		t.Error("a cancelled/expired caller context must not trigger failover — the caller is giving up")
	}
	// A deadline surfacing THROUGH the dialer is still the caller giving up.
	if isDialFailure(&dialFailure{err: context.DeadlineExceeded}) {
		t.Error("a deadline reaching the dialer must not fail over")
	}
}

// testClient builds a Client over the ordered endpoints with the dialer tagged,
// mirroring what newControlPlaneHTTPClient does in production.
func testClient(endpoints string) *Client {
	tr := markDialFailures(&http.Transport{
		DialContext: (&net.Dialer{}).DialContext,
	})
	c := New(endpoints, "token", &http.Client{Transport: tr})
	return c
}

// unreachable returns a URL that cannot be dialled: port 1 on loopback, closed
// by convention. This exercises the real dialer rather than a stub.
const unreachable = "http://127.0.0.1:1"

func TestFallsThroughWhenThePrimaryCannotBeDialled(t *testing.T) {
	var hits int32
	secondary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer secondary.Close()

	c := testClient(unreachable + "," + secondary.URL)
	var out map[string]any
	if err := c.postJSON(context.Background(), "/internal/gateway/authorize", map[string]string{"a": "b"}, &out); err != nil {
		t.Fatalf("expected fallthrough to the secondary, got %v", err)
	}
	if atomic.LoadInt32(&hits) != 1 {
		t.Fatalf("secondary should have served exactly once, got %d", hits)
	}
}

// TestDoesNotFailOverOnceTheRequestWasDelivered is THE money-safety property,
// and the only test here that can distinguish the rule from its absence.
//
// The primary accepts the connection, READS THE REQUEST, then drops it without
// answering. httpc.Do therefore returns an error even though the server has
// already seen — and may have acted on — the request. These planes have
// SEPARATE databases and the idempotency key does not travel between them, so
// re-sending `authorize` here can escrow twice and `settle` can bill twice.
//
// Note a plain 500 does NOT exercise this: net/http returns (resp, nil) for any
// status, so a 500 never reaches the failover branch at all. An earlier version
// of this test used a 500 and passed even when the rule was deleted — it was
// green for the wrong reason. Hence the hijack.
func TestDoesNotFailOverOnceTheRequestWasDelivered(t *testing.T) {
	var primaryHits, secondaryHits int32
	primaryLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer primaryLn.Close()
	go func() {
		for {
			conn, err := primaryLn.Accept()
			if err != nil {
				return
			}
			// Read what the client sent, then hang up without replying: the
			// request WAS delivered, the answer never arrives.
			buf := make([]byte, 4096)
			_, _ = conn.Read(buf)
			atomic.AddInt32(&primaryHits, 1)
			_ = conn.Close()
		}
	}()

	secondary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&secondaryHits, 1)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer secondary.Close()

	c := testClient("http://" + primaryLn.Addr().String() + "," + secondary.URL)
	var out map[string]any
	callErr := c.postJSON(context.Background(), "/internal/gateway/authorize", map[string]string{"a": "b"}, &out)
	if callErr == nil {
		t.Fatal("a dropped connection must surface as an error, not be papered over by the secondary")
	}
	if atomic.LoadInt32(&primaryHits) == 0 {
		t.Fatal("precondition failed: the primary never received the request, so this did not test delivery")
	}
	if n := atomic.LoadInt32(&secondaryHits); n != 0 {
		t.Fatalf(
			"secondary was hit %d time(s) after the primary had ALREADY RECEIVED the request — "+
				"that is a double-escrow / double-bill against a different database",
			n,
		)
	}
}

// A 500 must also not reach the secondary. This cannot fail independently of
// the rule above (net/http reports a 500 as success at the transport layer), but
// it pins the end-to-end behaviour callers depend on.
func TestDoesNotFailOverOnceAServerHasResponded(t *testing.T) {
	var primaryHits, secondaryHits int32
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&primaryHits, 1)
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":{"type":"boom"}}`))
	}))
	defer primary.Close()
	secondary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&secondaryHits, 1)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer secondary.Close()

	c := testClient(primary.URL + "," + secondary.URL)
	var out map[string]any
	err := c.postJSON(context.Background(), "/internal/gateway/authorize", map[string]string{"a": "b"}, &out)
	if err == nil {
		t.Fatal("a 500 from the primary must surface as an error, not be papered over by the secondary")
	}
	if atomic.LoadInt32(&primaryHits) != 1 {
		t.Fatalf("primary should have been hit once, got %d", primaryHits)
	}
	if n := atomic.LoadInt32(&secondaryHits); n != 0 {
		t.Fatalf(
			"secondary was hit %d time(s) after the primary already responded — "+
				"that is a double-escrow / double-bill against a different database",
			n,
		)
	}
}

func TestAllEndpointsUndialableSurfacesAnError(t *testing.T) {
	c := testClient(unreachable + ",http://127.0.0.1:2")
	var out map[string]any
	err := c.postJSON(context.Background(), "/internal/gateway/authorize", map[string]string{}, &out)
	if err == nil {
		t.Fatal("with no endpoint dialable the call must fail rather than silently succeed")
	}
}

func TestEnabledRequiresAtLeastOneEndpoint(t *testing.T) {
	if New("", "token", nil).Enabled() {
		t.Error("no endpoint means not enabled")
	}
	if !New("https://trustedrouter.com/v1", "token", nil).Enabled() {
		t.Error("one endpoint plus a token means enabled")
	}
	if got := New("https://a.example/v1,https://b.example/v1", "t", nil).primaryBaseURL(); got != "https://a.example/v1" {
		t.Errorf("primary must be the FIRST endpoint, got %q", got)
	}
}
