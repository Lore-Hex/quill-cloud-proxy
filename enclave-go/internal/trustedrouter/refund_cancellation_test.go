package trustedrouter

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// A refund closes an authorization, so it must leave whatever has happened to
// the request it belongs to. That used to be each call site's job, and call
// sites kept being found that had not done it. It is the client's job now.
func TestRefundLeavesEvenWhenTheRequestWasCancelled(t *testing.T) {
	var refunds atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/internal/gateway/refund" {
			refunds.Add(1)
		}
		_, _ = fmt.Fprint(w, `{"data":{"refunded":true}}`)
	}))
	t.Cleanup(server.Close)
	client := New(server.URL, "internal", server.Client())
	authorization := &Authorization{AuthorizationID: "auth_1", WorkspaceID: "ws_1", APIKeyHash: "key_1", Model: "m", EndpointID: "e@p/prepaid", Provider: "p"}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	expired, release := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer release()
	for label, ctx := range map[string]context.Context{"cancelled": cancelled, "past its deadline": expired} {
		before := refunds.Load()
		if err := client.Refund(ctx, authorization, 502, "provider_error", 0.5, nil); err != nil {
			t.Fatalf("%s: %v", label, err)
		}
		if refunds.Load() != before+1 {
			t.Fatalf("%s: the refund never reached the control plane", label)
		}
	}
}

func TestRefundStillHasADeadlineOfItsOwn(t *testing.T) {
	// Dropping the request's cancellation must not mean waiting forever.
	if refundDeadline <= 0 || refundDeadline > 30*time.Second {
		t.Fatalf("refundDeadline = %v", refundDeadline)
	}
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-release }))
	t.Cleanup(func() { close(release); server.Close() })
	httpClient := server.Client()
	httpClient.Timeout = 200 * time.Millisecond // stand in for the deadline: the point is that it returns
	client := New(server.URL, "internal", httpClient)
	started := time.Now()
	err := client.Refund(context.Background(), &Authorization{AuthorizationID: "auth_1", WorkspaceID: "ws_1", APIKeyHash: "key_1"}, 502, "provider_error", 0.5, nil)
	if err == nil || time.Since(started) > 5*time.Second {
		t.Fatalf("err=%v after %v: a hung control plane must not hang the refund", err, time.Since(started))
	}
}
