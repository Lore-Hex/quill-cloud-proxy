package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
)

// A settle retry is a charge waiting to be delivered. A refund that fails
// leaves a hold to expire, which costs the caller some held credit for a while
// and nobody a charge. So a failed refund must never cost a queued settle its
// place.
//
// The exits this change routes through refundHold make that hold trivially:
// their refund is one attempt and is never queued. This test keeps it that
// way, end to end: the retry queue is full of settles, a request then fails at
// its provider, the control plane refuses its refund, and every queued settle
// is still there and is delivered. If a later change starts queuing these
// refunds for retry, the queue evicts its oldest job when full, whatever its
// kind, and this test fails with a settle missing. Retrying refunds needs the
// settles protected first.
func TestFailedRefundNeverCostsAQueuedSettleItsPlace(t *testing.T) {
	const queuedCharges = 3
	t.Setenv("QUILL_SETTLEMENT_RETRY_QUEUE_SIZE", fmt.Sprint(queuedCharges))
	t.Setenv("QUILL_SETTLEMENT_RETRY_ATTEMPTS", "1")
	queue := newSettlementRetryQueueFromEnv()
	original := settlementRetries
	settlementRetries = queue
	t.Cleanup(func() { settlementRetries = original })

	var mu sync.Mutex
	var settled []string
	refundsRefused := 0
	gateway := trustedrouter.New("https://trustedrouter.com", "internal-token", &http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			raw, err := io.ReadAll(r.Body)
			if err != nil {
				return nil, err
			}
			var body map[string]any
			_ = json.Unmarshal(raw, &body)
			respond := func(status int, payload string) (*http.Response, error) {
				return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(payload)), Request: r}, nil
			}
			mu.Lock()
			defer mu.Unlock()
			switch r.URL.Path {
			case "/internal/gateway/authorize":
				model, _ := body["model"].(string)
				return respond(200, fmt.Sprintf(`{"data":{"authorization_id":"auth_refunded","workspace_id":"ws_1","api_key_hash":"key_1","model":%q,"endpoint_id":"e@openai/prepaid","provider":"openai","usage_type":"Credits","limit_usage_type":"Credits","route_candidates":[]}}`, model))
			case "/internal/gateway/settle":
				id, _ := body["authorization_id"].(string)
				settled = append(settled, id)
				return respond(200, `{"data":{"settled":true,"generation_id":"gen_1","cost_microdollars":12}}`)
			case "/internal/gateway/refund":
				refundsRefused++
				return respond(503, `{"error":{"message":"control plane says 503","type":"test"}}`)
			}
			t.Errorf("unexpected control-plane path %s", r.URL.Path)
			return respond(500, `{}`)
		}),
	})

	// The queue is full of settles the request path could not deliver.
	var want []string
	for i := 1; i <= queuedCharges; i++ {
		id := fmt.Sprintf("auth_charge_%d", i)
		want = append(want, id)
		if !queue.Enqueue(settlementRetryJob{
			cause:         errors.New("settle was not acknowledged"),
			trGateway:     gateway,
			authorization: &trustedrouter.Authorization{AuthorizationID: id, Model: "m", EndpointID: "e@openai/prepaid"},
			usage:         trustedrouter.Usage{RequestID: fmt.Sprintf("req_%d", i), InputTokens: 1, OutputTokens: 1},
		}) {
			t.Fatalf("settle retry %d was not queued", i)
		}
	}
	if len(queue.jobs) != queuedCharges {
		t.Fatalf("queued settles = %d, want the queue full at %d", len(queue.jobs), queuedCharges)
	}

	// A request now fails at its provider and its refund is refused.
	var out bytes.Buffer
	serveEmbeddings(context.Background(), &out, &rejectedEmbeddingLLM{err: errors.New("provider failed")},
		[]byte(`{"model":"openai/text-embedding-3-large","input":"hi"}`), gateway, true, "test-key", nil, "idem-isolation", requestAttributionHeaders{}, "rlog_isolation")
	if !strings.HasPrefix(out.String(), "HTTP/1.1 502 ") {
		t.Fatalf("response: %s", out.String())
	}
	mu.Lock()
	refused := refundsRefused
	mu.Unlock()
	if refused != 1 {
		t.Fatalf("refund attempts = %d, want the one the control plane refused", refused)
	}
	if len(queue.jobs) != queuedCharges {
		t.Fatalf("queued jobs = %d after the failed refund, want the %d settles untouched", len(queue.jobs), queuedCharges)
	}

	// Deliver whatever the queue still holds.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	queue.Start(ctx)
	if err := queue.WaitForIdle(ctx); err != nil {
		t.Fatalf("the queue did not drain: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	sort.Strings(settled)
	if fmt.Sprint(settled) != fmt.Sprint(want) {
		t.Fatalf("settles delivered = %v, want every queued charge %v: the failed refund cost a settle its place", settled, want)
	}
	if refundsRefused != 1 {
		t.Fatalf("refund attempts = %d after the queue drained, want 1: the failed refund was retried", refundsRefused)
	}
}
